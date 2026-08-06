// Measures the semantic layer against the labelled corpus in
// tests/fixtures/semantic-eval.fixtures.js.
//
// The suite locks detection output against regressions but never measured
// whether the verdicts are correct, so weight and prompt changes were being made
// blind. This runs the REAL services — buildAiAnalysisInput, the Ollama call, the
// signal provider and the scorer — against a live model and reports the
// false-positive rate on benign mail, which is the failure users report.
//
//   npm run eval:semantic
//   npm run eval:semantic -- --only=google-security-alert
//   npm run eval:semantic -- --json > baseline.json
//
// Requires Ollama running with OLLAMA_MODEL pulled. Exits non-zero if the model
// is unreachable, so a broken setup cannot look like a passing evaluation.

import { OLLAMA_MODEL, OLLAMA_BASE_URL } from '../src/config/env.js';
import { buildAiAnalysisInput } from '../src/services/scan-ai-input.service.js';
import { analyzeEmailSemanticsWithOllama } from '../src/services/ollama-semantic.service.js';
import { collectAiSemanticSignals } from '../src/detection/providers/ai-semantic.provider.js';
import { AI_SIGNAL_WEIGHTS, AI_UNCORROBORATED_SCORE_MAX, RISK_THRESHOLDS } from '../src/config/scoring.config.js';
import { SEMANTIC_EVAL_FIXTURES, BENIGN_COUNT, MALICIOUS_COUNT } from '../tests/fixtures/semantic-eval.fixtures.js';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const only = args.find((arg) => arg.startsWith('--only='))?.slice('--only='.length);

const log = (...parts) => {
    if (!asJson) console.log(...parts);
};

// Signals that make an accusation about the sender's intent, as opposed to
// describing a surface feature. `login_or_action_request` is deliberately not
// here: it is true of most legitimate mail and the weights already treat it as
// weak. The others are what users see and disbelieve.
const SERIOUS_SIGNAL_KEYS = new Set([
    'social_engineering_high',
    'social_engineering_medium',
    'brand_impersonation_suspected',
    'sensitive_data_request',
]);

// The AI-only score for one fixture, using the same weights the engine uses.
// Deliberately excludes rule signals: this isolates what the semantic layer
// contributes on its own, which is the number that decides whether AI alone can
// push benign mail over RISK_THRESHOLDS.suspicious.
// Uses the uncorroborated cap, because that is the situation being measured:
// these fixtures are scored by the semantic layer alone, with no rule signals.
const scoreAiSignals = (signals) =>
    Math.min(
        signals.reduce((total, { key }) => total + (AI_SIGNAL_WEIGHTS[key] || 0), 0),
        AI_UNCORROBORATED_SCORE_MAX
    );

// A benign message is a false positive when the semantic layer alone would move
// it out of the "safe" band, or when it contradicts an expectation the fixture
// states outright.
const gradeExpectations = (expected, actual) => {
    const mismatches = [];

    for (const [field, want] of Object.entries(expected || {})) {
        if (want === null) continue;
        if (actual[field] !== want) {
            mismatches.push(`${field}: expected ${want}, got ${actual[field]}`);
        }
    }

    return mismatches;
};

const runFixture = async (fixture) => {
    const analysisInput = buildAiAnalysisInput(fixture.email, {});
    const startedAt = Date.now();
    const result = await analyzeEmailSemanticsWithOllama({ analysisInput, enabled: true });
    const latencyMs = Date.now() - startedAt;

    if (result.status !== 'evaluated') {
        return { ...fixture, status: result.status, error: result.error, latencyMs };
    }

    const signals = collectAiSemanticSignals(result);
    const aiScore = scoreAiSignals(signals);

    return {
        id: fixture.id,
        label: fixture.label,
        note: fixture.note,
        status: 'evaluated',
        latencyMs,
        parserFallback: Boolean(result.parserFallback),
        aiScore,
        crossesSuspicious: aiScore >= RISK_THRESHOLDS.suspicious,
        signalKeys: signals.map(({ key }) => key),
        // The practical harm is not only crossing a threshold. A benign email
        // that shows "Social engineering" or "Brand impersonation" in its
        // triggered-rule list has already misled the user, and those points
        // still stack on top of whatever the rule providers contribute.
        spuriousSignals: signals
            .map(({ key }) => key)
            .filter((key) => SERIOUS_SIGNAL_KEYS.has(key)),
        observed: {
            urgencyLevel: result.urgencyLevel,
            socialEngineeringLevel: result.socialEngineeringLevel,
            sensitiveDataRequest: result.sensitiveDataRequest,
            loginOrActionRequest: result.loginOrActionRequest,
            brandImpersonationSuspected: result.brandImpersonationSuspected,
            confidence: result.confidence,
            evidence: result.evidence,
        },
        // Can the quoted evidence actually be found in what we sent the model?
        // A quote that is not in the text is a fabrication, and a signal resting
        // on it should not score. This check is mechanical, so it works even
        // where the model's self-reported confidence does not.
        evidenceGrounded: Boolean(
            result.evidence
            && `${analysisInput.subject} ${analysisInput.body}`
                .toLowerCase()
                .includes(result.evidence.toLowerCase().slice(0, 40))
        ),
        mismatches: gradeExpectations(fixture.expected, result),
        summary: result.summary,
    };
};

const main = async () => {
    const fixtures = only
        ? SEMANTIC_EVAL_FIXTURES.filter((fixture) => fixture.id === only)
        : SEMANTIC_EVAL_FIXTURES;

    if (!fixtures.length) {
        console.error(`No fixture matched --only=${only}`);
        process.exit(2);
    }

    log(`model      ${OLLAMA_MODEL}`);
    log(`endpoint   ${OLLAMA_BASE_URL}`);
    log(`fixtures   ${fixtures.length} (${BENIGN_COUNT} benign, ${MALICIOUS_COUNT} malicious)`);
    log('');

    const results = [];

    // Sequential on purpose: Ollama largely serialises anyway, and concurrent
    // requests would make the per-fixture latency figures meaningless.
    for (const fixture of fixtures) {
        const result = await runFixture(fixture);
        results.push(result);

        if (result.status !== 'evaluated') {
            log(`  ERROR  ${result.id ?? fixture.id} — ${result.error}`);
            continue;
        }

        const flagged = result.label === 'benign' && result.spuriousSignals.length > 0;
        const missed = result.label === "malicious" && result.spuriousSignals.length === 0;
        const mark = flagged ? 'FALSE POS' : missed ? 'MISSED   ' : 'ok       ';

        log(
            `  ${mark} ${result.id.padEnd(30)} ai=${String(result.aiScore).padStart(2)}`
            + ` ${(result.latencyMs / 1000).toFixed(1)}s`
            + (result.signalKeys.length ? `  ${result.signalKeys.join(', ')}` : '')
        );

        for (const mismatch of result.mismatches) {
            log(`            ${mismatch}`);
        }
    }

    const evaluated = results.filter((result) => result.status === 'evaluated');
    const failed = results.filter((result) => result.status !== 'evaluated');

    if (!evaluated.length) {
        console.error(`\nEvery call failed (${failed[0]?.error}). Is Ollama running with ${OLLAMA_MODEL} pulled?`);
        process.exit(1);
    }

    const benign = evaluated.filter((result) => result.label === 'benign');
    const malicious = evaluated.filter((result) => result.label === 'malicious');
    const falsePositives = benign.filter((result) => result.spuriousSignals.length);
    const overThreshold = benign.filter((result) => result.crossesSuspicious);
    // With the corroboration cap in place, the semantic layer deliberately cannot
    // cross the suspicious threshold unaided — that is the invariant, not a
    // failure. So detection here asks the question that is still meaningful for
    // this layer: did it produce an intent signal the rule engine can corroborate?
    // Whether the message is ultimately caught depends on the rule providers,
    // which these fixtures do not exercise.
    const detected = malicious.filter((result) => result.spuriousSignals.length > 0);
    const withMismatches = evaluated.filter((result) => result.mismatches.length);
    const rate = (part, whole) => (whole ? ((part / whole) * 100).toFixed(1) : '0.0');

    const report = {
        model: OLLAMA_MODEL,
        evaluated: evaluated.length,
        failed: failed.length,
        falsePositiveRate: Number(rate(falsePositives.length, benign.length)),
        overThresholdRate: Number(rate(overThreshold.length, benign.length)),
        detectionRate: Number(rate(detected.length, malicious.length)),
        signalAccuracy: Number(rate(evaluated.length - withMismatches.length, evaluated.length)),
        meanBenignAiScore: benign.length
            ? Number((benign.reduce((sum, r) => sum + r.aiScore, 0) / benign.length).toFixed(1))
            : 0,
        meanMaliciousAiScore: malicious.length
            ? Number((malicious.reduce((sum, r) => sum + r.aiScore, 0) / malicious.length).toFixed(1))
            : 0,
        medianLatencyMs: evaluated.map((r) => r.latencyMs).sort((a, b) => a - b)[Math.floor(evaluated.length / 2)],
        parserFallbacks: evaluated.filter((r) => r.parserFallback).length,
        falsePositives: falsePositives.map((r) => ({ id: r.id, aiScore: r.aiScore, signals: r.spuriousSignals })),
        missed: malicious.filter((r) => !r.spuriousSignals.length).map((r) => ({ id: r.id, aiScore: r.aiScore })),
        results,
    };

    if (asJson) {
        console.log(JSON.stringify(report, null, 2));
        return;
    }

    log('');
    log('────────────────────────────────────────────────');
    log(`false positives   ${falsePositives.length}/${benign.length}  (${report.falsePositiveRate}%)   target < 5%   [benign mail accused of intent]`);
    log(`over threshold    ${overThreshold.length}/${benign.length}  (${report.overThresholdRate}%)              [benign mail AI alone pushes past ${RISK_THRESHOLDS.suspicious}]`);
    log(`ai contribution   ${detected.length}/${malicious.length}  (${report.detectionRate}%)   target > 90%   [malicious mail where AI gives corroboratable signal]`);
    log(`signal accuracy   ${report.signalAccuracy}%  (fixtures with no contradicted expectation)`);
    log(`mean AI score     benign ${report.meanBenignAiScore}   malicious ${report.meanMaliciousAiScore}`);
    log(`median latency    ${(report.medianLatencyMs / 1000).toFixed(1)}s`);
    if (report.parserFallbacks) log(`parser fallbacks  ${report.parserFallbacks}`);
    if (failed.length) log(`failed calls      ${failed.length}`);
    log('────────────────────────────────────────────────');
};

await main();
