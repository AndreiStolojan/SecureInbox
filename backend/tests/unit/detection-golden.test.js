// ─────────────────────────────────────────────────────────────────────────────
// detection-golden.test.js — dovada byte-for-byte pentru refactorul detecției.
//
// Rulează motorul modular peste corpusul v7, cu AI determinist, și compară
// rezultatul public de scorare cu baseline-ul înghețat înainte de refactor.
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { createDetectionContext } from '../../src/detection/context.js';
import { runDetection } from '../../src/detection/index.js';
import { verifySenderBrand } from '../../src/services/brand-verification.service.js';

const corpusUrl = new URL('../fixtures/detection-corpus/', import.meta.url);
const snapshotUrl = new URL('../fixtures/detection-snapshot.json', import.meta.url);

const serialize = (value) => `${JSON.stringify(value, null, 2)}\n`;

// The v7 baseline is frozen and must not be regenerated — scripts/snapshot-
// detection.js refuses to write it from a later engine. So a deliberate scoring
// change is recorded here instead, fixture by fixture, with its justification.
// Every other fixture stays locked byte-for-byte, which is the point of the file:
// the lock keeps working while one intended divergence is stated out loud.
const INTENTIONAL_DEVIATIONS = {
    // Invariant 4 (AI_UNCORROBORATED_SCORE_MAX). This fixture is precisely the
    // behaviour being corrected: five AI signals, zero deterministic evidence,
    // and a `suspicious` verdict authored by the model alone. Measured against
    // qwen2.5:1.5b — the model in the Raspberry Pi deployment — the semantic
    // layer asserted social engineering on all 30 benign fixtures in
    // tests/fixtures/semantic-eval.fixtures.js, so an AI-only verdict is not
    // trustworthy. The evidence is still emitted and still shown; only the score
    // is withheld until a rule provider corroborates it.
    'ai-cap': {
        since: 'rules-ai-v12',
        overrides: { score: 25, aiScore: 25, verdict: 'safe' },
    },
};

const applyIntentionalDeviations = (result) => {
    const deviation = INTENTIONAL_DEVIATIONS[result.id];

    return deviation ? { ...result, ...deviation.overrides } : result;
};

const buildAiSignals = (fixture) =>
    fixture.ai.enabled
        ? {
              status: 'evaluated',
              urgencyLevel: 'none',
              sensitiveDataRequest: false,
              loginOrActionRequest: false,
              socialEngineeringLevel: 'none',
              brandImpersonationSuspected: false,
              ...(fixture.ai.signals || {}),
          }
        : {
              status: 'disabled',
          };

const characterizeFixture = async (fixture) => {
    const email = {
        senderDomain: 'example.test',
        replyToDomain: '',
        hasShortenedUrl: false,
        suspiciousLinkPatterns: [],
        attachmentExtensions: [],
        linkCount: 0,
        ...fixture.email,
    };
    const senderListContext = {
        senderAllowlisted: false,
        senderBlocklisted: false,
        listMatch: null,
        ...(fixture.listContext || {}),
    };
    const brandContext = verifySenderBrand({
        senderDomain: email.senderDomain,
        authResults: email.authResults,
    });
    const scanContext = senderListContext.senderBlocklisted
        ? {
              ...senderListContext,
              senderVerifiedBrand: false,
              brandName: null,
          }
        : {
              ...brandContext,
              ...senderListContext,
          };
    const aiSignals = buildAiSignals(fixture);
    const context = createDetectionContext({
        email,
        senderListContext,
        brandContext,
        authResults: email.authResults || {},
        scanContext,
        userSettings: { aiEnabled: fixture.ai.enabled },
        aiInput: { fixtureId: fixture.id },
        semanticAnalyzer: async () => aiSignals,
    });
    const result = await runDetection(context, {
        recordOutcome: () => {},
    });

    return {
        id: fixture.id,
        score: result.score,
        ruleScore: result.ruleScore,
        aiScore: result.aiScore,
        verdict: result.verdict,
        reasons: result.reasons,
        triggeredRules: result.triggeredRules,
        senderVerifiedBrand: Boolean(scanContext.senderVerifiedBrand),
        verifiedBrandName: scanContext.senderVerifiedBrand
            ? scanContext.brandName || null
            : null,
        senderListMatch: senderListContext.listMatch || null,
    };
};

test('runDetection reproduces the locked pre-refactor snapshot byte-for-byte', async () => {
    const expectedText = await readFile(snapshotUrl, 'utf8');
    const expected = JSON.parse(expectedText);
    const fixtureNames = (await readdir(corpusUrl))
        .filter((name) => name.endsWith('.json'))
        .sort();
    const fixtures = await Promise.all(
        fixtureNames.map(async (name) =>
            JSON.parse(await readFile(new URL(name, corpusUrl), 'utf8'))
        )
    );
    const results = [];

    for (const fixture of fixtures) {
        results.push(await characterizeFixture(fixture));
    }

    const actual = {
        schemaVersion: expected.schemaVersion,
        baselineEngineVersion: expected.baselineEngineVersion,
        baseRevision: expected.baseRevision,
        corpusSize: fixtures.length,
        results,
    };

    assert.equal(
        serialize(actual),
        serialize({ ...expected, results: expected.results.map(applyIntentionalDeviations) })
    );
});

test('every recorded deviation from the v7 baseline is real and still needed', () => {
    // Guards the mechanism above: a deviation left behind after the behaviour was
    // reverted would silently mask a regression, and a typo in a fixture id would
    // mask nothing at all while looking deliberate.
    const expectedIds = new Set(
        JSON.parse(readFileSync(new URL(snapshotUrl), 'utf8')).results.map(({ id }) => id)
    );

    for (const id of Object.keys(INTENTIONAL_DEVIATIONS)) {
        assert.ok(expectedIds.has(id), `deviation names unknown fixture "${id}"`);
    }
});
