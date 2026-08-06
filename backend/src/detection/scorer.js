// ─────────────────────────────────────────────────────────────────────────────
// scorer.js — aplică greutăți, modificatori, plafoane și praguri semnalelor.
//
// Providerii descriu doar dovezi; niciun punct nu este decis în provider.
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    AI_SCORE_MAX,
    AI_UNCORROBORATED_SCORE_MAX,
    AI_SIGNAL_WEIGHTS,
    RISK_THRESHOLDS,
    RULE_WEIGHTS,
    SCORE_MAX,
    USER_BLOCKLIST_RULE_POINTS,
    applyScoreContextModifiers,
} from '../config/scoring.config.js';

export const mapScoreToVerdict = (score) => {
    if (score >= RISK_THRESHOLDS.likelyPhishing) {
        return 'likely_phishing';
    }

    if (score >= RISK_THRESHOLDS.suspicious) {
        return 'suspicious';
    }

    return 'safe';
};

const getSignalBasePoints = (signal) => {
    if (signal.key === 'user_blocklist_match') {
        return USER_BLOCKLIST_RULE_POINTS;
    }

    const weights = signal.kind === 'ai' ? AI_SIGNAL_WEIGHTS : RULE_WEIGHTS;
    const basePoints = weights[signal.key];

    if (!Number.isFinite(basePoints)) {
        throw new Error(`Unknown detection signal weight: ${signal.key}`);
    }

    return basePoints;
};

const compareSignals = (left, right) => {
    const orderDifference = (left.order ?? 0) - (right.order ?? 0);

    if (orderDifference !== 0) {
        return orderDifference;
    }

    return (left.sequence ?? 0) - (right.sequence ?? 0);
};

const normalizeSignalDetails = (details) => {
    if (details === undefined || details === null) {
        return '';
    }
    if (typeof details === 'string') {
        return details;
    }

    try {
        return typeof details === 'object'
            ? JSON.stringify(details)
            : String(details);
    } catch {
        return '[unserializable details]';
    }
};

export const scoreSignals = (signals = [], scanContext = {}) => {
    let ruleScore = 0;
    let rawAiScore = 0;
    const reasons = [];
    const triggeredRules = [];
    const orderedSignals = signals.map((signal, index) => ({
        ...signal,
        sequence: signal.sequence ?? index,
    })).sort(compareSignals);

    for (const signal of orderedSignals) {
        const basePoints = getSignalBasePoints(signal);
        // Legacy compatibility: deterministic suspicious-link rules used their
        // persisted `suspicious_link_pattern:*` id for modifier lookup, while
        // AI rules used the unprefixed semantic key.
        const modifierKey =
            signal.kind === 'ai'
                ? signal.key
                : signal.rule || signal.key;
        const effectivePoints =
            signal.key === 'user_blocklist_match'
                ? basePoints
                : applyScoreContextModifiers(modifierKey, basePoints, scanContext);

        if (effectivePoints <= 0) {
            continue;
        }

        if (signal.kind === 'ai') {
            rawAiScore += effectivePoints;
        } else {
            ruleScore += effectivePoints;
        }

        reasons.push(signal.reason);
        triggeredRules.push({
            rule: signal.rule || signal.key,
            points: effectivePoints,
            details: normalizeSignalDetails(signal.details),
        });
    }

    // Corroboration cap. The engine's stated invariants keep any single signal
    // below the phishing threshold and keep AI below it in aggregate, but nothing
    // stopped the AI layer from reaching `suspicious` on its own — and measured
    // against qwen2.5:1.5b it did exactly that on 46% of benign fixtures. A local
    // model's unsupported opinion should be able to corroborate deterministic
    // evidence and to raise a borderline case, never to author a verdict by
    // itself. With no rule evidence at all, AI is held below the suspicious band.
    const aiCap = ruleScore > 0 ? AI_SCORE_MAX : AI_UNCORROBORATED_SCORE_MAX;
    const aiScore = Math.min(rawAiScore, aiCap);
    const score = Math.min(SCORE_MAX, ruleScore + aiScore);

    return {
        score,
        ruleScore,
        aiScore,
        verdict: mapScoreToVerdict(score),
        reasons,
        triggeredRules,
    };
};
