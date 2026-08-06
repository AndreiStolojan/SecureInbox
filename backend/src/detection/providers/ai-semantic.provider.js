// Local semantic evidence. The raw analyzer response is carried in result meta
// for persistence and explanation generation; emitted evidence stays point-free.

export const meta = Object.freeze({
    id: 'ai-semantic',
    version: 1,
    kind: 'ai',
    optional: true,
});

const buildAiDisabledSignals = () => ({
    status: 'disabled',
    provider: 'ollama',
    mode: 'local',
    latencyMs: 0,
    evaluatedAt: new Date(),
    disabledReason: 'ai_disabled',
});

// Signals that accuse the sender of intent rather than describe a surface
// feature. Measured against qwen2.5:1.5b, the model asserted social engineering
// on all 30 benign fixtures and brand impersonation on 29 of 30 — while missing
// it on the genuine PayPal phish. Unbacked, these are worse than no signal, so
// they now require a quote the model copied from the email and that we found
// there. `urgency_*` and `login_or_action_request` stay ungated: they describe
// wording, are already weighted as weak, and are usually right.
const EVIDENCE_BACKED_KEYS = new Set([
    'sensitive_data_request',
    'social_engineering_high',
    'social_engineering_medium',
    'brand_impersonation_suspected',
]);

export const collectAiSemanticSignals = (aiSignals) => {
    const signals = [];

    if (!aiSignals || aiSignals.status !== 'evaluated') {
        return signals;
    }

    // A grounded quote is the only self-report from the model we can verify.
    // `confidence` cannot be used for this — measured, it is a constant 0.95 on
    // every email, benign or malicious, so it discriminates nothing.
    //
    // Suppress only on an explicit `false`, meaning the analyzer checked the
    // quote and did not find it in the email. `undefined` means no check ran —
    // an older persisted result, or a caller passing raw signals — and those
    // must keep their previous behaviour rather than silently lose evidence.
    const isSupported = (key) =>
        !EVIDENCE_BACKED_KEYS.has(key) || aiSignals.evidenceGrounded !== false;

    if (aiSignals.urgencyLevel === 'high') {
        signals.push({
            key: 'urgency_high',
            rule: 'ai_semantic:urgency_high',
            reason: 'AI semantic: high urgency language detected.',
            details: 'AI flagged urgent pressure language as high.',
            order: 70,
        });
    } else if (aiSignals.urgencyLevel === 'medium') {
        signals.push({
            key: 'urgency_medium',
            rule: 'ai_semantic:urgency_medium',
            reason: 'AI semantic: medium urgency language detected.',
            details: 'AI flagged urgent pressure language as medium.',
            order: 70,
        });
    }

    if (aiSignals.sensitiveDataRequest && isSupported('sensitive_data_request')) {
        signals.push({
            key: 'sensitive_data_request',
            rule: 'ai_semantic:sensitive_data_request',
            reason: 'AI semantic: request for sensitive data detected.',
            details: 'AI detected password/card/OTP style data request.',
            order: 71,
        });
    }

    if (aiSignals.loginOrActionRequest) {
        signals.push({
            key: 'login_or_action_request',
            rule: 'ai_semantic:login_or_action_request',
            reason: 'AI semantic: login or rapid action request detected.',
            details: 'AI detected push toward login or immediate user action.',
            order: 72,
        });
    }

    if (aiSignals.socialEngineeringLevel === 'high' && isSupported('social_engineering_high')) {
        signals.push({
            key: 'social_engineering_high',
            rule: 'ai_semantic:social_engineering_high',
            reason: 'AI semantic: high social engineering pressure detected.',
            details: 'AI flagged social engineering patterns as high.',
            order: 73,
        });
    } else if (aiSignals.socialEngineeringLevel === 'medium' && isSupported('social_engineering_medium')) {
        signals.push({
            key: 'social_engineering_medium',
            rule: 'ai_semantic:social_engineering_medium',
            reason: 'AI semantic: medium social engineering pressure detected.',
            details: 'AI flagged social engineering patterns as medium.',
            order: 73,
        });
    }

    if (aiSignals.brandImpersonationSuspected && isSupported('brand_impersonation_suspected')) {
        signals.push({
            key: 'brand_impersonation_suspected',
            rule: 'ai_semantic:brand_impersonation_suspected',
            reason: 'AI semantic: possible brand impersonation detected.',
            details: 'AI found likely impersonation of known organization/brand.',
            order: 74,
        });
    }

    return signals;
};

export const collectSignals = collectAiSemanticSignals;
export const collectAiSignals = collectAiSemanticSignals;

export const analyze = async (ctx = {}) => {
    if (!ctx.userSettings?.aiEnabled) {
        return {
            status: 'skipped',
            signals: [],
            meta: {
                aiSignals: buildAiDisabledSignals(),
            },
        };
    }

    if (typeof ctx.semanticAnalyzer !== 'function') {
        throw new TypeError('AI provider requires ctx.semanticAnalyzer when AI is enabled.');
    }

    const aiSignals = await ctx.semanticAnalyzer({
        analysisInput: ctx.aiInput,
        enabled: true,
        brandContext: ctx.scanContext,
    });

    return {
        ...(aiSignals?.status === 'failed' ? { status: 'error' } : {}),
        signals: collectAiSemanticSignals(aiSignals),
        meta: {
            aiSignals,
        },
    };
};
