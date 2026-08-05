// ─────────────────────────────────────────────────────────────────────────────
// registry.js — registrul ordonat și izolarea erorilor providerilor.
//
// Orice provider poate eșua fără să oprească scanarea. Etichetele Prometheus
// provin exclusiv din acest registru finit. Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import * as aiSemanticProvider from './providers/ai-semantic.provider.js';
import * as attachmentAnalysisProvider from './providers/attachment.provider.js';
import * as attachmentExtensionProvider from './providers/attachment-extension.provider.js';
import * as linkAnalysisProvider from './providers/link-analysis.provider.js';
import * as threatIntelligenceProvider from './providers/threat-intelligence.provider.js';
import * as replyToProvider from './providers/reply-to.provider.js';
import * as senderListProvider from './providers/sender-list.provider.js';
import * as emailAuthProvider from './providers/email-auth.provider.js';
import {
    AI_SIGNAL_WEIGHTS,
    RULE_WEIGHTS,
} from './weights/index.js';
import { detectionProviderTotal } from '../monitoring/metrics.js';

export const DEFAULT_PROVIDERS = Object.freeze([
    senderListProvider,
    emailAuthProvider,
    replyToProvider,
    linkAnalysisProvider,
    threatIntelligenceProvider,
    attachmentAnalysisProvider,
    attachmentExtensionProvider,
    aiSemanticProvider,
]);

export const DETECTION_PROVIDER_IDS = Object.freeze(
    DEFAULT_PROVIDERS.map((provider) => provider.meta.id)
);

const detectionProviderIdSet = new Set(DETECTION_PROVIDER_IDS);

export const recordDetectionProviderOutcome = ({ provider, result }) => {
    if (!detectionProviderIdSet.has(provider)) {
        throw new Error(`Unknown detection provider metric label: ${provider}`);
    }
    if (!['success', 'error', 'skipped'].includes(result)) {
        throw new Error(`Unknown detection provider result metric label: ${result}`);
    }

    detectionProviderTotal.inc({ provider, result });
};

export const validateProviderRegistry = (providers) => {
    const ids = new Set();

    for (const provider of providers) {
        const { meta, analyze } = provider || {};

        if (
            !meta ||
            typeof meta.id !== 'string' ||
            !/^[a-z][a-z0-9-]{0,63}$/.test(meta.id) ||
            !Number.isInteger(meta.version) ||
            !['rule', 'ai'].includes(meta.kind) ||
            typeof meta.optional !== 'boolean' ||
            typeof analyze !== 'function'
        ) {
            throw new Error('Invalid detection provider contract.');
        }

        if (ids.has(meta.id)) {
            throw new Error(`Duplicate detection provider id: ${meta.id}`);
        }

        ids.add(meta.id);
    }

    return providers;
};

validateProviderRegistry(DEFAULT_PROVIDERS);

const validateProviderResult = (result, provider) => {
    const providerId = provider.meta.id;
    const weights =
        provider.meta.kind === 'ai'
            ? AI_SIGNAL_WEIGHTS
            : RULE_WEIGHTS;

    if (!result || !Array.isArray(result.signals)) {
        throw new Error(`Detection provider ${providerId} returned an invalid result.`);
    }

    for (const signal of result.signals) {
        if (!signal || typeof signal.key !== 'string' || !signal.key) {
            throw new Error(`Detection provider ${providerId} returned an invalid signal.`);
        }

        if (Object.hasOwn(signal, 'points')) {
            throw new Error(`Detection provider ${providerId} assigned points directly.`);
        }

        if (
            signal.key !== 'user_blocklist_match' &&
            !Object.hasOwn(weights, signal.key)
        ) {
            throw new Error(
                `Detection provider ${providerId} returned ${provider.meta.kind} ` +
                `signal with unknown weight ${signal.key}.`
            );
        }
    }

    return result;
};

const toPersistedProviderMeta = ({ provider, result, status, error }) => {
    const resultMeta = result?.meta && typeof result.meta === 'object'
        ? { ...result.meta }
        : {};

    // Semnalele AI brute au propriul câmp în Scan; nu le duplicăm în providerMeta.
    delete resultMeta.aiSignals;

    return {
        provider: provider.meta.id,
        version: provider.meta.version,
        kind: provider.meta.kind,
        status,
        ...(error ? { message: error.message } : {}),
        ...(Object.keys(resultMeta).length > 0 ? { meta: resultMeta } : {}),
    };
};

export const runProviders = async (
    ctx,
    {
        providers = DEFAULT_PROVIDERS,
        recordOutcome = recordDetectionProviderOutcome,
    } = {}
) => {
    validateProviderRegistry(providers);

    const signals = [];
    const providerMeta = [];
    const providerResults = new Map();
    let sequence = 0;
    const recordOutcomeSafely = (outcome) => {
        try {
            recordOutcome(outcome);
        } catch (error) {
            console.error('[detection:metrics] Outcome recording failed', error.message);
        }
    };

    for (const provider of providers) {
        try {
            const result = validateProviderResult(
                await provider.analyze(ctx),
                provider
            );
            const status = ['error', 'skipped'].includes(result.status)
                ? result.status
                : 'success';

            recordOutcomeSafely({ provider: provider.meta.id, result: status });
            providerResults.set(provider.meta.id, result);
            providerMeta.push(
                toPersistedProviderMeta({ provider, result, status })
            );

            for (const signal of result.signals) {
                signals.push({
                    ...signal,
                    kind: provider.meta.kind,
                    providerId: provider.meta.id,
                    sequence,
                });
                sequence += 1;
            }
        } catch (error) {
            recordOutcomeSafely({
                provider: provider.meta.id,
                result: 'error',
            });
            providerMeta.push(
                toPersistedProviderMeta({
                    provider,
                    status: 'error',
                    error,
                })
            );

            const log = provider.meta.optional ? console.debug : console.error;
            log(`[detection:${provider.meta.id}] Provider failed`, error.message);
        }
    }

    return {
        signals,
        providerMeta,
        providerResults,
    };
};
