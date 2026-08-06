export const meta = Object.freeze({
    id: 'threat-intelligence',
    version: 1,
    kind: 'rule',
    optional: true,
});

const SOURCE_NAMES = Object.freeze(['web_risk', 'urlhaus', 'rdap', 'redirect']);
const MAX_SOURCE_COUNT = 1_000;

const asBoundedCount = (value) =>
    Number.isInteger(value) && value >= 0
        ? Math.min(value, MAX_SOURCE_COUNT)
        : 0;

const sourceCounts = (value) => Object.fromEntries(
    SOURCE_NAMES.map((name) => [name, asBoundedCount(value?.[name])])
);

const sourceStatuses = (value) => Object.fromEntries(
    SOURCE_NAMES.map((name) => [
        name,
        ['ok', 'unavailable', 'skipped'].includes(value?.[name])
            ? value[name]
            : 'skipped',
    ])
);

const emptyMeta = () => ({
    sourceCounts: sourceCounts(),
    sourceStatuses: sourceStatuses(),
});

const SOURCE_LABELS = Object.freeze({
    web_risk: 'Google Web Risk',
    urlhaus: 'URLhaus',
});

const sourceList = (value) => [...new Set(
    (Array.isArray(value) ? value : [])
        .filter((source) => Object.hasOwn(SOURCE_LABELS, source))
        .map((source) => SOURCE_LABELS[source])
)].join(' and ');

const signal = ({ key, reason, details, order }) => ({
    key,
    rule: `threat_intelligence:${key}`,
    reason,
    details,
    order,
});

// The analyzer result is intentionally a compact, already-redacted aggregate.
// URL/domain-level source responses never enter signals or provider metadata.
export const collectThreatIntelligenceSignals = (result) => {
    if (!result || result.status !== 'evaluated') return [];

    const signals = [];
    if (result.knownMalicious === true) {
        const matchedSources = sourceList(result.maliciousSources);
        signals.push(signal({
            key: 'url_known_malicious',
            reason: 'Threat intelligence identified a link as known malicious.',
            details: matchedSources
                ? `At least one checked link matched ${matchedSources}.`
                : 'At least one checked link matched a malware intelligence source.',
            order: 41,
        }));
    }
    if (result.knownPhishing === true) {
        const matchedSources = sourceList(result.phishingSources);
        signals.push(signal({
            key: 'url_known_phishing_campaign',
            reason: 'Threat intelligence identified a link as known phishing.',
            details: matchedSources
                ? `At least one checked link matched ${matchedSources}.`
                : 'At least one checked link matched a phishing intelligence source.',
            order: 41,
        }));
    }

    // `null` is the analyzer's explicit "registration age unknown" sentinel: no
    // links to look up, no RDAP endpoint for the TLD, or a failed/expired lookup.
    // It must never be coerced, because Number(null) is 0 — which reads as
    // "registered today" and fires the 30-point signal on ordinary mail. Only an
    // actual finite number is evidence; anything else produces no signal.
    const domainAgeDays =
        typeof result.domainAgeDays === 'number' && Number.isFinite(result.domainAgeDays)
            ? result.domainAgeDays
            : null;
    if (domainAgeDays !== null && domainAgeDays >= 0 && domainAgeDays < 7) {
        signals.push(signal({
            key: 'domain_registered_days_ago_lt_7',
            reason: 'A linked domain was registered very recently.',
            details: 'At least one linked domain has a registration age below seven days.',
            order: 42,
        }));
    } else if (domainAgeDays !== null && domainAgeDays >= 0 && domainAgeDays < 30) {
        signals.push(signal({
            key: 'domain_registered_days_ago_lt_30',
            reason: 'A linked domain was registered recently.',
            details: 'At least one linked domain has a registration age below thirty days.',
            order: 42,
        }));
    }

    if (asBoundedCount(result.linkTextHrefMismatchCount) > 0) {
        signals.push(signal({
            key: 'link_text_href_mismatch',
            reason: 'A displayed link address differs from its destination.',
            details: 'At least one link shows a different visible address and destination.',
            order: 43,
        }));
    }
    if (asBoundedCount(result.differentRegistrableRedirectTargetCount) > 0) {
        signals.push(signal({
            key: 'redirect_chain_to_different_tld',
            reason: 'A redirect changes to a different registrable domain.',
            details: 'At least one checked redirect did not match the sender registrable domain.',
            order: 44,
        }));
    }
    if (asBoundedCount(result.excessiveRedirectChainCount) > 0) {
        signals.push(signal({
            key: 'excessive_redirect_chain',
            reason: 'A link uses an unusually long redirect chain.',
            details: 'At least one checked link exceeded the normal redirect-chain length.',
            order: 45,
        }));
    }
    if (asBoundedCount(result.redirectToPrivateCount) > 0) {
        signals.push(signal({
            key: 'redirect_to_private_address',
            reason: 'A redirect attempted to reach a private network address.',
            details: 'At least one redirect target was rejected because it was not publicly routable.',
            order: 46,
        }));
    }

    return signals;
};

export const analyze = async (ctx = {}) => {
    if (typeof ctx.threatIntelAnalyzer !== 'function') {
        return { status: 'skipped', signals: [], meta: emptyMeta() };
    }

    try {
        const result = await ctx.threatIntelAnalyzer(ctx.email);
        const normalizedMeta = {
            sourceCounts: sourceCounts(result?.sourceCounts),
            sourceStatuses: sourceStatuses(result?.sourceStatuses),
        };

        if (!result || result.status !== 'evaluated') {
            return { status: 'skipped', signals: [], meta: normalizedMeta };
        }

        const signals = collectThreatIntelligenceSignals(result);
        const attemptedStatuses = Object.values(normalizedMeta.sourceStatuses)
            .filter((status) => status !== 'skipped');
        const completeOutage =
            signals.length === 0 &&
            attemptedStatuses.length > 0 &&
            attemptedStatuses.every((status) => status === 'unavailable');

        return {
            ...(completeOutage ? { status: 'skipped' } : {}),
            signals,
            meta: normalizedMeta,
        };
    } catch {
        return { status: 'error', signals: [], meta: emptyMeta() };
    }
};

export const collectSignals = collectThreatIntelligenceSignals;
