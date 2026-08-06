import assert from 'node:assert/strict';
import test from 'node:test';

import {
    analyze,
    collectThreatIntelligenceSignals,
    meta,
} from '../../src/detection/providers/threat-intelligence.provider.js';
import { THREAT_INTELLIGENCE_RULE_WEIGHTS } from '../../src/detection/weights/threat-intelligence.weights.js';

test('threat intelligence emits each bounded evidence signal once with the assigned weights', () => {
    const signals = collectThreatIntelligenceSignals({
        status: 'evaluated',
        knownMalicious: true,
        knownPhishing: true,
        domainAgeDays: 4,
        linkTextHrefMismatchCount: 3,
        differentRegistrableRedirectTargetCount: 1,
        excessiveRedirectChainCount: 2,
        redirectToPrivateCount: 1,
    });

    assert.equal(meta.optional, true);
    assert.deepEqual(
        signals.map(({ key, points }) => ({ key, points })),
        [
            { key: 'url_known_malicious', points: undefined },
            { key: 'url_known_phishing_campaign', points: undefined },
            { key: 'domain_registered_days_ago_lt_7', points: undefined },
            { key: 'link_text_href_mismatch', points: undefined },
            { key: 'redirect_chain_to_different_tld', points: undefined },
            { key: 'excessive_redirect_chain', points: undefined },
            { key: 'redirect_to_private_address', points: undefined },
        ]
    );
    assert.equal(new Set(signals.map(({ key }) => key)).size, signals.length);
    assert.ok(signals.every(({ rule }) => rule.startsWith('threat_intelligence:')));
    assert.ok(signals.every(({ details }) => !/example|https?:|\.com/i.test(details)));
    assert.deepEqual(THREAT_INTELLIGENCE_RULE_WEIGHTS, {
        url_known_malicious: 45,
        url_known_phishing_campaign: 45,
        domain_registered_days_ago_lt_7: 30,
        domain_registered_days_ago_lt_30: 18,
        link_text_href_mismatch: 20,
        redirect_chain_to_different_tld: 15,
        excessive_redirect_chain: 12,
        redirect_to_private_address: 40,
    });
});

test('domain age bands are mutually exclusive and unavailable data creates no evidence', () => {
    const underThirty = collectThreatIntelligenceSignals({
        status: 'evaluated',
        domainAgeDays: 29,
    });
    assert.deepEqual(underThirty.map(({ key }) => key), ['domain_registered_days_ago_lt_30']);
    assert.deepEqual(collectThreatIntelligenceSignals({ status: 'evaluated', domainAgeDays: -1 }), []);
    assert.deepEqual(collectThreatIntelligenceSignals({ status: 'unavailable', domainAgeDays: 1 }), []);
});

test('an unknown registration age is never scored as a newly registered domain', () => {
    // The analyzer reports `null` for "age unknown": an email with no links to look
    // up, a TLD with no RDAP endpoint (.ro, .de, .io), or a failed lookup. Coercing
    // it with Number() yields 0, which reads as "registered today" and fires the
    // 30-point signal — the phishing engine's own `suspicious` threshold — on
    // ordinary mail. Every falsy sentinel must produce no evidence at all.
    for (const unknownAge of [null, undefined, '', false, [], NaN]) {
        assert.deepEqual(
            collectThreatIntelligenceSignals({ status: 'evaluated', domainAgeDays: unknownAge }),
            [],
            `domainAgeDays: ${String(unknownAge)} must not create evidence`
        );
    }

    // A genuinely fresh registration is still evidence: the guard rejects unknown
    // values, not the legitimate zero-day case.
    assert.deepEqual(
        collectThreatIntelligenceSignals({ status: 'evaluated', domainAgeDays: 0 })
            .map(({ key }) => key),
        ['domain_registered_days_ago_lt_7']
    );
});

test('provider is fail-open and persists only bounded source counts', async () => {
    const email = { links: ['https://private.example/path?recipient=secret'] };
    const skipped = await analyze({ email });
    assert.deepEqual(skipped, {
        status: 'skipped', signals: [], meta: {
            sourceCounts: { web_risk: 0, urlhaus: 0, rdap: 0, redirect: 0 },
            sourceStatuses: { web_risk: 'skipped', urlhaus: 'skipped', rdap: 'skipped', redirect: 'skipped' },
        },
    });

    const evaluated = await analyze({
        email,
        threatIntelAnalyzer: async (receivedEmail) => {
            assert.equal(receivedEmail, email);
            return {
                status: 'evaluated',
                sourceCounts: { web_risk: 1, urlhaus: 3, rdap: -2, redirect: 9, attacker: 9 },
                sourceStatuses: { web_risk: 'ok', urlhaus: 'unavailable', rdap: 'invalid', attacker: 'ok' },
                knownMalicious: true,
                rawUrl: 'https://must-not-be-persisted.example/secret',
                rawDomain: 'must-not-be-persisted.example',
            };
        },
    });
    assert.equal(evaluated.status, undefined);
    assert.deepEqual(evaluated.meta, {
        sourceCounts: { web_risk: 1, urlhaus: 3, rdap: 0, redirect: 9 },
        sourceStatuses: { web_risk: 'ok', urlhaus: 'unavailable', rdap: 'skipped', redirect: 'skipped' },
    });
    assert.deepEqual(evaluated.signals.map(({ key }) => key), ['url_known_malicious']);
    assert.doesNotMatch(JSON.stringify(evaluated.meta), /private|secret|must-not/);

    const failed = await analyze({
        threatIntelAnalyzer: async () => { throw new Error('private upstream failure'); },
    });
    assert.deepEqual(failed, {
        status: 'error', signals: [], meta: {
            sourceCounts: { web_risk: 0, urlhaus: 0, rdap: 0, redirect: 0 },
            sourceStatuses: { web_risk: 'skipped', urlhaus: 'skipped', rdap: 'skipped', redirect: 'skipped' },
        },
    });
});

test('a complete source outage is recorded as skipped with bounded statuses', async () => {
    const result = await analyze({
        threatIntelAnalyzer: async () => ({
            status: 'evaluated',
            sourceCounts: {},
            sourceStatuses: {
                web_risk: 'unavailable',
                urlhaus: 'unavailable',
                rdap: 'unavailable',
                redirect: 'skipped',
                attacker: 'ok',
            },
        }),
    });

    assert.equal(result.status, 'skipped');
    assert.deepEqual(result.meta.sourceStatuses, {
        web_risk: 'unavailable',
        urlhaus: 'unavailable',
        rdap: 'unavailable',
        redirect: 'skipped',
    });
});
