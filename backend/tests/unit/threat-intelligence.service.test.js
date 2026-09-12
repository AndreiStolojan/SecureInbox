import assert from 'node:assert/strict';
import test from 'node:test';

import {
    createThreatIntelligenceService,
} from '../../src/services/threat-intel/threat-intelligence.service.js';

const NOW = new Date('2026-08-03T12:00:00.000Z');

const createMemoryCache = () => {
    const values = new Map();
    const key = ({ source, subject }) => `${source}:${subject}`;

    return {
        values,
        async get(input) {
            return values.get(key(input)) || null;
        },
        async set(input) {
            values.set(key(input), { ...input.value });
        },
    };
};

test('aggregates current sources, redirect evidence and domain age without exposing URLs', async () => {
    const cache = createMemoryCache();
    const calls = { webRisk: 0, urlhaus: 0, rdap: 0, redirect: 0 };
    const service = createThreatIntelligenceService({
        enabled: true,
        cache,
        now: () => NOW,
        webRisk: {
            async lookup(url) {
                calls.webRisk += 1;
                return {
                    status: 'ok',
                    matches: new URL(url).hostname === 'bit.ly' ? ['MALWARE'] : ['SOCIAL_ENGINEERING'],
                    expiresAt: '2026-08-04T12:00:00.000Z',
                };
            },
        },
        urlhaus: {
            async lookup(url) {
                calls.urlhaus += 1;
                return { status: 'ok', match: new URL(url).hostname === 'bad.com' };
            },
        },
        rdap: {
            async lookupDomain(domain) {
                calls.rdap += 1;
                return {
                    status: 'ok',
                    registeredAt: domain === 'bad.com'
                        ? '2026-07-31T12:00:00.000Z'
                        : '2010-01-01T00:00:00.000Z',
                };
            },
        },
        async resolveRedirect() {
            calls.redirect += 1;
            return {
                finalUrl: 'https://target.net/private?token=secret',
                statusCode: 200,
                redirects: ['/1', '/2', '/3', '/4'],
            };
        },
    });
    const email = {
        senderDomain: 'sender.com',
        links: [
            'https://bad.com/login?recipient=person%40example.com',
            'https://bit.ly/go?utm_source=mail',
            'https://bad.com/login?recipient=person%40example.com#duplicate',
        ],
        htmlBody: [
            '<a href="https://bad.com/login?recipient=person%40example.com">https://good.com</a>',
            '<a href="https://bit.ly/go?utm_source=mail">Continue</a>',
        ].join(''),
    };

    const first = await service.analyze(email);
    assert.deepEqual(first, {
        status: 'evaluated',
        sourceCounts: { web_risk: 2, urlhaus: 2, rdap: 2, redirect: 1 },
        sourceStatuses: { web_risk: 'ok', urlhaus: 'ok', rdap: 'ok', redirect: 'ok' },
        knownMalicious: true,
        knownPhishing: true,
        maliciousSources: ['web_risk', 'urlhaus'],
        phishingSources: ['web_risk'],
        domainAgeDays: 3,
        // Empty because both RDAP lookups succeeded here.
        rdapReasons: [],
        linkTextHrefMismatchCount: 1,
        differentRegistrableRedirectTargetCount: 1,
        excessiveRedirectChainCount: 1,
        redirectToPrivateCount: 0,
        checkedUrlCount: 2,
        cappedUrlCount: 0,
        cacheHitCount: 0,
    });
    assert.doesNotMatch(JSON.stringify(first), /bad\.com|target\.net|recipient|token|secret/);

    const second = await service.analyze(email);
    assert.deepEqual(calls, { webRisk: 2, urlhaus: 2, rdap: 2, redirect: 1 });
    assert.equal(second.cacheHitCount, 7);
    assert.equal(second.knownMalicious, true);
    assert.equal(second.domainAgeDays, 3);
});

test('deduplicates links and enforces the per-email URL cap', async () => {
    const calls = [];
    const service = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        maxUrls: 2,
        webRisk: {
            async lookup(url) {
                calls.push({ source: 'web', hostname: new URL(url).hostname });
                return { status: 'ok', matches: [] };
            },
        },
        urlhaus: {
            async lookup(url) {
                calls.push({ source: 'haus', hostname: new URL(url).hostname });
                return { status: 'ok', match: false };
            },
        },
        rdap: {
            async lookupDomain() {
                return { status: 'not_found', registeredAt: null };
            },
        },
    });

    const result = await service.analyze({
        links: [
            'https://one.com/?utm_source=a',
            'https://one.com/#duplicate',
            'https://two.com/',
            'https://three.com/',
        ],
    });

    assert.equal(result.checkedUrlCount, 2);
    assert.equal(result.cappedUrlCount, 1);
    assert.equal(calls.length, 4);
    assert.ok(calls.every((entry) => entry.hostname !== 'three.com'));
});

test('fails open when sources fail independently or the total budget expires', async () => {
    const partial = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        webRisk: { async lookup() { return { status: 'unavailable', matches: [] }; } },
        urlhaus: { async lookup() { throw new Error('offline'); } },
        rdap: { async lookupDomain() { return { status: 'not_found', registeredAt: null }; } },
    });
    const partialResult = await partial.analyze({ links: ['https://example.com/'] });
    assert.equal(partialResult.status, 'evaluated');
    assert.deepEqual(partialResult.sourceStatuses, {
        web_risk: 'unavailable',
        urlhaus: 'unavailable',
        rdap: 'ok',
        redirect: 'skipped',
    });
    assert.equal(partialResult.knownMalicious, false);

    const never = new Promise(() => {});
    const timed = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        timeoutMs: 10,
        webRisk: { lookup: async () => never },
        urlhaus: { lookup: async () => never },
        rdap: { lookupDomain: async () => never },
    });
    const startedAt = Date.now();
    const timedResult = await timed.analyze({ links: ['https://example.com/'] });
    assert.ok(Date.now() - startedAt < 250);
    assert.equal(timedResult.status, 'evaluated');
    assert.deepEqual(timedResult.sourceCounts, {
        web_risk: 0, urlhaus: 0, rdap: 0, redirect: 0,
    });
});

test('an unknown registration age reports why, and is not cached for a month', async () => {
    // Roughly a quarter of live TLDs — .ro, .de, .io among them — have no IANA
    // RDAP endpoint, so for a Romanian inbox this is the common case rather than
    // an edge one. Without the reason reaching the result, an operator cannot
    // tell a working lookup from one that never runs.
    const cache = createMemoryCache();
    const service = createThreatIntelligenceService({
        enabled: true,
        cache,
        webRisk: { async lookup() { return { status: 'ok', matches: [] }; } },
        urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
        rdap: {
            async lookupDomain() {
                return { status: 'unavailable', registeredAt: null, reason: 'registry_unavailable' };
            },
        },
    });

    const result = await service.analyze({ links: ['https://emag.ro/oferta'] });

    assert.equal(result.status, 'evaluated');
    assert.equal(result.domainAgeDays, null);
    assert.deepEqual(result.rdapReasons, ['registry_unavailable']);
    assert.equal(result.sourceStatuses.rdap, 'unavailable');

    // A registry that answers `ok` without a registration event teaches us
    // nothing durable, so it must not occupy the 30-day domain TTL.
    const dated = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        webRisk: { async lookup() { return { status: 'ok', matches: [] }; } },
        urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
        rdap: { async lookupDomain() { return { status: 'ok', registeredAt: null }; } },
    });
    const datedResult = await dated.analyze({ links: ['https://example.com/'] });

    assert.equal(datedResult.domainAgeDays, null);
    assert.deepEqual(datedResult.rdapReasons, []);
});

test('bounds stalled cache reads and writes by the per-scan deadline', async () => {
    const never = new Promise(() => {});
    const readStall = createThreatIntelligenceService({
        enabled: true,
        timeoutMs: 10,
        cache: { get: async () => never, set: async () => {} },
        webRisk: { async lookup() { return { status: 'ok', matches: [] }; } },
        urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
        rdap: { async lookupDomain() { return { status: 'not_found' }; } },
    });
    const writeStall = createThreatIntelligenceService({
        enabled: true,
        timeoutMs: 10,
        cache: { get: async () => null, set: async () => never },
        webRisk: { async lookup() { return { status: 'ok', matches: [] }; } },
        urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
        rdap: { async lookupDomain() { return { status: 'not_found' }; } },
    });

    for (const service of [readStall, writeStall]) {
        const startedAt = Date.now();
        const result = await service.analyze({ links: ['https://example.com/'] });

        assert.ok(Date.now() - startedAt < 250);
        assert.equal(result.status, 'evaluated');
    }
});

test('turns private redirect attempts and long chains into bounded evidence', async () => {
    const privateError = new Error('private address');
    privateError.code = 'SAFE_FETCH_ADDRESS_BLOCKED';
    const redirectLimitError = new Error('too many redirects');
    redirectLimitError.code = 'SAFE_FETCH_REDIRECT_LIMIT';
    redirectLimitError.hopCount = 4;
    const service = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        rdap: { async lookupDomain() { return { status: 'not_found', registeredAt: null }; } },
        async resolveRedirect(url) {
            if (url.includes('bit.ly')) throw privateError;
            throw redirectLimitError;
        },
    });

    const result = await service.analyze({
        links: ['https://bit.ly/private', 'https://tinyurl.com/long'],
    });

    assert.equal(result.redirectToPrivateCount, 1);
    assert.equal(result.excessiveRedirectChainCount, 1);
    assert.equal(result.sourceCounts.redirect, 1);
    assert.equal(result.sourceStatuses.redirect, 'ok');
});

test('caches private redirect blocks only for the short error TTL', async () => {
    const writes = [];
    const privateError = new Error('private address');
    privateError.code = 'SAFE_FETCH_ADDRESS_BLOCKED';
    const service = createThreatIntelligenceService({
        enabled: true,
        cache: {
            async get() { return null; },
            async set(input) { writes.push(input); },
        },
        rdap: { async lookupDomain() { return { status: 'not_found', registeredAt: null }; } },
        async resolveRedirect() { throw privateError; },
    });

    await service.analyze({ links: ['https://bit.ly/private'] });

    const redirectWrite = writes.find(({ source }) => source === 'redirect');
    assert.equal(redirectWrite.value.status, 'blocked');
    assert.equal(redirectWrite.ttlMs, 5 * 60 * 1000);
});

test('disabled threat intelligence performs no work', async () => {
    let calls = 0;
    const service = createThreatIntelligenceService({
        enabled: false,
        cache: createMemoryCache(),
        webRisk: { async lookup() { calls += 1; } },
    });

    assert.deepEqual(await service.analyze({ links: ['https://example.com/'] }), {
        status: 'disabled',
        sourceCounts: { web_risk: 0, urlhaus: 0, rdap: 0, redirect: 0 },
    });
    assert.equal(calls, 0);
});

test('correlated Web Risk categories do not double-score one source result', async () => {
    const service = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        webRisk: {
            async lookup() {
                return { status: 'ok', matches: ['MALWARE', 'SOCIAL_ENGINEERING'] };
            },
        },
        urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
        rdap: { async lookupDomain() { return { status: 'not_found', registeredAt: null }; } },
    });

    const result = await service.analyze({ links: ['https://example.com/'] });
    assert.equal(result.knownPhishing, true);
    assert.equal(result.knownMalicious, false);
    assert.deepEqual(result.phishingSources, ['web_risk']);
    assert.deepEqual(result.maliciousSources, []);
});

test('canonical equivalents share one in-flight lookup across concurrent scans', async () => {
    const calls = { webRisk: 0, urlhaus: 0, rdap: 0 };
    const pause = () => new Promise((resolve) => setTimeout(resolve, 5));
    const service = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        webRisk: {
            async lookup() {
                calls.webRisk += 1;
                await pause();
                return { status: 'ok', matches: [] };
            },
        },
        urlhaus: {
            async lookup() {
                calls.urlhaus += 1;
                await pause();
                return { status: 'ok', match: false };
            },
        },
        rdap: {
            async lookupDomain() {
                calls.rdap += 1;
                await pause();
                return { status: 'not_found', registeredAt: null };
            },
        },
    });

    await Promise.all([
        service.analyze({ links: ['https://EXAMPLE.com:443/a/../offer?utm_source=one#top'] }),
        service.analyze({ links: ['https://example.com/offer?fbclid=two'] }),
    ]);

    assert.deepEqual(calls, { webRisk: 1, urlhaus: 1, rdap: 1 });
});

test('redirect target comparison uses the sender registrable domain', async () => {
    const service = createThreatIntelligenceService({
        enabled: true,
        cache: createMemoryCache(),
        rdap: { async lookupDomain() { return { status: 'not_found', registeredAt: null }; } },
        async resolveRedirect() {
            return {
                finalUrl: 'https://accounts.sender.com/login',
                statusCode: 200,
                redirects: ['https://accounts.sender.com/login'],
            };
        },
    });

    const sameSender = await service.analyze({
        senderDomain: 'mail.sender.com',
        links: ['https://bit.ly/account'],
    });
    assert.equal(sameSender.differentRegistrableRedirectTargetCount, 0);

    const differentSender = await service.analyze({
        senderDomain: 'other.com',
        links: ['https://bit.ly/account'],
    });
    assert.equal(differentSender.differentRegistrableRedirectTargetCount, 1);
});

test('a timed-out single-flight waiter does not cancel a later scan', async () => {
    const cache = createMemoryCache();
    let webRiskCalls = 0;
    const service = createThreatIntelligenceService({
        enabled: true,
        cache,
        timeoutMs: 50,
        webRisk: {
            lookup(_url, { signal }) {
                webRiskCalls += 1;
                return new Promise((resolve, reject) => {
                    const timeoutId = setTimeout(
                        () => resolve({ status: 'ok', matches: [] }),
                        60
                    );
                    signal.addEventListener('abort', () => {
                        clearTimeout(timeoutId);
                        reject(signal.reason);
                    }, { once: true });
                });
            },
        },
        urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
        rdap: { async lookupDomain() { return { status: 'not_found', registeredAt: null }; } },
    });
    const email = { links: ['https://example.com/'] };
    const firstPromise = service.analyze(email);
    await new Promise((resolve) => setTimeout(resolve, 30));
    const secondPromise = service.analyze(email);
    const [first, second] = await Promise.all([firstPromise, secondPromise]);

    assert.equal(webRiskCalls, 1);
    assert.equal(first.sourceStatuses.web_risk, 'unavailable');
    assert.equal(second.sourceStatuses.web_risk, 'ok');
    assert.equal(
        cache.values.get('web_risk:https://example.com/').status,
        'clean'
    );
});

test('an already-expired single-flight deadline observes an orphaned rejection', async () => {
    const unhandled = [];
    const onUnhandled = (error) => unhandled.push(error);
    process.on('unhandledRejection', onUnhandled);

    try {
        const service = createThreatIntelligenceService({
            enabled: true,
            timeoutMs: 1,
            cache: {
                async get() {
                    await new Promise((resolve) => setTimeout(resolve, 5));
                    return null;
                },
                async set() {},
            },
            webRisk: { async lookup() { return { status: 'ok', matches: [] }; } },
            urlhaus: { async lookup() { return { status: 'ok', match: false }; } },
            rdap: { async lookupDomain() { return { status: 'not_found' }; } },
            async resolveRedirect() {
                throw new Error('redirect failed after its waiter expired');
            },
        });

        const result = await service.analyze({ links: ['https://bit.ly/abc'] });
        await new Promise((resolve) => setImmediate(resolve));

        assert.equal(result.status, 'evaluated');
        assert.deepEqual(unhandled, []);
    } finally {
        process.off('unhandledRejection', onUnhandled);
    }
});
