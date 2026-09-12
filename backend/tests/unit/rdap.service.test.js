import assert from 'node:assert/strict';
import test from 'node:test';

import { createRdapService, normalizeRdapDomain } from '../../src/services/threat-intel/rdap.service.js';
import { createSafeJsonGet } from '../../src/services/threat-intel/safe-fetch.service.js';

const PUBLIC_ADDRESS = '8.8.8.8';
const bootstrap = {
    services: [[['com'], ['https://rdap.example.test/base/']]],
};

const streamedJsonResponse = (body, { status = 200 } = {}) => Object.assign(
    new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json' },
    }),
    { statusCode: status, remoteAddress: PUBLIC_ADDRESS }
);

const createTestJsonGet = (handler, requests) => createSafeJsonGet({
    dnsLookup: async () => [{ address: PUBLIC_ADDRESS, family: 4 }],
    requestAdapter: async (request) => {
        requests?.push(request);
        return handler(request);
    },
});

test('RDAP caches IANA bootstrap and sends only a registrable domain to its pinned registry GET', async () => {
    const requests = [];
    let currentTime = new Date('2026-08-03T12:00:00.000Z');
    const service = createRdapService({
        now: () => currentTime,
        bootstrapTtlMs: 60_000,
        safeJsonGet: createTestJsonGet(({ options }) => {
            if (options.hostname === 'data.iana.org') {
                return streamedJsonResponse(bootstrap);
            }
            return streamedJsonResponse({
                objectClassName: 'domain',
                events: [{ eventAction: 'registration', eventDate: '2026-07-10T00:00:00Z' }],
            });
        }, requests),
    });

    assert.deepEqual(await service.lookupDomain('Sub.Example.com.'), {
        status: 'ok', registeredAt: '2026-07-10T00:00:00.000Z',
    });
    currentTime = new Date('2026-08-03T12:00:30.000Z');
    await service.lookupDomain('another-example.com');

    assert.equal(requests.length, 3);
    assert.equal(requests[1].options.path, '/base/domain/example.com');
    assert.equal(requests[2].options.path, '/base/domain/another-example.com');
    assert.equal(requests[1].options.method, 'GET');
    assert.equal(requests[1].options.headers.Accept, 'application/rdap+json, application/json');
    assert.equal(requests[1].expectedAddress, PUBLIC_ADDRESS);
    assert.equal(requests[1].maxBytes, 256 * 1024);
});

test('RDAP validates domain, bootstrap, and registry payloads fail-open', async () => {
    let calls = 0;
    const invalidDomain = createRdapService({ safeJsonGet: async () => { calls += 1; } });
    assert.deepEqual(await invalidDomain.lookupDomain('https://example.com/private'), {
        status: 'unavailable', registeredAt: null, reason: 'invalid_domain',
    });
    assert.equal(calls, 0);

    const invalidBootstrapRequests = [];
    const invalidBootstrap = createRdapService({
        safeJsonGet: createTestJsonGet(
            () => streamedJsonResponse({ services: [] }),
            invalidBootstrapRequests
        ),
    });
    assert.deepEqual(await invalidBootstrap.lookupDomain('example.com'), {
        status: 'unavailable', registeredAt: null, reason: 'bootstrap_unavailable',
    });
    assert.equal(invalidBootstrapRequests.length, 1);

    const noRegistration = createRdapService({
        safeJsonGet: createTestJsonGet(({ options }) => options.hostname === 'data.iana.org'
            ? streamedJsonResponse(bootstrap)
            : streamedJsonResponse({ objectClassName: 'domain', events: [] })
        ),
    });
    assert.deepEqual(await noRegistration.lookupDomain('example.com'), {
        status: 'ok', registeredAt: null,
    });
});

test('RDAP normalizes only registrable public-looking domains', () => {
    assert.equal(normalizeRdapDomain('WWW.Example.COM.'), 'example.com');
    assert.equal(normalizeRdapDomain('localhost'), null);
    assert.equal(normalizeRdapDomain('bad_domain.example'), null);
    assert.equal(normalizeRdapDomain('https://example.com'), null);
});

test('RDAP rejects private or local registry endpoints from bootstrap data', async () => {
    const requests = [];
    const service = createRdapService({
        safeJsonGet: createTestJsonGet(
            () => streamedJsonResponse({
                services: [[
                    ['com'],
                    ['https://127.0.0.1/rdap/', 'https://registry.local/rdap/'],
                ]],
            }),
            requests
        ),
    });

    assert.deepEqual(await service.lookupDomain('example.com'), {
        status: 'unavailable', registeredAt: null, reason: 'bootstrap_unavailable',
    });
    assert.equal(requests.length, 1);
});

test('RDAP bootstrap uses one refresh, negative-caches failures, then retries after the short TTL', async () => {
    let currentTime = new Date('2026-08-03T12:00:00.000Z');
    let bootstrapRequests = 0;
    const service = createRdapService({
        now: () => currentTime,
        bootstrapNegativeTtlMs: 1_000,
        safeJsonGet: async () => {
            bootstrapRequests += 1;
            return { ok: false, status: 503, body: null };
        },
    });

    const results = await Promise.all([
        service.lookupDomain('one-example.com'),
        service.lookupDomain('two-example.com'),
    ]);
    assert.deepEqual(results, [
        { status: 'unavailable', registeredAt: null, reason: 'bootstrap_unavailable' },
        { status: 'unavailable', registeredAt: null, reason: 'bootstrap_unavailable' },
    ]);
    assert.equal(bootstrapRequests, 1);

    currentTime = new Date('2026-08-03T12:00:00.500Z');
    await service.lookupDomain('three-example.com');
    assert.equal(bootstrapRequests, 1);

    currentTime = new Date('2026-08-03T12:00:01.000Z');
    await service.lookupDomain('four-example.com');
    assert.equal(bootstrapRequests, 2);
});

test('RDAP serves a stale bootstrap during a short refresh outage', async () => {
    let currentTime = new Date('2026-08-03T12:00:00.000Z');
    let bootstrapRequests = 0;
    const service = createRdapService({
        now: () => currentTime,
        bootstrapTtlMs: 60_000,
        bootstrapNegativeTtlMs: 1_000,
        safeJsonGet: async (url) => {
            if (new URL(url).hostname === 'data.iana.org') {
                bootstrapRequests += 1;
                return bootstrapRequests === 1
                    ? { ok: true, status: 200, body: bootstrap }
                    : { ok: false, status: 503, body: null };
            }
            return {
                ok: true,
                status: 200,
                body: { objectClassName: 'domain', events: [] },
            };
        },
    });

    assert.deepEqual(await service.lookupDomain('first-example.com'), {
        status: 'ok', registeredAt: null,
    });
    currentTime = new Date('2026-08-03T12:01:00.000Z');
    assert.deepEqual(await service.lookupDomain('second-example.com'), {
        status: 'ok', registeredAt: null,
    });
    currentTime = new Date('2026-08-03T12:01:00.500Z');
    assert.deepEqual(await service.lookupDomain('third-example.com'), {
        status: 'ok', registeredAt: null,
    });
    assert.equal(bootstrapRequests, 2);
});

test('a cancelled bootstrap waiter does not cancel the shared refresh for another lookup', async () => {
    let releaseBootstrap;
    let bootstrapSignal;
    let bootstrapStartedResolve;
    const bootstrapStarted = new Promise((resolve) => {
        bootstrapStartedResolve = resolve;
    });
    const service = createRdapService({
        safeJsonGet: (url, { signal }) => {
            if (new URL(url).hostname === 'data.iana.org') {
                bootstrapSignal = signal;
                bootstrapStartedResolve();
                return new Promise((resolve) => {
                    releaseBootstrap = () => resolve({ ok: true, status: 200, body: bootstrap });
                });
            }
            return Promise.resolve({
                ok: true,
                status: 200,
                body: { objectClassName: 'domain', events: [] },
            });
        },
    });
    const controller = new AbortController();
    const cancelledLookup = service.lookupDomain('one-example.com', { signal: controller.signal });
    await bootstrapStarted;

    controller.abort();
    assert.deepEqual(await cancelledLookup, {
        status: 'unavailable', registeredAt: null, reason: 'bootstrap_unavailable',
    });
    assert.equal(bootstrapSignal, undefined);

    const activeLookup = service.lookupDomain('two-example.com');
    releaseBootstrap();
    assert.deepEqual(await activeLookup, { status: 'ok', registeredAt: null });
});
