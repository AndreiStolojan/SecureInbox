import assert from 'node:assert/strict';
import test from 'node:test';

import AttachmentHash from '../../src/models/attachment-hash.model.js';
import {
    createHashReputationService,
    hashAttachmentBuffer,
    MALICIOUS_TTL_MS,
    UNKNOWN_TTL_MS,
} from '../../src/services/attachment/hash-reputation.service.js';

const jsonResponse = (body) => new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
});

const createMemoryCache = () => {
    const values = new Map();
    const writes = [];
    return {
        values,
        writes,
        async get(hash) { return values.get(hash) || null; },
        async set(hash, verdict, ttlMs) {
            values.set(hash, { verdict });
            writes.push({ hash, verdict, ttlMs });
        },
    };
};

test('MalwareBazaar sends only a SHA-256 hash and caches a malicious hit', async () => {
    const cache = createMemoryCache();
    const sha256 = hashAttachmentBuffer(Buffer.from('harmless synthetic bytes'));
    let request;
    const service = createHashReputationService({
        authKey: 'free-community-key',
        cache,
        fetch: async (url, options) => {
            request = { url, options };
            return jsonResponse({ query_status: 'ok', data: [{ sha256_hash: sha256 }] });
        },
    });

    assert.deepEqual(await service.lookupHash(sha256), {
        status: 'ok', malicious: true, cached: false,
    });
    assert.equal(request.options.headers['Auth-Key'], 'free-community-key');
    assert.equal(request.options.body, `query=get_info&hash=${sha256}`);
    assert.doesNotMatch(request.options.body, /filename|bytes|harmless|data=/i);
    assert.deepEqual(cache.writes, [{
        hash: sha256,
        verdict: 'malicious',
        ttlMs: MALICIOUS_TTL_MS,
    }]);
});

test('MalwareBazaar caches misses and makes no request without an Auth-Key', async () => {
    const cache = createMemoryCache();
    const sha256 = 'a'.repeat(64);
    let calls = 0;
    const service = createHashReputationService({
        authKey: 'key',
        cache,
        fetch: async () => {
            calls += 1;
            return jsonResponse({ query_status: 'hash_not_found' });
        },
    });

    assert.deepEqual(await service.lookupHash(sha256), {
        status: 'ok', malicious: false, cached: false,
    });
    assert.deepEqual(await service.lookupHash(sha256), {
        status: 'ok', malicious: false, cached: true,
    });
    assert.equal(calls, 1);
    assert.equal(cache.writes[0].ttlMs, UNKNOWN_TTL_MS);

    const disabled = createHashReputationService({
        cache: createMemoryCache(),
        fetch: async () => { calls += 1; },
    });
    assert.deepEqual(await disabled.lookupHash(sha256), {
        status: 'unavailable', malicious: false, reason: 'not_configured',
    });
    assert.equal(calls, 1);
});

test('an aborted caller does not wait for a stalled cache read or leak its late rejection', async () => {
    const unhandled = [];
    const onUnhandled = (error) => unhandled.push(error);
    process.on('unhandledRejection', onUnhandled);

    let rejectRead;
    let markReadStarted;
    let cacheSignal;
    const readStarted = new Promise((resolve) => { markReadStarted = resolve; });
    let fetchCalls = 0;
    const controller = new AbortController();
    const service = createHashReputationService({
        authKey: 'key',
        cache: {
            get: (_hash, { signal }) => new Promise((_resolve, reject) => {
                cacheSignal = signal;
                rejectRead = reject;
                markReadStarted();
            }),
            async set() {},
        },
        fetch: async () => {
            fetchCalls += 1;
            return jsonResponse({ query_status: 'hash_not_found' });
        },
    });

    try {
        const lookup = service.lookupHash('a'.repeat(64), { signal: controller.signal });
        await readStarted;
        controller.abort();

        assert.deepEqual(await lookup, {
            status: 'unavailable', malicious: false, reason: 'timeout',
        });
        assert.equal(fetchCalls, 0);
        assert.equal(cacheSignal?.aborted, true);

        rejectRead(new Error('late cache read failure'));
        await new Promise((resolve) => setImmediate(resolve));
        assert.deepEqual(unhandled, []);
    } finally {
        process.off('unhandledRejection', onUnhandled);
    }
});

test('an aborted caller does not wait for a stalled cache write or leak its late rejection', async () => {
    const unhandled = [];
    const onUnhandled = (error) => unhandled.push(error);
    process.on('unhandledRejection', onUnhandled);

    let rejectWrite;
    let markWriteStarted;
    let cacheSignal;
    const writeStarted = new Promise((resolve) => { markWriteStarted = resolve; });
    const controller = new AbortController();
    const service = createHashReputationService({
        authKey: 'key',
        cache: {
            async get() { return null; },
            set: (_hash, _verdict, _ttlMs, { signal }) => new Promise((_resolve, reject) => {
                cacheSignal = signal;
                rejectWrite = reject;
                markWriteStarted();
            }),
        },
        fetch: async () => jsonResponse({ query_status: 'hash_not_found' }),
    });

    try {
        const lookup = service.lookupHash('b'.repeat(64), { signal: controller.signal });
        await writeStarted;
        controller.abort();

        assert.deepEqual(await lookup, {
            status: 'ok', malicious: false, cached: false,
        });
        assert.equal(cacheSignal?.aborted, true);

        rejectWrite(new Error('late cache write failure'));
        await new Promise((resolve) => setImmediate(resolve));
        assert.deepEqual(unhandled, []);
    } finally {
        process.off('unhandledRejection', onUnhandled);
    }
});

test('attachment hash cache schema has a unique hash and absolute TTL index', () => {
    const indexes = AttachmentHash.schema.indexes();
    assert.equal(AttachmentHash.collection.collectionName, 'attachmenthashes');
    assert.ok(indexes.some(([fields, options]) => fields.sha256 === 1 && options.unique));
    assert.ok(indexes.some(([fields, options]) =>
        fields.expiresAt === 1 && options.expireAfterSeconds === 0
    ));
});
