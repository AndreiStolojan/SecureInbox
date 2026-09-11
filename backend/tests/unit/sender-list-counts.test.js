import assert from 'node:assert/strict';
import test from 'node:test';
import mongoose from 'mongoose';
import Email from '../../src/models/email.model.js';
import SenderListEntry from '../../src/models/sender-list.model.js';
import { getSenderListEntries } from '../../src/services/sender-list.service.js';

const userId = new mongoose.Types.ObjectId();
const entries = Array.from({ length: 12 }, (_, index) => ({
    _id: new mongoose.Types.ObjectId(), kind: 'domain', listType: 'allow',
    value: `d${index}.example.test`, createdAt: new Date(),
}));

// Return controlled rules without a database; aggregate behavior is supplied per test.
const stubEntries = (t, values = entries) => {
    t.mock.method(SenderListEntry, 'find', (filter) => {
        assert.deepEqual(filter, { userId });
        return { sort: () => values };
    });
};

test('sender counts bound active queries, preserve order and include every risk bucket', async (t) => {
    stubEntries(t);
    let active = 0;
    let peak = 0;
    let calls = 0;
    t.mock.method(Email, 'aggregate', async (pipeline) => {
        const index = calls++;
        assert.equal(String(pipeline[0].$match.userId), String(userId));
        assert.equal(pipeline[0].$match.inboxState, undefined); // Removed mail still counts.
        active++;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setImmediate(resolve));
        active--;
        return [{ _id: 'safe', count: index }, { _id: 'unscanned', count: 1 }];
    });
    const result = await getSenderListEntries({ userId, withMatchCounts: true });
    assert.equal(peak, 4);
    assert.equal(active, 0);
    assert.equal(calls, entries.length);
    assert.deepEqual(result.map((entry) => entry.id), entries.map((entry) => entry._id));
    result.forEach((entry, index) => {
        assert.equal(entry.matchedEmails, index + 1);
        assert.deepEqual(entry.matchedByBucket, { safe: index, needs_review: 0, quarantine: 0,
            reviewed_safe: 0, confirmed_phishing: 0, unscanned: 1 });
    });
});

test('empty and count-free sender lists never aggregate', async (t) => {
    stubEntries(t, []);
    const aggregate = t.mock.method(Email, 'aggregate', () => { throw new Error('unexpected query'); });
    assert.deepEqual(await getSenderListEntries({ userId, withMatchCounts: true }), []);
    assert.deepEqual(await getSenderListEntries({ userId }), []);
    assert.equal(aggregate.mock.callCount(), 0);
});

test('failed counts reject the request, settle bounded work and allow another request', async (t) => {
    stubEntries(t);
    let active = 0;
    let calls = 0;
    let fail = true;
    t.mock.method(Email, 'aggregate', async () => {
        const current = calls++;
        active++;
        try {
            await new Promise((resolve) => setImmediate(resolve));
            if (fail && current === 0) throw new Error('database unavailable');
            return [];
        } finally { active--; }
    });
    await assert.rejects(getSenderListEntries({ userId, withMatchCounts: true }), /database unavailable/);
    // Existing workers may finish after rejection. Drain them before testing a new call.
    for (let turn = 0; turn < entries.length; turn++) await new Promise((resolve) => setImmediate(resolve));
    assert.equal(active, 0);
    fail = false;
    assert.equal((await getSenderListEntries({ userId, withMatchCounts: true })).length, entries.length);
    assert.equal(active, 0);
});
