// Benchmarks only generated mail in a fresh loopback MongoDB database, then drops it.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import os from 'node:os';
import mongoose from 'mongoose';

const uri = process.argv[2];
const target = new URL(uri);
if (target.protocol !== 'mongodb:' || target.hostname !== '127.0.0.1'
    || target.username || target.password || target.search || target.pathname !== '/') {
    throw new Error('Supply mongodb://127.0.0.1:PORT/ for a disposable local server.');
}
Object.assign(process.env, {
    NODE_ENV: 'test', PORT: '5500', DB_URI: uri, JWT_SECRET: 'synthetic-test',
    JWT_EXPIRES_IN: '1h', MAIL_TOKEN_ENCRYPTION_KEY: 'synthetic-test',
    GMAIL_PUSH_ENABLED: 'false', THREAT_INTEL_ENABLED: 'false', AI_SEMANTIC_ENABLED: 'false',
});
const [{ default: Email }, { default: Scan }, { default: Entry }, { getSenderListEntries }] = await Promise.all([
    import('../src/models/email.model.js'), import('../src/models/scan.model.js'),
    import('../src/models/sender-list.model.js'), import('../src/services/sender-list.service.js'),
]);
const database = `sender_benchmark_${randomUUID().replaceAll('-', '')}_test`;
await mongoose.connect(uri, { dbName: database, serverSelectionTimeoutMS: 5000 });
const id = (n) => new mongoose.Types.ObjectId(n.toString(16).padStart(24, '0'));
const userId = id(1);
const otherUser = id(2);
const buckets = ['safe', 'needs_review', 'quarantine', 'reviewed_safe', 'confirmed_phishing', 'unscanned'];
const emails = [];
const scans = [];
const entries = [];
for (let domain = 0; domain < 100; domain++) {
    for (let bucket = 0; bucket < 6; bucket++) {
        const emailId = id(1000 + domain * 6 + bucket);
        emails.push({ _id: emailId, userId, providerMessageId: String(emailId),
            from: `Sender <person@d${domain}.example.test>`, senderDomain: `d${domain}.example.test`,
            receivedAt: new Date('2026-01-01'), inboxState: bucket === 5 ? 'removed' : 'present',
            userVerdict: bucket === 3 ? 'safe' : bucket === 4 ? 'phishing' : null });
        if (bucket !== 5) scans.push({ _id: id(10000 + domain * 6 + bucket), userId, emailId,
            verdict: ['safe', 'suspicious', 'likely_phishing'][bucket % 3], scannedAt: new Date('2026-01-01') });
    }
    entries.push({ _id: id(20000 + domain * 2), userId, listType: 'allow', kind: 'sender',
        value: `person@d${domain}.example.test`, createdAt: new Date(2026000000000 - domain * 2) });
    entries.push({ _id: id(20001 + domain * 2), userId, listType: 'allow', kind: 'domain',
        value: domain === 0 ? 'example.test' : `d${domain}.example.test`, createdAt: new Date(2026000000000 - domain * 2 - 1) });
}
const originalAggregate = Email.aggregate;
let active = 0;
let peak = 0;
let queryCount = 0;
Email.aggregate = async function (...args) {
    queryCount++;
    active++;
    peak = Math.max(peak, active);
    try { return await originalAggregate.apply(this, args); }
    finally { active--; }
};
const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];
const results = [];
try {
    await Promise.all([Email.init(), Scan.init(), Entry.init()]);
    await Email.collection.insertMany([...emails, ...emails.slice(0, 6).map((email, index) => ({
        ...email, _id: id(30000 + index), userId: otherUser,
    }))]);
    await Scan.collection.insertMany(scans);
    for (const count of [0, 1, 50, 200]) {
        await Entry.deleteMany({ userId });
        if (count) await Entry.collection.insertMany(entries.slice(0, count));
        const durations = [];
        const memory = [];
        for (let sample = -3; sample < 12; sample++) {
            active = peak = queryCount = 0;
            let peakRss = process.memoryUsage().rss;
            const timer = setInterval(() => { peakRss = Math.max(peakRss, process.memoryUsage().rss); }, 5);
            const start = performance.now();
            let actual;
            try { actual = await getSenderListEntries({ userId, withMatchCounts: true }); }
            finally { clearInterval(timer); }
            const duration = performance.now() - start;
            assert.equal(active, 0);
            assert.equal(queryCount, count);
            assert.equal(actual.length, count);
            actual.forEach((entry, index) => {
                assert.equal(String(entry.id), String(entries[index]._id));
                const perBucket = entry.value === 'example.test' ? 100 : 1;
                assert.equal(entry.matchedEmails, perBucket * 6);
                assert.deepEqual(entry.matchedByBucket, Object.fromEntries(buckets.map((bucket) => [bucket, perBucket])));
            });
            if (sample >= 0) { durations.push(duration); memory.push(Math.max(peakRss, process.memoryUsage().rss)); }
        }
        assert.deepEqual(await getSenderListEntries({ userId: otherUser, withMatchCounts: true }), []);
        results.push({ rules: count, aggregationCount: count, databaseOperations: count + 1, maxInflightAggregations: peak,
            medianMs: percentile(durations, 0.5), p95Ms: percentile(durations, 0.95),
            peakSampledRssBytes: Math.max(...memory), samplesMs: durations });
    }
    console.log(JSON.stringify({ revision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
        node: process.version, architecture: os.arch(), platform: os.platform(),
        mongo: (await mongoose.connection.db.admin().serverInfo()).version,
        warmups: 3, samples: 12, syntheticEmails: 606, results }, null, 2));
} finally {
    Email.aggregate = originalAggregate;
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
}
