// Compare existing indexes with two candidates using actual inbox service queries.
// Only a new synthetic database on a disposable loopback MongoDB server is touched.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import mongoose from 'mongoose';

const uri = process.argv[2];
const target = new URL(uri);
if (target.protocol !== 'mongodb:' || target.hostname !== '127.0.0.1'
    || target.username || target.password || target.search || target.pathname !== '/') {
    throw new Error('Supply mongodb://127.0.0.1:PORT/ for a disposable local server.');
}
Object.assign(process.env, { NODE_ENV: 'test', PORT: '5500', DB_URI: uri,
    JWT_SECRET: 'synthetic', JWT_EXPIRES_IN: '1h', MAIL_TOKEN_ENCRYPTION_KEY: 'synthetic',
    GMAIL_PUSH_ENABLED: 'false', APP_READ_ONLY: 'false' });
const [{ default: Email }, { default: Scan }, { getEmailsForUser }] = await Promise.all([
    import('../src/models/email.model.js'), import('../src/models/scan.model.js'),
    import('../src/services/email.service.js'),
]);
const database = `inbox_index_${randomUUID().replaceAll('-', '')}_test`;
await mongoose.connect(uri, { dbName: database, serverSelectionTimeoutMS: 5000 });
const id = (n) => new mongoose.Types.ObjectId(n.toString(16).padStart(24, '0'));
const userId = id(1);
const otherUser = id(2);
const account = id(3);
const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];
const summarize = (samplesMs) => ({ medianMs: percentile(samplesMs, .5), p95Ms: percentile(samplesMs, .95), samplesMs });
const candidates = [
    { name: 'existing' },
    { name: 'inbox_stable_order', key: { userId: 1, receivedAt: -1, _id: -1 } },
    { name: 'inbox_state_order', key: { userId: 1, inboxState: 1, receivedAt: -1, _id: -1 } },
];
const queries = [
    ['first', {}], ['later', { page: '10' }], ['empty', { page: '9999' }],
    ['account', { mailAccountId: String(account) }],
    ['range', { from: '2026-01-01', to: '2026-01-10' }], ['search', { q: 'needle' }],
    ['safe', { riskBucket: 'safe' }], ['reviewed', { riskBucket: 'reviewed_safe' }],
    ['unscanned', { riskBucket: 'unscanned' }], ['phishing', { verdict: 'phishing' }],
];
const originalAggregate = Email.aggregate;
let pipelines = [];
Email.aggregate = function (pipeline) { pipelines.push(pipeline); return originalAggregate.call(this, pipeline); };
const output = { revision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    node: process.version, architecture: process.arch, warmups: 3, samples: 12, workloads: [] };
try {
    await Promise.all([Email.init(), Scan.init()]);
    output.mongo = (await mongoose.connection.db.admin().serverInfo()).version;
    output.existingIndexes = await Email.collection.listIndexes().toArray();
    for (const size of [600, 6000]) {
        await Email.deleteMany({});
        await Scan.deleteMany({});
        const emails = Array.from({ length: size }, (_, i) => ({
            _id: id(1000 + i), userId, providerMessageId: `synthetic-${i}`,
            mailAccountId: i % 2 ? account : id(4), from: `person${i % 20}@example.test`,
            subject: i % 9 ? 'ordinary synthetic mail' : 'synthetic needle',
            receivedAt: new Date(Date.UTC(2026, 0, 1) + Math.floor(i / 4) * 3600000),
            ...(i % 10 === 1 ? {} : { inboxState: i % 10 === 0 ? 'removed' : 'present' }),
            userVerdict: i % 6 === 3 ? 'safe' : i % 6 === 4 ? 'phishing' : null,
        }));
        await Email.collection.insertMany([...emails, { ...emails[0], _id: id(90000), userId: otherUser, inboxState: 'present' }]);
        await Scan.collection.insertMany(emails.filter((_, i) => i % 6 !== 5).map((email, i) => ({
            _id: id(100000 + i), emailId: email._id, userId,
            verdict: ['safe', 'suspicious', 'likely_phishing'][i % 3], scannedAt: new Date('2026-02-01'),
        })));
        const baseline = new Map();
        const expectedIds = emails.filter((email) => email.inboxState !== 'removed')
            .sort((a, b) => b.receivedAt - a.receivedAt || String(b._id).localeCompare(String(a._id)))
            .map((email) => String(email._id));
        for (const candidate of candidates) {
            if (candidate.key) await Email.collection.createIndex(candidate.key, { name: candidate.name });
            const measured = { size, candidate: candidate.name, queries: [] };
            // A fixed dataset has neither duplicates nor gaps across every page.
            const actualIds = [];
            for (let page = 1; actualIds.length < expectedIds.length; page++) {
                const result = await getEmailsForUser({ userId, query: { page: String(page), limit: '100' } });
                assert.equal(result.pagination.total, expectedIds.length);
                assert.ok(result.items.length);
                actualIds.push(...result.items.map((email) => String(email._id)));
            }
            assert.deepEqual(actualIds, expectedIds);
            const isolated = await getEmailsForUser({ userId: otherUser, query: {} });
            assert.equal(isolated.pagination.total, 1);
            assert.equal(String(isolated.items[0]._id), String(id(90000)));
            for (const [name, query] of queries) {
                const samples = [];
                let result;
                for (let sample = -3; sample < 12; sample++) {
                    pipelines = [];
                    const start = performance.now();
                    result = await getEmailsForUser({ userId, query });
                    if (sample >= 0) samples.push(performance.now() - start);
                    if (candidate.name === 'existing') baseline.set(name, result);
                    else assert.deepEqual(result, baseline.get(name));
                }
                const plans = [];
                for (const pipeline of pipelines) {
                    const explain = await Email.collection.aggregate(pipeline).explain('executionStats');
                    const cursor = explain.stages?.find((stage) => stage.$cursor)?.$cursor || explain;
                    plans.push({ documentsExamined: cursor.executionStats?.totalDocsExamined,
                        keysExamined: cursor.executionStats?.totalKeysExamined,
                        winningPlan: cursor.queryPlanner?.winningPlan,
                        blockingSort: JSON.stringify(cursor.queryPlanner?.winningPlan).includes('"SORT"')
                            || (explain.stages || []).some((stage) => stage.$sort || stage.$facet?.items?.some((item) => item.$sort)),
                        lookups: (explain.stages || []).filter((stage) => stage.$lookup).map((stage) => ({
                            documentsExamined: stage.totalDocsExamined, keysExamined: stage.totalKeysExamined,
                            indexesUsed: stage.indexesUsed,
                        })) });
                }
                measured.queries.push({ name, ...summarize(samples), plans });
            }
            measured.indexSizes = (await mongoose.connection.db.command({ collStats: 'emails' })).indexSizes;
            const inserts = [];
            const updates = [];
            for (let sample = 0; sample < 8; sample++) {
                const extra = emails.slice(0, 200).map((email, i) => ({ ...email, _id: id(500000 + i), providerMessageId: `write-${i}` }));
                let start = performance.now();
                await Email.collection.insertMany(extra);
                inserts.push(performance.now() - start);
                start = performance.now();
                await Email.collection.updateMany({ providerMessageId: /^write-/ }, { $set: { receivedAt: new Date('2026-03-01') } });
                updates.push(performance.now() - start);
                await Email.collection.deleteMany({ providerMessageId: /^write-/ });
            }
            measured.insert200 = summarize(inserts);
            measured.update200 = summarize(updates);
            output.workloads.push(measured);
            if (candidate.key) await Email.collection.dropIndex(candidate.name);
        }
    }
    console.log(JSON.stringify(output, null, 2));
} finally {
    Email.aggregate = originalAggregate;
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
}
