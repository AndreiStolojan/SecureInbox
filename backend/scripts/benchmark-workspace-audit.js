// Reproduce the inbox-query audit on generated mail in a fresh loopback database.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import mongoose from 'mongoose';

const BASELINE_REVISION = '9567caf';
const IMPLEMENTATION_REVISION = '5cec9dc';
const uri = process.argv[2];
const target = new URL(uri);
if (target.protocol !== 'mongodb:' || target.hostname !== '127.0.0.1'
    || target.username || target.password || target.search || target.pathname !== '/') {
    throw new Error('Supply mongodb://127.0.0.1:PORT/ for a disposable local server.');
}

Object.assign(process.env, {
    NODE_ENV: 'test',
    PORT: '5500',
    DB_URI: uri,
    JWT_SECRET: 'synthetic-test',
    JWT_EXPIRES_IN: '1h',
    MAIL_TOKEN_ENCRYPTION_KEY: 'synthetic-test',
    GMAIL_PUSH_ENABLED: 'false',
    ATTACHMENT_ANALYSIS_ENABLED: 'false',
});

const serviceUrl = new URL('../src/services/email.service.js', import.meta.url);
const mongooseUrl = import.meta.resolve('mongoose');
const baselineSource = execFileSync(
    'git',
    ['show', `${BASELINE_REVISION}:backend/src/services/email.service.js`],
    { encoding: 'utf8' }
).replace(/from '([^']+)'/g, (statement, specifier) => {
    if (specifier.startsWith('.')) return `from '${new URL(specifier, serviceUrl).href}'`;
    if (specifier === 'mongoose') return `from '${mongooseUrl}'`;
    return statement;
});

const [{ default: Email }, { default: Scan }, baseline, current] = await Promise.all([
    import('../src/models/email.model.js'),
    import('../src/models/scan.model.js'),
    import(`data:text/javascript;base64,${Buffer.from(baselineSource).toString('base64')}`),
    import(serviceUrl),
]);

const database = `workspace_audit_${randomUUID().replaceAll('-', '')}_test`;
await mongoose.connect(uri, { dbName: database, serverSelectionTimeoutMS: 5000 });
const id = (n) => new mongoose.Types.ObjectId(n.toString(16).padStart(24, '0'));
const userId = id(1);
const otherUserId = id(2);
const accountId = id(3);
const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];
const summarize = (values) => ({
    medianMs: percentile(values, 0.5),
    minMs: Math.min(...values),
    maxMs: Math.max(...values),
    samples: values.length,
});
const summarizeStages = (explain) => (explain.stages || []).map((stage) => ({
    stage: Object.keys(stage)[0],
    nReturned: stage.nReturned,
    totalDocsExamined: stage.totalDocsExamined ?? stage.$cursor?.executionStats?.totalDocsExamined,
    totalKeysExamined: stage.totalKeysExamined ?? stage.$cursor?.executionStats?.totalKeysExamined,
    executionTimeMillis: stage.$cursor?.executionStats?.executionTimeMillis,
    indexesUsed: stage.indexesUsed,
}));

const queries = [
    {}, { page: 2 }, { page: 100 }, { limit: 1 },
    { riskBucket: 'safe' }, { riskBucket: 'needs_review' },
    { riskBucket: 'quarantine' }, { riskBucket: 'unscanned' },
    { riskBucket: 'reviewed_safe' }, { riskBucket: 'confirmed_phishing' },
    { riskBucket: 'safe', page: 2 }, { riskBucket: 'safe', q: 'needle' },
    { q: 'no-such-message' }, { verdict: 'phishing' }, { verdict: 'safe' },
    { q: 'needle' },
    { from: '2020-01-01T00:00:00.000Z', to: '2030-01-01T00:00:00.000Z' },
];
const output = {
    baselineRevision: BASELINE_REVISION,
    implementationRevision: IMPLEMENTATION_REVISION,
    measuredRevision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
    environment: { node: process.version, platform: process.platform, arch: process.arch },
    database: { syntheticEmails: 600, writesDuringMeasurement: 0 },
    warmups: 4,
    samples: 16,
    queries: [],
};

try {
    const emails = Array.from({ length: 600 }, (_, index) => ({
        _id: id(1000 + index),
        userId,
        mailAccountId: accountId,
        provider: 'gmail',
        providerMessageId: `synthetic-${index}`,
        from: `Sender ${index % 6} <sender${index % 6}@example.test>`,
        to: ['recipient@example.test'],
        senderDomain: 'example.test',
        subject: index % 7 ? 'Synthetic message' : 'Synthetic needle message',
        snippet: 'Generated benchmark content',
        receivedAt: new Date(Date.UTC(2026, 0, 1) + index * 60000),
        inboxState: 'present',
        userVerdict: index % 10 === 3 ? 'safe' : index % 10 === 4 ? 'phishing' : null,
    }));
    const scans = emails.filter((_, index) => index % 10 !== 5).map((email, index) => ({
        _id: id(10000 + index),
        userId,
        emailId: email._id,
        score: [10, 40, 70][index % 3],
        ruleScore: [10, 40, 70][index % 3],
        aiScore: 0,
        verdict: ['safe', 'suspicious', 'likely_phishing'][index % 3],
        scannedAt: new Date('2026-02-01T00:00:00.000Z'),
        createdAt: new Date('2026-02-01T00:00:00.000Z'),
    }));
    await Email.collection.insertMany([
        ...emails,
        { ...emails[0], _id: id(90000), userId: otherUserId, providerMessageId: 'other-user' },
    ]);
    await Scan.collection.insertMany(scans);
    await Email.collection.createIndex({ userId: 1, receivedAt: -1 });
    await Scan.collection.createIndex({ emailId: 1, createdAt: -1 });

    for (const query of queries) {
        assert.deepEqual(
            await current.getEmailsForUser({ userId, query }),
            await baseline.getEmailsForUser({ userId, query })
        );
    }
    output.equivalenceCases = queries.length;

    for (const email of emails.slice(0, 3)) {
        assert.deepEqual(
            await current.getEmailByIdForUser({ userId, emailId: email._id }),
            await baseline.getEmailByIdForUser({ userId, emailId: email._id })
        );
    }
    output.detailEquivalenceCases = 3;
    assert.equal((await current.getEmailsForUser({ userId: otherUserId, query: { page: 2 } })).items.length, 0);
    assert.equal((await current.getEmailsForUser({ userId: id(999), query: {} })).items.length, 0);
    output.ownershipIsolationCases = 2;

    for (const query of [{}, { page: 2 }, { riskBucket: 'safe' }, { q: 'needle' }]) {
        const timings = { before: [], after: [] };
        for (let sample = 0; sample < 20; sample++) {
            const order = sample % 2
                ? [['after', current], ['before', baseline]]
                : [['before', baseline], ['after', current]];
            for (const [name, service] of order) {
                const startedAt = performance.now();
                await service.getEmailsForUser({ userId, query });
                if (sample >= 4) timings[name].push(performance.now() - startedAt);
            }
        }
        output.queries.push({ query, before: summarize(timings.before), after: summarize(timings.after) });
    }

    output.explain = {};
    for (const [name, service] of [['before', baseline], ['after', current]]) {
        const pipelines = [];
        const originalAggregate = Email.aggregate;
        try {
            Email.aggregate = async (pipeline) => { pipelines.push(pipeline); return []; };
            await service.getEmailsForUser({ userId, query: {} });
        } finally {
            Email.aggregate = originalAggregate;
        }
        output.explain[name] = [];
        for (const pipeline of pipelines) {
            output.explain[name].push(summarizeStages(
                await Email.collection.aggregate(pipeline).explain('executionStats')
            ));
        }
    }

    const senderFilter = { userId, from: emails[0].from, _id: { $ne: emails[0]._id } };
    const senderTimes = { before: [], after: [] };
    for (let sample = 0; sample < 20; sample++) {
        for (const name of sample % 2 ? ['after', 'before'] : ['before', 'after']) {
            const startedAt = performance.now();
            await (name === 'before' ? Email.countDocuments(senderFilter) : Email.exists(senderFilter));
            if (sample >= 4) senderTimes[name].push(performance.now() - startedAt);
        }
    }
    output.senderExists = {
        matchingOtherEmails: await Email.countDocuments(senderFilter),
        before: summarize(senderTimes.before),
        after: summarize(senderTimes.after),
    };
    console.log(JSON.stringify(output, null, 2));
} finally {
    await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
}
