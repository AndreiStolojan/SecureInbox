// Exercise the real API or scan service against a disposable, synthetic database.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { execFileSync, fork } from 'node:child_process';
import { once } from 'node:events';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';

const [mode, mongoAddress, aiAddress = 'http://127.0.0.1:11435', model = 'qwen2.5:1.5b'] = process.argv.slice(2);
assert(['api', 'rules', 'ai'].includes(mode), 'Usage: benchmark-pi-profile.js api|rules|ai mongodb://127.0.0.1:PORT/ [OLLAMA_URL MODEL]');
const mongo = new URL(mongoAddress);
assert(mongo.protocol === 'mongodb:' && mongo.hostname === '127.0.0.1'
    && !mongo.username && !mongo.password && mongo.pathname === '/' && !mongo.search && !mongo.hash,
'Use a credential-free, loopback MongoDB URL with no database or options.');
const ollama = new URL(aiAddress);
assert(ollama.protocol === 'http:' && ollama.hostname === '127.0.0.1'
    && !ollama.username && !ollama.password && ollama.pathname === '/' && !ollama.search && !ollama.hash,
'Ollama must use a credential-free loopback HTTP URL.');
const database = `pi_profile_${randomBytes(8).toString('hex')}_test`;
const secret = randomBytes(32).toString('hex');
Object.assign(process.env, {
    NODE_ENV: 'test', PORT: '0', DB_URI: `${mongo.href}${database}`,
    JWT_SECRET: secret, JWT_EXPIRES_IN: '1h', MAIL_TOKEN_ENCRYPTION_KEY: secret,
    APP_READ_ONLY: 'false', GMAIL_PUSH_ENABLED: 'false', ARCJET_KEY: '',
    AI_SEMANTIC_ENABLED: String(mode === 'ai'), OLLAMA_BASE_URL: ollama.origin,
    OLLAMA_MODEL: model, OLLAMA_TIMEOUT_MS: '60000', SCAN_CONCURRENCY: '1',
    THREAT_INTEL_ENABLED: 'false', ATTACHMENT_ANALYSIS_ENABLED: 'false',
    GOOGLE_CLIENT_ID: '', GOOGLE_CLIENT_SECRET: '', EMAIL_FROM: '', EMAIL_PASSWORD: '',
});

const User = (await import('../src/models/user.model.js')).default;
const Email = (await import('../src/models/email.model.js')).default;
const { scanEmailWithRules } = await import('../src/services/scan.service.js');
const app = (await import('../src/app.js')).default;
const percentile = (values, p) => [...values].sort((a, b) => a - b)[Math.ceil(values.length * p) - 1];
const summarize = (values) => ({ medianMs: percentile(values, 0.5), p95Ms: percentile(values, 0.95), samplesMs: values });
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
let server;
let sampler;
let samplerExit;
let hostOutput = '';
let report;
let samplerCode;

try {
    await mongoose.connect(process.env.DB_URI);
    const user = await User.create({ name: 'Synthetic benchmark', email: 'profile@example.test',
        passwordHash: 'no-login', settings: { aiEnabled: mode === 'ai', alertsEnabled: false, digestEnabled: false } });
    const accountId = new mongoose.Types.ObjectId();
    const emails = await Email.insertMany(Array.from({ length: 600 }, (_, index) => ({
        userId: user._id, mailAccountId: accountId, providerMessageId: `synthetic-${index}`,
        subject: 'Urgent: verify your account', from: 'support@example.test', senderDomain: 'example.test',
        textBody: 'Your account will be suspended. Reply with your password and verification code to keep access.',
        receivedAt: new Date(Date.UTC(2026, 8, 1) + index * 60000),
        links: [], attachments: [],
    })));
    await Promise.all([User.init(), Email.init()]);
    const samplerReady = new Promise((resolve, reject) => {
        sampler = fork(new URL('../../scripts/measure-pi-host.mjs', import.meta.url), [mode, '600'],
            { stdio: ['ignore', 'pipe', 'inherit', 'ipc'] });
        sampler.once('message', resolve);
        sampler.once('error', reject);
        sampler.once('exit', (code) => reject(new Error(`Host sampler exited before readiness: ${code}`)));
    });
    sampler.stdout.setEncoding('utf8');
    sampler.stdout.on('data', (chunk) => { hostOutput += chunk; });
    samplerExit = once(sampler, 'exit');
    await samplerReady;
    const startedAt = new Date().toISOString();
    const started = performance.now();
    report = { mode, startedAt, sourceRevision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
        node: process.version, arch: process.arch, emails: emails.length, concurrency: 1,
        ai: mode === 'ai' ? { model, timeoutMsPerCall: 60000 } : false };
    if (mode === 'api') {
        server = app.listen(0, '127.0.0.1');
        await once(server, 'listening');
        const base = `http://127.0.0.1:${server.address().port}/api/v1/`;
        const token = jwt.sign({ userId: user._id }, secret, { expiresIn: '1h' });
        const routes = ['emails', 'emails/stats', 'emails/trend', 'emails/top-risky-senders', `emails/${emails[0]._id}`];
        const timings = routes.map(() => []);
        for (let round = -3; round < 30; round += 1) {
            for (const [index, route] of routes.entries()) {
                const start = performance.now();
                const response = await fetch(`${base}${route}`, {
                    headers: { authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10000),
                });
                const body = await response.json();
                assert.equal(response.status, 200, `API route ${index} failed`);
                assert.equal(body.success, true);
                if (round >= 0) timings[index].push(performance.now() - start);
            }
            await sleep(500);
        }
        report.warmupRounds = 3;
        report.rounds = 30;
        report.pauseBetweenRoundsMs = 500;
        report.requests = 165;
        report.routes = routes.map((route, index) => ({ route: index === 4 ? 'emails/:id' : route, ...summarize(timings[index]) }));
    } else {
        const samples = [];
        const repetitions = mode === 'ai' ? 5 : 300;
        for (let index = -2; index < repetitions; index += 1) {
            const start = performance.now();
            const { scan, status } = await scanEmailWithRules({ userId: user._id, emailId: emails[0]._id, scanSource: 'manual' });
            assert.equal(status, 'scanned');
            const result = { durationMs: performance.now() - start, verdict: scan.verdict,
                aiStatus: scan.aiSignals?.status, explanationStatus: scan.aiExplanationMeta?.status,
                fallbackReason: scan.aiExplanationMeta?.fallbackReason ?? null };
            if (index === -2) report.coldScan = result;
            if (index === -1) report.warmupScan = result;
            if (index >= 0) samples.push(result);
            if (mode === 'ai' || index % 50 === 0) {
                process.stderr.write(`${mode} scan ${index + 3}/${repetitions + 2}: ${Math.round(result.durationMs)} ms\n`);
            }
        }
        report.scans = { ...summarize(samples.map((sample) => sample.durationMs)), results: samples };
        report.scansPerSecond = samples.length / (samples.reduce((total, sample) => total + sample.durationMs, 0) / 1000);
    }
    report.elapsedMs = performance.now() - started;
    report.processPeakRssBytes = process.resourceUsage().maxRSS * 1024;
    report.failures = 0;
} finally {
    if (sampler && sampler.exitCode === null) sampler.kill('SIGTERM');
    if (samplerExit) {
        const [code] = await samplerExit;
        samplerCode = code;
    }
    if (server) await new Promise((resolve) => server.close(resolve));
    if (mongoose.connection.readyState === 1) await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
}
assert.equal(samplerCode, 0, 'Host sampler failed');
report.databaseDropped = true;
report.host = JSON.parse(hostOutput);
console.log(JSON.stringify(report, null, 2));
