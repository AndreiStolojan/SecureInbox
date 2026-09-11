import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { once } from 'node:events';
import mongoose from 'mongoose';
import cron from 'node-cron';

process.env.APP_READ_ONLY = 'true';
const [{ default: app }, { startSchedulers }, { default: connectToDatabase }] = await Promise.all([
    import('../../src/app.js'), import('../../src/services/scheduler.service.js'),
    import('../../src/database/mongodb.js'),
]);

test('read-only mode denies mutations, OAuth GETs and unknown routes before handlers', async (t) => {
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const base = `http://127.0.0.1:${server.address().port}`;
    for (const [method, path] of [
        ['POST', '/auth/register'], ['PATCH', '/users/me'], ['DELETE', '/mail-accounts/123'],
        ['POST', '/mail-accounts/123/sync'], ['POST', '/scans/emails/123'],
        ['POST', '/contact/message'], ['POST', '/reports/monthly-summary/send'],
        ['POST', '/webhooks/gmail'], ['GET', '/mail-accounts/google/start'],
        ['GET', '/mail-accounts/google/callback?code=synthetic'], ['GET', '/future-route'],
    ]) {
        const response = await fetch(`${base}/api/v1${path}`, { method });
        assert.equal(response.status, 403, `${method} ${path}`);
        assert.equal((await response.json()).code, 'READ_ONLY_MODE');
    }
    assert.equal((await fetch(`${base}/api/v1/health`)).status, 200);
    assert.equal((await fetch(`${base}/api/v1/emails`)).status, 401);
    // Invalid login reaches local input validation, not the read-only rejection.
    assert.equal((await fetch(`${base}/api/v1/auth/login`, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 400);
});

test('read-only startup creates no scheduled tasks or automatic database indexes', async (t) => {
    const schedule = t.mock.method(cron, 'schedule', () => { throw new Error('scheduled side effect'); });
    startSchedulers().stop();
    assert.equal(schedule.mock.callCount(), 0);
    t.mock.method(mongoose, 'connect', async (_uri, options) => {
        assert.deepEqual(options, { autoIndex: false, autoCreate: false });
    });
    await connectToDatabase();
});

test('read-only mode rejects ambiguous flags and production startup', () => {
    for (const env of [ { APP_READ_ONLY: 'yes' }, { APP_READ_ONLY: 'true', NODE_ENV: 'production' } ]) {
        const child = spawnSync(process.execPath, ['--input-type=module', '-e',
            "await import('./src/config/env.js')"], {
            cwd: new URL('../../', import.meta.url), encoding: 'utf8',
            env: { ...process.env, ENV_FILE: '/dev/null', ...env },
        });
        assert.notEqual(child.status, 0);
        assert.match(child.stderr, /APP_READ_ONLY/);
    }
});
