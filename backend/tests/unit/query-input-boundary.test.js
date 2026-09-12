import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import app from '../../src/app.js';
import { JWT_SECRET } from '../../src/config/env.js';
import User from '../../src/models/user.model.js';
import SenderListEntry from '../../src/models/sender-list.model.js';

// Exercise the actual routing and Joi middleware before the flagged MongoDB queries.
test('auth and sender-list routes reject query operators before database lookup', async (t) => {
    const userId = '000000000000000000000001';
    t.mock.method(User, 'findById', async () => ({ _id: userId }));
    const userLookup = t.mock.method(User, 'findOne', () => ({ select: async () => null }));
    const listLookup = t.mock.method(SenderListEntry, 'findOne', async () => null);
    const server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    t.after(() => new Promise((resolve) => server.close(resolve)));
    const base = `http://127.0.0.1:${server.address().port}/api/v1`;
    const headers = { 'Content-Type': 'application/json',
        authorization: `Bearer ${jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' })}` };
    const requests = [];
    for (const input of [{ $ne: null }, { $regex: '.*' }, ['person@example.test'], 1]) {
        for (const route of ['/auth/login', '/auth/register']) {
            requests.push([route, { name: 'Synthetic user', email: input, password: 'Valid-password1!' }]);
        }
        for (const field of ['kind', 'value', 'listType']) {
            requests.push(['/sender-lists', { kind: 'sender', listType: 'allow', value: 'person@example.test', [field]: input }]);
        }
    }
    for (const [route, body] of requests) {
        const response = await fetch(`${base}${route}`, { method: 'POST', headers, body: JSON.stringify(body) });
        assert.equal(response.status, 400, route);
        assert.equal((await response.json()).code, 'VALIDATION_ERROR', route);
    }
    assert.equal(userLookup.mock.callCount(), 0);
    assert.equal(listLookup.mock.callCount(), 0);

    // A valid request reaches the query, proving the assertions are not caused by
    // an earlier auth/read-only rejection or a disconnected router.
    const response = await fetch(`${base}/auth/login`, { method: 'POST', headers,
        body: JSON.stringify({ email: 'person@example.test', password: 'Valid-password1!' }) });
    assert.equal(response.status, 401);
    assert.equal((await response.json()).code, 'INVALID_CREDENTIALS');
    assert.equal(userLookup.mock.callCount(), 1);
});
