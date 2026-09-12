import assert from 'node:assert/strict';
import test from 'node:test';
import { assertDevelopmentSeed } from '../../scripts/seed-guard.js';

test('demo seed refuses production and requires a development database and opt-in', () => {
    const env = { NODE_ENV: 'development', SEED_DEMO: 'true', DB_URI: 'mongodb://localhost/secureinbox_dev' };
    assert.doesNotThrow(() => assertDevelopmentSeed(env));
    assert.doesNotThrow(() => assertDevelopmentSeed({ ...env, DB_URI: 'mongodb+srv://example.test/secureinbox_test' }));
    assert.doesNotThrow(() => assertDevelopmentSeed({ ...env, DB_URI: 'mongodb://localhost/secureinbox-dev' }));
    for (const change of [
        { APP_READ_ONLY: 'true' },
        { NODE_ENV: 'production' },
        { SEED_DEMO: 'false' },
        { DB_URI: 'mongodb+srv://example.test/secureinbox' },
        { DB_URI: 'mongodb+srv://example.test/secureinbox_dev_prod' },
        { DB_URI: 'mongodb+srv://example.test/test_archive' },
    ]) {
        assert.throws(() => assertDevelopmentSeed({ ...env, ...change }), /Demo seed requires/);
    }
});
