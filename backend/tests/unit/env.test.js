import assert from 'node:assert/strict';
import test from 'node:test';

import {
    ATTACHMENT_ANALYSIS_CONCURRENCY,
    ATTACHMENT_ANALYSIS_ENABLED,
    ATTACHMENT_ANALYSIS_TIMEOUT_MS,
    ATTACHMENT_MAX_BYTES,
    ATTACHMENT_MAX_COUNT,
    ATTACHMENT_MAX_TOTAL_BYTES,
    MALWAREBAZAAR_AUTH_KEY,
    THREAT_INTEL_ENABLED,
    THREAT_INTEL_MAX_URLS_PER_EMAIL,
    THREAT_INTEL_TIMEOUT_MS,
    URLHAUS_AUTH_KEY,
    WEB_RISK_API_KEY,
    isAttachmentAnalysisEnabled,
    isThreatIntelEnabled,
    isTruthyEnvValue,
} from '../../src/config/env.js';

test('isTruthyEnvValue accepts only explicit truthy values', () => {
    for (const value of ['true', 'TRUE', '1', 'yes', 'on', ' on ']) {
        assert.equal(isTruthyEnvValue(value), true);
    }

    for (const value of [undefined, null, '', 'false', '0', 'off', 'random']) {
        assert.equal(isTruthyEnvValue(value), false);
    }
});

test('threat intelligence is disabled by default and its source keys stay optional', () => {
    assert.equal(THREAT_INTEL_ENABLED, 'false');
    assert.equal(isThreatIntelEnabled(), false);
    assert.equal(WEB_RISK_API_KEY, '');
    assert.equal(URLHAUS_AUTH_KEY, '');
    assert.equal(THREAT_INTEL_MAX_URLS_PER_EMAIL, '5');
    assert.equal(THREAT_INTEL_TIMEOUT_MS, '10000');
});

test('attachment analysis is opt-in with bounded defaults and an optional reputation key', () => {
    assert.equal(ATTACHMENT_ANALYSIS_ENABLED, 'false');
    assert.equal(isAttachmentAnalysisEnabled(), false);
    assert.equal(ATTACHMENT_MAX_BYTES, '10485760');
    assert.equal(ATTACHMENT_MAX_TOTAL_BYTES, '26214400');
    assert.equal(ATTACHMENT_MAX_COUNT, '10');
    assert.equal(ATTACHMENT_ANALYSIS_CONCURRENCY, '3');
    assert.equal(ATTACHMENT_ANALYSIS_TIMEOUT_MS, '15000');
    assert.equal(MALWAREBAZAAR_AUTH_KEY, '');
});
