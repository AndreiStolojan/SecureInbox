import assert from 'node:assert/strict';
import test from 'node:test';
import { summarizeSemanticResults } from '../../scripts/eval-semantic.js';

const evaluated = (id, label, accused = false) => ({
    id, label, status: 'evaluated', aiScore: accused ? 20 : 0, latencyMs: 100,
    spuriousSignals: accused ? ['sensitive_data_request'] : [],
    crossesSuspicious: false, mismatches: [], parserFallback: false,
});

test('semantic rates distinguish a missing class from an observed zero rate', () => {
    const report = summarizeSemanticResults([evaluated('benign', 'benign')], 'synthetic');
    assert.equal(report.falsePositiveRate, 0);
    assert.equal(report.detectionRate, null);
    assert.equal(report.meanMaliciousAiScore, null);
    assert.deepEqual(report.selectedClassCounts, { benign: 1, malicious: 0 });
    assert.equal(report.coveragePercent, 100);
    assert.equal(report.complete, true);
});

test('failed providers remain in coverage and cannot make a partial result complete', () => {
    const report = summarizeSemanticResults([
        evaluated('benign', 'benign'),
        evaluated('caught', 'malicious', true),
        { id: 'unavailable', label: 'malicious', status: 'failed', latencyMs: 5000 },
    ], 'synthetic');
    assert.equal(report.detectionRate, 100);
    assert.equal(report.coveragePercent, 66.7);
    assert.equal(report.complete, false);
    assert.equal(report.failed, 1);
    assert.deepEqual(report.selectedClassCounts, { benign: 1, malicious: 2 });
    assert.deepEqual(report.evaluatedClassCounts, { benign: 1, malicious: 1 });
});

test('semantic rates use explicit class denominators', () => {
    const report = summarizeSemanticResults([
        evaluated('b1', 'benign', true), evaluated('b2', 'benign'),
        evaluated('m1', 'malicious', true), evaluated('m2', 'malicious'), evaluated('m3', 'malicious'),
    ], 'synthetic');
    assert.equal(report.falsePositiveRate, 50);
    assert.equal(report.detectionRate, 33.3);
    assert.equal(report.overThresholdRate, 0);
    assert.equal(report.meanBenignAiScore, 10);
    assert.equal(report.falsePositives.length, 1);
    assert.equal(report.missed.length, 2);
});

test('empty and fully unavailable evaluations do not invent performance or accuracy', () => {
    for (const results of [[], [{ id: 'failed', label: 'malicious', status: 'failed' }]]) {
        const report = summarizeSemanticResults(results, 'synthetic');
        assert.equal(report.complete, false);
        assert.equal(report.falsePositiveRate, null);
        assert.equal(report.detectionRate, null);
        assert.equal(report.signalAccuracy, null);
        assert.equal(report.medianLatencyMs, null);
    }
});
