// ─────────────────────────────────────────────────────────────────────────────
// detection-contracts.test.js — contracte de context, schemă și observabilitate.
//
// Blochează forma internă nouă fără a extinde răspunsul public al scanării.
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createDetectionContext } from '../../src/detection/context.js';
import Scan from '../../src/models/scan.model.js';
import {
    metricsRegistry,
} from '../../src/monitoring/metrics.js';
import {
    DETECTION_PROVIDER_IDS,
    recordDetectionProviderOutcome,
} from '../../src/detection/registry.js';
import { CURRENT_SCAN_ENGINE_VERSION } from '../../src/services/scan.service.js';

test('detection context and its plain-object inputs are frozen snapshots', () => {
    const email = { senderDomain: 'example.test' };
    const senderListContext = { senderAllowlisted: true };
    const brandContext = { senderVerifiedBrand: false };
    const authResults = { status: 'ok', dmarc: { result: 'pass' } };
    const scanContext = { senderAllowlisted: true };
    const userSettings = { aiEnabled: true };
    const aiInput = { subject: 'Test' };
    const semanticAnalyzer = async () => ({ status: 'evaluated' });
    const threatIntelAnalyzer = async () => ({ status: 'evaluated' });
    const context = createDetectionContext({
        email,
        senderListContext,
        brandContext,
        authResults,
        scanContext,
        userSettings,
        aiInput,
        semanticAnalyzer,
        threatIntelAnalyzer,
    });

    assert.ok(Object.isFrozen(context));
    assert.ok(Object.isFrozen(context.senderListContext));
    assert.ok(Object.isFrozen(context.brandContext));
    assert.ok(Object.isFrozen(context.authResults));
    assert.ok(Object.isFrozen(context.authResults.dmarc));
    assert.ok(Object.isFrozen(context.scanContext));
    assert.ok(Object.isFrozen(context.userSettings));
    assert.ok(Object.isFrozen(context.aiInput));
    assert.equal(context.email, email);
    assert.equal(context.semanticAnalyzer, semanticAnalyzer);
    assert.equal(context.threatIntelAnalyzer, threatIntelAnalyzer);
    assert.throws(() => {
        context.userSettings.aiEnabled = false;
    }, TypeError);

    senderListContext.senderAllowlisted = false;
    aiInput.subject = 'Changed after construction';
    assert.equal(context.senderListContext.senderAllowlisted, true);
    assert.equal(context.aiInput.subject, 'Test');

    const nestedSource = {
        listMatch: { value: 'trusted.example' },
        tags: ['trusted'],
    };
    const nestedContext = createDetectionContext({
        email,
        scanContext: nestedSource,
        aiInput: { metadata: { linksIncludedCount: 1 } },
    });

    assert.ok(Object.isFrozen(nestedContext.scanContext.listMatch));
    assert.ok(Object.isFrozen(nestedContext.scanContext.tags));
    assert.ok(Object.isFrozen(nestedContext.aiInput.metadata));
    nestedSource.listMatch.value = 'mutated.example';
    nestedSource.tags.push('mutated');
    assert.equal(nestedContext.scanContext.listMatch.value, 'trusted.example');
    assert.deepEqual(nestedContext.scanContext.tags, ['trusted']);
});

test('Scan schema persists optional provider metadata and engine is v12', () => {
    const providerMeta = [
        {
            provider: 'link-analysis',
            version: 1,
            kind: 'rule',
            status: 'success',
        },
    ];
    const scan = new Scan({
        emailId: '507f1f77bcf86cd799439011',
        userId: '507f1f77bcf86cd799439012',
        score: 0,
        ruleScore: 0,
        aiScore: 0,
        verdict: 'safe',
        providerMeta,
    });

    assert.equal(Scan.schema.path('providerMeta').instance, 'Mixed');
    assert.deepEqual(scan.providerMeta, providerMeta);
    assert.deepEqual(new Scan().providerMeta, []);
    assert.equal(CURRENT_SCAN_ENGINE_VERSION, 'rules-ai-v12');
});

test('detection provider metrics accept only bounded provider and result labels', async () => {
    assert.deepEqual(DETECTION_PROVIDER_IDS, [
        'sender-list',
        'email-auth',
        'reply-to',
        'link-analysis',
        'threat-intelligence',
        'attachment-analysis',
        'attachment-extension',
        'ai-semantic',
    ]);

    recordDetectionProviderOutcome({
        provider: 'sender-list',
        result: 'success',
    });
    recordDetectionProviderOutcome({
        provider: 'ai-semantic',
        result: 'skipped',
    });

    assert.throws(
        () =>
            recordDetectionProviderOutcome({
                provider: 'attacker-controlled-provider',
                result: 'success',
            }),
        /Unknown detection provider metric label/
    );
    assert.throws(
        () =>
            recordDetectionProviderOutcome({
                provider: 'sender-list',
                result: 'attacker-controlled-result',
            }),
        /Unknown detection provider result metric label/
    );

    const output = await metricsRegistry.metrics();
    assert.match(
        output,
        /secureinbox_detection_provider_total\{provider="sender-list",result="success"\}/
    );
    assert.match(
        output,
        /secureinbox_detection_provider_total\{provider="ai-semantic",result="skipped"\}/
    );
    assert.doesNotMatch(output, /attacker-controlled/);
});

test('Grafana dashboard references the detection provider counter', async () => {
    const dashboard = await readFile(
        new URL(
            '../../../monitoring/grafana/dashboards/secureinbox-local.json',
            import.meta.url
        ),
        'utf8'
    );

    assert.match(dashboard, /secureinbox_detection_provider_total/);
});
