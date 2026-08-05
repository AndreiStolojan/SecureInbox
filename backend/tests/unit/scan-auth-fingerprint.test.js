import assert from 'node:assert/strict';
import test from 'node:test';

import {
    CURRENT_ATTACHMENT_CONFIG_FINGERPRINT,
    CURRENT_SCAN_ENGINE_VERSION,
    CURRENT_THREAT_INTEL_CONFIG_FINGERPRINT,
    buildAuthResultsFingerprint,
    buildAttachmentConfigFingerprint,
    buildAttachmentAnalysisFingerprint,
    buildThreatIntelConfigFingerprint,
    isCurrentScanValidForCurrentAiSetting,
} from '../../src/services/scan.service.js';

const passedAuth = {
    status: 'ok',
    spf: { result: 'pass', domain: 'mail.example.com' },
    dkim: { result: 'none', signatures: [] },
    dmarc: { result: 'pass', policy: 'reject', alignment: 'relaxed' },
    arc: { result: 'none', chainLength: 0 },
};

test('auth fingerprints ignore timestamps but change with scoring evidence', () => {
    const first = buildAuthResultsFingerprint({
        ...passedAuth,
        evaluatedAt: new Date('2026-07-31T10:00:00Z'),
    });
    const sameEvidence = buildAuthResultsFingerprint({
        ...passedAuth,
        evaluatedAt: new Date('2026-07-31T11:00:00Z'),
    });
    const unavailable = buildAuthResultsFingerprint({
        ...passedAuth,
        status: 'unavailable',
    });

    assert.equal(first, sameEvidence);
    assert.notEqual(first, unavailable);
});

test('a current scan is stale whenever the persisted authentication outcome changes', () => {
    const oldFingerprint = buildAuthResultsFingerprint({ status: 'unavailable' });
    const newFingerprint = buildAuthResultsFingerprint(passedAuth);
    const currentScan = {
        engineVersion: CURRENT_SCAN_ENGINE_VERSION,
        authResultsFingerprint: oldFingerprint,
        threatIntelConfigFingerprint: CURRENT_THREAT_INTEL_CONFIG_FINGERPRINT,
        attachmentConfigFingerprint: CURRENT_ATTACHMENT_CONFIG_FINGERPRINT,
    };

    assert.equal(
        isCurrentScanValidForCurrentAiSetting({
            currentScan,
            aiEnabled: false,
            authResultsFingerprint: oldFingerprint,
        }),
        true
    );
    assert.equal(
        isCurrentScanValidForCurrentAiSetting({
            currentScan,
            aiEnabled: false,
            authResultsFingerprint: newFingerprint,
        }),
        false
    );
});

test('enabling or configuring threat intelligence makes an earlier scan stale', () => {
    const disabled = buildThreatIntelConfigFingerprint({
        enabled: false,
        webRiskConfigured: false,
        urlhausConfigured: false,
        maxUrls: 5,
    });
    const enabled = buildThreatIntelConfigFingerprint({
        enabled: true,
        webRiskConfigured: true,
        urlhausConfigured: false,
        maxUrls: 5,
    });
    const authResultsFingerprint = buildAuthResultsFingerprint(passedAuth);
    const currentScan = {
        engineVersion: CURRENT_SCAN_ENGINE_VERSION,
        authResultsFingerprint,
        threatIntelConfigFingerprint: disabled,
        attachmentConfigFingerprint: CURRENT_ATTACHMENT_CONFIG_FINGERPRINT,
    };

    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        threatIntelConfigFingerprint: disabled,
    }), true);
    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        threatIntelConfigFingerprint: enabled,
    }), false);
    assert.doesNotMatch(enabled, /true|false|web|urlhaus/i);
});

test('changing the threat intelligence deadline invalidates a scan', () => {
    const baseConfig = {
        enabled: true,
        webRiskConfigured: true,
        urlhausConfigured: true,
        maxUrls: 5,
    };

    const tenSecondBudget = buildThreatIntelConfigFingerprint({
        ...baseConfig,
        timeoutMs: 10_000,
    });
    const fiveSecondBudget = buildThreatIntelConfigFingerprint({
        ...baseConfig,
        timeoutMs: 5_000,
    });

    assert.notEqual(tenSecondBudget, fiveSecondBudget);
});

test('enabling attachment analysis invalidates an extension-only scan', () => {
    const disabled = buildAttachmentConfigFingerprint({ enabled: false });
    const enabled = buildAttachmentConfigFingerprint({
        enabled: true,
        reputationConfigured: true,
        maxBytes: 10_485_760,
        maxTotalBytes: 26_214_400,
        maxCount: 10,
        timeoutMs: 15_000,
    });

    assert.notEqual(disabled, enabled);
    assert.doesNotMatch(enabled, /true|false|malware/i);
});

test('attachment analysis fingerprints ignore timestamps and non-scoring metadata', () => {
    const first = buildAttachmentAnalysisFingerprint({
        status: 'evaluated',
        evaluatedAt: new Date('2026-08-01T09:00:00Z'),
        reason: 'completed',
        items: [{
            attachmentIndex: 0,
            detectedMimeType: 'application/pdf',
            detectedExtension: 'pdf',
            findings: ['attachment_pdf_openaction_javascript'],
        }],
    });
    const sameSignals = buildAttachmentAnalysisFingerprint({
        status: 'partial',
        evaluatedAt: new Date('2026-08-02T09:00:00Z'),
        reason: 'one attachment unavailable',
        items: [{
            attachmentIndex: 7,
            detectedMimeType: 'application/octet-stream',
            detectedExtension: 'bin',
            findings: ['attachment_pdf_openaction_javascript'],
        }],
    });

    assert.equal(first, sameSignals);
});

test('a changed attachment finding makes the current scan stale', () => {
    const authResultsFingerprint = buildAuthResultsFingerprint(passedAuth);
    const unavailableFingerprint = buildAttachmentAnalysisFingerprint({
        status: 'unavailable',
        items: [],
    });
    const maliciousFingerprint = buildAttachmentAnalysisFingerprint({
        status: 'evaluated',
        items: [{
            findings: ['attachment_known_malware_hash'],
        }],
    });
    const currentScan = {
        engineVersion: CURRENT_SCAN_ENGINE_VERSION,
        authResultsFingerprint,
        threatIntelConfigFingerprint: CURRENT_THREAT_INTEL_CONFIG_FINGERPRINT,
        attachmentConfigFingerprint: CURRENT_ATTACHMENT_CONFIG_FINGERPRINT,
        attachmentAnalysisFingerprint: unavailableFingerprint,
    };

    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        attachmentAnalysisEnabled: true,
        attachmentAnalysisFingerprint: unavailableFingerprint,
    }), true);
    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        attachmentAnalysisEnabled: true,
        attachmentAnalysisFingerprint: maliciousFingerprint,
    }), false);
});

test('disabled attachment analysis ignores persisted attachment result changes', () => {
    const authResultsFingerprint = buildAuthResultsFingerprint(passedAuth);
    const currentScan = {
        engineVersion: CURRENT_SCAN_ENGINE_VERSION,
        authResultsFingerprint,
        threatIntelConfigFingerprint: CURRENT_THREAT_INTEL_CONFIG_FINGERPRINT,
        attachmentConfigFingerprint: CURRENT_ATTACHMENT_CONFIG_FINGERPRINT,
        attachmentAnalysisFingerprint: buildAttachmentAnalysisFingerprint({
            status: 'unavailable',
        }),
    };

    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        attachmentAnalysisEnabled: false,
        attachmentAnalysisFingerprint: buildAttachmentAnalysisFingerprint({
            status: 'evaluated',
            items: [{ findings: ['attachment_known_malware_hash'] }],
        }),
    }), true);
});

test('an enabled threat intelligence outage is retried on a later sync', () => {
    const authResultsFingerprint = buildAuthResultsFingerprint(passedAuth);
    const currentScan = {
        engineVersion: CURRENT_SCAN_ENGINE_VERSION,
        authResultsFingerprint,
        threatIntelConfigFingerprint: CURRENT_THREAT_INTEL_CONFIG_FINGERPRINT,
        attachmentConfigFingerprint: CURRENT_ATTACHMENT_CONFIG_FINGERPRINT,
        providerMeta: [{
            provider: 'threat-intelligence',
            status: 'skipped',
            meta: {
                sourceStatuses: {
                    web_risk: 'unavailable',
                    urlhaus: 'unavailable',
                    rdap: 'unavailable',
                    redirect: 'skipped',
                },
            },
        }],
    };

    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        threatIntelEnabled: false,
    }), true);
    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        threatIntelEnabled: true,
    }), false);

    currentScan.providerMeta[0].status = 'success';
    assert.equal(isCurrentScanValidForCurrentAiSetting({
        currentScan,
        aiEnabled: false,
        authResultsFingerprint,
        threatIntelEnabled: true,
    }), true);
});
