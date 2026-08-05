import assert from 'node:assert/strict';
import test from 'node:test';

import {
    analyze,
    collectAttachmentAnalysisSignals,
} from '../../src/detection/providers/attachment.provider.js';
import { RULE_WEIGHTS } from '../../src/detection/weights/index.js';

test('attachment analysis maps only bounded findings to point-free signals', () => {
    const analysis = {
        status: 'partial',
        items: [{
            attachmentIndex: 0,
            findings: [
                'attachment_known_malware_hash',
                'attachment_type_mismatch_dangerous',
                'attachment_type_mismatch_suspicious',
                'attachment_encrypted_archive_with_password_in_body',
                'attachment_encrypted_archive',
                'untrusted_finding',
            ],
            sha256: 'must-not-reach-provider-meta',
            attachmentId: 'must-not-reach-provider-meta',
        }],
    };

    const signals = collectAttachmentAnalysisSignals(analysis);
    assert.deepEqual(signals.map(({ key }) => key), [
        'attachment_known_malware_hash',
        'attachment_type_mismatch_dangerous',
        'attachment_encrypted_archive_with_password_in_body',
    ]);
    assert.ok(signals.every((entry) => !Object.hasOwn(entry, 'points')));
    assert.ok(signals.every((entry) => RULE_WEIGHTS[entry.key] < 60));
});

test('attachment analysis is optional and does not replace extension fallback evidence', async () => {
    const result = await analyze({
        attachmentAnalysisEnabled: true,
        email: { attachmentExtensions: ['exe'] },
    });

    assert.equal(result.status, 'skipped');
    assert.deepEqual(result.signals, []);
    assert.deepEqual(result.meta, { status: 'unavailable', itemCount: 0 });
});

test('disabled rollback ignores findings already persisted on the email', async () => {
    const result = await analyze({
        attachmentAnalysisEnabled: false,
        email: {
            attachmentAnalysis: {
                status: 'evaluated',
                items: [{ findings: ['attachment_known_malware_hash'] }],
            },
        },
    });

    assert.equal(result.status, 'skipped');
    assert.deepEqual(result.signals, []);
    assert.equal(result.meta.status, 'disabled');
});
