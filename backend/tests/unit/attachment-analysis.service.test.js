import assert from 'node:assert/strict';
import test from 'node:test';

import { createAttachmentAnalysisService } from '../../src/services/attachment/analysis.service.js';

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const dependencies = (overrides = {}) => ({
    typeAnalyzer: async ({ filename }) => ({
        detectedExtension: filename.endsWith('.zip') ? 'zip' : 'pdf',
        detectedMimeType: filename.endsWith('.zip') ? 'application/zip' : 'application/pdf',
        mismatch: 'none',
        hasRtlOverride: false,
        hasDangerousDoubleExtension: false,
    }),
    archiveAnalyzer: async () => ({
        status: 'analyzed',
        encryptedEntryCount: 0,
        nestedArchiveEntryCount: 0,
        highCompressionRatio: false,
    }),
    officeAnalyzer: async () => ({ status: 'analyzed', hasVbaProject: false }),
    pdfAnalyzer: () => ({ status: 'analyzed', hasOpenActionJavaScript: false }),
    ...overrides,
});

test('is opt-in and makes no fetch while disabled', async () => {
    let calls = 0;
    const service = createAttachmentAnalysisService({
        fetchAttachment: async () => { calls += 1; },
    });

    assert.deepEqual(await service.analyze({ attachments: [{}] }), {
        status: 'skipped',
        reason: 'disabled',
        evaluatedAt: null,
        items: [],
    });
    assert.equal(calls, 0);
});

test('records count, item-size, and total-size skips before fetching', async () => {
    const fetched = [];
    const service = createAttachmentAnalysisService({
        enabled: true,
        maxAttachments: 5,
        maxAttachmentBytes: 10,
        maxTotalBytes: 15,
        fetchAttachment: async ({ attachmentId, declaredSize }) => {
            fetched.push(attachmentId);
            return Buffer.alloc(declaredSize);
        },
        ...dependencies(),
    });
    const result = await service.analyze({
        attachments: [
            { filename: 'missing.pdf', size: 1 },
            { attachmentId: 'invalid', filename: 'invalid.pdf', size: -1 },
            { attachmentId: 'large', filename: 'large.pdf', size: 11 },
            { attachmentId: 'kept', filename: 'kept.pdf', size: 8 },
            { attachmentId: 'total', filename: 'total.pdf', size: 8 },
            { attachmentId: 'capped', filename: 'capped.pdf', size: 1 },
        ],
    });

    assert.equal(result.status, 'partial');
    assert.equal(result.reason, 'attachment_limit');
    assert.deepEqual(result.items.map(({ reason }) => reason), [
        'missing_attachment_id', 'invalid_size', 'too_large', null, 'total_size_limit',
    ]);
    assert.deepEqual(fetched, ['kept']);
});

test('maps structural and hash results to bounded finding keys without private data', async () => {
    const service = createAttachmentAnalysisService({
        enabled: true,
        fetchAttachment: async ({ declaredSize }) => Buffer.alloc(declaredSize),
        hashAnalyzer: async () => ({ status: 'ok', malicious: true, sha256: 'a'.repeat(64) }),
        ...dependencies({
            typeAnalyzer: async () => ({
                detectedExtension: 'zip',
                detectedMimeType: 'application/zip',
                mismatch: 'dangerous',
                hasRtlOverride: true,
                hasDangerousDoubleExtension: true,
            }),
            archiveAnalyzer: async () => ({
                encryptedEntryCount: 1,
                nestedArchiveEntryCount: 1,
                highCompressionRatio: true,
                dangerousEntryCount: 1,
                pathTraversalEntryCount: 1,
                entryNames: ['private.exe'],
            }),
            officeAnalyzer: async () => ({ hasVbaProject: true }),
        }),
    });
    const result = await service.analyze({
        messageId: 'private-message',
        mailAccount: { accessToken: 'private-token' },
        textBody: 'Password for the attached archive: 1234',
        attachments: [{
            attachmentId: 'private-attachment',
            filename: 'invoice.pdf.exe',
            declaredMimeType: 'application/pdf',
            size: 4,
        }],
    });

    assert.deepEqual(result.items[0].findings, [
        'attachment_known_malware_hash',
        'attachment_type_mismatch_dangerous',
        'attachment_double_extension',
        'attachment_rtl_override_filename',
        'attachment_encrypted_archive_with_password_in_body',
        'attachment_nested_archive',
        'attachment_zip_bomb_ratio',
        'attachment_dangerous_archive_entry',
        'attachment_archive_path_traversal',
        'attachment_macro_enabled_office',
    ]);
    assert.doesNotMatch(JSON.stringify(result), /private|1234|a{64}/u);
});

test('records external PDF actions and legacy Office only for unverified senders', async () => {
    const service = createAttachmentAnalysisService({
        enabled: true,
        fetchAttachment: async ({ declaredSize }) => Buffer.alloc(declaredSize),
        ...dependencies({
            typeAnalyzer: async ({ filename }) => ({
                detectedExtension: filename.endsWith('.doc') ? 'cfb' : 'pdf',
                detectedMimeType: filename.endsWith('.doc')
                    ? 'application/x-cfb'
                    : 'application/pdf',
                mismatch: 'none',
            }),
            pdfAnalyzer: () => ({ hasExternalUri: true }),
        }),
    });
    const input = {
        attachments: [
            { attachmentId: 'pdf', filename: 'notice.pdf', size: 1 },
            { attachmentId: 'doc', filename: 'legacy.doc', size: 1 },
        ],
        senderDomain: 'example.com',
    };

    const unverified = await service.analyze({ ...input, senderVerified: false });
    assert.deepEqual(unverified.items[0].findings, ['attachment_pdf_external_uri']);
    assert.deepEqual(unverified.items[1].findings, ['attachment_legacy_office_unverified']);

    const verified = await service.analyze({ ...input, senderVerified: true });
    assert.deepEqual(verified.items[1].findings, []);
});

test('isolates fetch failures and returns partial results at the wall-clock deadline', async () => {
    let sawAbort = false;
    const service = createAttachmentAnalysisService({
        enabled: true,
        concurrency: 1,
        timeoutMs: 20,
        fetchAttachment: async ({ attachmentId, declaredSize, signal }) => {
            if (attachmentId === 'ready') return Buffer.alloc(declaredSize);
            if (attachmentId === 'failed') throw new Error('fetch failed');
            return new Promise((resolve) => signal.addEventListener('abort', () => {
                sawAbort = true;
                resolve(Buffer.alloc(declaredSize));
            }, { once: true }));
        },
        ...dependencies(),
    });
    const result = await service.analyze({
        attachments: [
            { attachmentId: 'ready', filename: 'ready.pdf', size: 1 },
            { attachmentId: 'failed', filename: 'failed.pdf', size: 1 },
            { attachmentId: 'slow', filename: 'slow.pdf', size: 1 },
        ],
    });

    await delay(0);
    assert.equal(result.status, 'partial');
    assert.equal(result.reason, 'timed_out');
    assert.deepEqual(result.items.map(({ status }) => status), [
        'evaluated', 'unavailable', 'unavailable',
    ]);
    assert.deepEqual(result.items.map(({ reason }) => reason), [null, 'fetch_failed', 'timed_out']);
    assert.equal(sawAbort, true);
});

test('passes the deadline signal to an in-flight hash lookup', async () => {
    let hashSignal;
    let sawHashAbort = false;
    const service = createAttachmentAnalysisService({
        enabled: true,
        timeoutMs: 20,
        fetchAttachment: async ({ declaredSize }) => Buffer.alloc(declaredSize),
        hashAnalyzer: async (_buffer, { signal }) => new Promise((resolve) => {
            hashSignal = signal;
            signal.addEventListener('abort', () => {
                sawHashAbort = true;
                resolve({ status: 'unavailable' });
            }, { once: true });
        }),
        ...dependencies(),
    });

    const result = await service.analyze({
        attachments: [{ attachmentId: 'slow-hash', filename: 'invoice.pdf', size: 1 }],
    });

    assert.equal(result.status, 'partial');
    assert.equal(result.reason, 'timed_out');
    assert.equal(hashSignal?.aborted, true);
    assert.equal(sawHashAbort, true);
});
