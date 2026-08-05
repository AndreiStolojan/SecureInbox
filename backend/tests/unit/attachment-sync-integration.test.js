import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzeGmailAttachmentsForPayload } from '../../src/services/mail-account.service.js';

const input = {
    mailAccount: { userId: 'user-id' },
    messageId: 'message-id',
    emailPayload: {
        providerMessageId: 'message-id',
        attachments: [{ attachmentId: 'attachment-id', filename: 'invoice.pdf', size: 4 }],
        textBody: '',
        htmlBody: '',
    },
};

test('disabled attachment analysis performs no lookup or download', async () => {
    let calls = 0;
    const result = await analyzeGmailAttachmentsForPayload({
        ...input,
        enabled: false,
        emailModel: { exists: async () => { calls += 1; } },
        analyzer: { analyze: async () => { calls += 1; } },
    });

    assert.equal(result, null);
    assert.equal(calls, 0);
});

test('manually reviewed email skips attachment analysis', async () => {
    let analysisCalls = 0;
    const result = await analyzeGmailAttachmentsForPayload({
        ...input,
        enabled: true,
        emailModel: { exists: async () => ({ _id: 'reviewed' }) },
        analyzer: { analyze: async () => { analysisCalls += 1; } },
    });

    assert.equal(result, null);
    assert.equal(analysisCalls, 0);
});

test('unreviewed email is analyzed and failures remain fail-open', async () => {
    let received;
    const success = await analyzeGmailAttachmentsForPayload({
        ...input,
        enabled: true,
        emailModel: { exists: async () => null },
        analyzer: { analyze: async (value) => {
            received = value;
            return { status: 'evaluated', reason: null, evaluatedAt: new Date(), items: [] };
        } },
    });

    assert.equal(success.status, 'evaluated');
    assert.deepEqual(received.attachments, input.emailPayload.attachments);

    const unavailable = await analyzeGmailAttachmentsForPayload({
        ...input,
        enabled: true,
        emailModel: { exists: async () => null },
        analyzer: { analyze: async () => { throw new Error('isolated'); } },
    });
    assert.equal(unavailable.status, 'unavailable');
    assert.equal(unavailable.reason, 'analysis_failed');
});
