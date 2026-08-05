import assert from 'node:assert/strict';
import test from 'node:test';

import {
    createGmailAttachmentFetchService,
} from '../../src/services/attachment/fetch.service.js';

test('Gmail attachment fetch uses the injected OAuth-aware requester and returns bytes', async () => {
    const expected = Buffer.from('safe bytes');
    const controller = new AbortController();
    let requestInput;
    const service = createGmailAttachmentFetchService({
        request: async (input) => {
            requestInput = input;
            return {
                size: expected.length,
                data: expected.toString('base64url'),
            };
        },
    });

    const bytes = await service.fetchAttachment({
        mailAccount: { _id: 'mail-account' },
        messageId: 'message_123',
        attachmentId: 'attachment_456',
        declaredSize: expected.length,
        timeoutMs: 1_500,
        signal: controller.signal,
    });

    assert.deepEqual(bytes, expected);
    assert.match(requestInput.url, /messages\/message_123\/attachments\/attachment_456$/);
    assert.equal(requestInput.errorCode, 'GMAIL_ATTACHMENT_FETCH_FAILED');
    assert.equal(requestInput.timeoutMs, 1_500);
    assert.equal(requestInput.signal, controller.signal);
    assert.equal(requestInput.maxResponseBytes, 4_112);
});

test('Gmail attachment fetch rejects invalid metadata before making a request', async () => {
    let calls = 0;
    const service = createGmailAttachmentFetchService({
        request: async () => { calls += 1; },
        defaultMaxBytes: 4,
    });
    const input = {
        mailAccount: { _id: 'mail-account' },
        messageId: 'message',
        attachmentId: 'attachment',
        declaredSize: 4,
    };

    await assert.rejects(
        service.fetchAttachment({ ...input, messageId: 'message/invalid' }),
        { code: 'GMAIL_MESSAGE_ID_INVALID' }
    );
    await assert.rejects(
        service.fetchAttachment({ ...input, attachmentId: '' }),
        { code: 'GMAIL_ATTACHMENT_ID_INVALID' }
    );
    await assert.rejects(
        service.fetchAttachment({ ...input, declaredSize: 4.5 }),
        { code: 'GMAIL_ATTACHMENT_DECLARED_SIZE_INVALID' }
    );
    await assert.rejects(
        service.fetchAttachment({ ...input, declaredSize: 5 }),
        { code: 'GMAIL_ATTACHMENT_TOO_LARGE' }
    );
    assert.equal(calls, 0);
});

test('Gmail attachment fetch bounds encoded data and verifies response and decoded sizes', async () => {
    const responseFor = (payload) => createGmailAttachmentFetchService({
        request: async () => payload,
        defaultMaxBytes: 4,
    });
    const input = {
        mailAccount: { _id: 'mail-account' },
        messageId: 'message',
        attachmentId: 'attachment',
        declaredSize: 1,
    };

    await assert.rejects(
        responseFor({ size: 1, data: Buffer.alloc(4).toString('base64url') })
            .fetchAttachment(input),
        { code: 'GMAIL_ATTACHMENT_DATA_INVALID' }
    );
    await assert.rejects(
        responseFor({ size: 2, data: 'YQ' }).fetchAttachment(input),
        { code: 'GMAIL_ATTACHMENT_SIZE_MISMATCH' }
    );
    await assert.rejects(
        responseFor({ size: 1, data: '++' }).fetchAttachment(input),
        { code: 'GMAIL_ATTACHMENT_DATA_INVALID' }
    );
});
