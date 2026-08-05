import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzePdfActiveContent } from '../../src/services/attachment/pdf.service.js';

test('finds active PDF action markers with a bounded raw-byte scan', () => {
    const result = analyzePdfActiveContent(Buffer.from([
        '%PDF-1.7',
        '1 0 obj << /OpenAction 2 0 R /JavaScript /JS /AA',
        '/Launch /EmbeddedFile /URI (https://example.test) >>',
    ].join('\n')));

    assert.equal(result.status, 'analyzed');
    assert.equal(result.hasOpenActionJavaScript, true);
    assert.equal(result.hasAdditionalActions, true);
    assert.equal(result.hasEmbeddedFile, true);
    assert.equal(result.hasLaunch, true);
    assert.equal(result.hasUri, true);
});

test('does not scan past the configured in-memory PDF byte limit', () => {
    const buffer = Buffer.concat([
        Buffer.from('%PDF-1.7\n'),
        Buffer.alloc(32, 0x20),
        Buffer.from('/OpenAction /JavaScript'),
    ]);
    const result = analyzePdfActiveContent(buffer, { maxBytes: 16 });

    assert.equal(result.truncated, true);
    assert.equal(result.hasOpenActionJavaScript, false);
});

test('does not treat non-PDF bytes as an active document', () => {
    assert.deepEqual(analyzePdfActiveContent(Buffer.from('plain text')), {
        status: 'not_pdf',
        inspectedBytes: 0,
        truncated: false,
        hasAdditionalActions: false,
        hasEmbeddedFile: false,
        hasJavaScript: false,
        hasJs: false,
        hasLaunch: false,
        hasOpenAction: false,
        hasUri: false,
        hasOpenActionJavaScript: false,
        hasExternalUri: false,
    });
});

test('flags a PDF URI action only when it points outside the sender domain', () => {
    const external = analyzePdfActiveContent(
        Buffer.from('%PDF-1.7\n/URI (https://login.evil.test/path)'),
        { senderDomain: 'example.com' }
    );
    const aligned = analyzePdfActiveContent(
        Buffer.from('%PDF-1.7\n/URI (https://docs.example.com/path)'),
        { senderDomain: 'example.com' }
    );

    assert.equal(external.hasExternalUri, true);
    assert.equal(aligned.hasExternalUri, false);
});
