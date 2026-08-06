import test from 'node:test';
import assert from 'node:assert/strict';

import { buildAiAnalysisInput } from '../../src/services/scan-ai-input.service.js';

// The body handed to the semantic model decides everything downstream: a model
// that never sees the message text cannot classify it, and its guesses land in
// the score anyway. These tests lock the cleaning behaviour.

// A brand email's <style> block routinely runs to several thousand characters —
// far past MAX_AI_BODY_CHARS. Stripping only the tags, not the element content,
// left the model reading CSS while the real message was truncated away.
const styleBlock = Array.from(
    { length: 60 },
    (_, index) => `.col-${index}{padding:${index}px;font-family:Helvetica,Arial;color:#4285f4}`
).join('\n');

test('non-text elements are removed with their content, not just their tags', () => {
    const { body } = buildAiAnalysisInput({
        subject: 'Security alert',
        from: 'no-reply@accounts.google.com',
        htmlBody: `<html><head><style type="text/css">${styleBlock}</style></head>`
            + '<body><p>A new sign-in on Windows.</p>'
            + '<script>window.track=1;var noise="filler";</script></body></html>',
    });

    assert.ok(styleBlock.length > 2000, 'fixture must exceed a realistic body budget');
    assert.equal(body, 'A new sign-in on Windows.');
});

test('an unterminated style or script consumes the rest of the document', () => {
    // Browsers treat everything after an unclosed <style> as being inside it.
    // Matching that keeps a single malformed tag from reintroducing the CSS.
    for (const htmlBody of [
        '<style>.a{color:red;font-family:Arial}<p>Trailing text',
        '<script>var a=1;alert(2)<p>Trailing text',
    ]) {
        const { body } = buildAiAnalysisInput({ htmlBody, snippet: 'Booking confirmed' });
        assert.equal(body, 'Booking confirmed', `leaked from: ${htmlBody}`);
    }
});

test('block boundaries keep adjacent sentences from fusing', () => {
    const { body } = buildAiAnalysisInput({
        htmlBody: '<p>Hi Andrei</p><p>Your invoice is ready</p>',
    });

    assert.equal(body, 'Hi Andrei Your invoice is ready');
});

test('common HTML entities are decoded for the model', () => {
    const { body } = buildAiAnalysisInput({
        htmlBody: '<p>You don&#39;t need to act &amp; nothing&nbsp;changed</p>',
    });

    assert.equal(body, "You don't need to act & nothing changed");
});

test('a plain-text body is preferred over the HTML alternative', () => {
    const { body } = buildAiAnalysisInput({
        textBody: 'Plain text wins',
        htmlBody: '<p>HTML alternative</p>',
    });

    assert.equal(body, 'Plain text wins');
});

test('truncation falls back to the last word boundary', () => {
    const longBody = `${'word '.repeat(1200)}FINALWORDTHATISCUT`;
    const { body, metadata } = buildAiAnalysisInput({ textBody: longBody });

    assert.equal(metadata.bodyTruncated, true);
    assert.ok(body.length <= 4000, 'must respect MAX_AI_BODY_CHARS');
    assert.doesNotMatch(body, /\s$/, 'trailing whitespace should be cut with the word');
    assert.ok(!body.endsWith('wor'), 'must not cut mid-word');
});
