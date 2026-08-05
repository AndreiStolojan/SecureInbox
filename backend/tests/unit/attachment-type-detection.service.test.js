import assert from 'node:assert/strict';
import test from 'node:test';

import {
    analyzeAttachmentFilename,
    analyzeAttachmentType,
} from '../../src/services/attachment/type-detection.service.js';

test('classifies a harmless synthetic PE disguised as a document as dangerous', async () => {
    const result = await analyzeAttachmentType({
        buffer: Buffer.concat([Buffer.from('MZ'), Buffer.alloc(510)]),
        filename: 'invoice.docx',
        declaredMimeType:
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    });

    assert.equal(result.status, 'analyzed');
    assert.equal(result.detectedExtension, 'exe');
    assert.equal(result.mismatch, 'dangerous');
    assert.equal(Object.hasOwn(result, 'buffer'), false);
});

test('does not let an executable declared MIME hide a document filename mismatch', async () => {
    const result = await analyzeAttachmentType({
        buffer: Buffer.concat([Buffer.from('MZ'), Buffer.alloc(510)]),
        filename: 'invoice.pdf',
        declaredMimeType: 'application/x-msdownload',
    });

    assert.equal(result.mismatch, 'dangerous');
});

test('allows the normal OOXML-as-ZIP magic-byte discrepancy', async () => {
    const result = await analyzeAttachmentType({
        buffer: Buffer.from([0x50, 0x4b, 0x03, 0x04, ...Array(30).fill(0)]),
        filename: 'quarterly-report.docx',
        declaredMimeType:
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    });

    assert.equal(result.detectedExtension, 'zip');
    assert.equal(result.mismatch, 'benign');
});

test('identifies scripts by their bounded shebang prefix', async () => {
    const result = await analyzeAttachmentType({
        buffer: Buffer.from('#!/bin/sh\necho harmless\n'),
        filename: 'scanned-document.pdf',
        declaredMimeType: 'application/pdf',
    });

    assert.equal(result.detectedExtension, 'script');
    assert.equal(result.mismatch, 'dangerous');
});

test('classifies ELF and Mach-O magic bytes as dangerous document mismatches', async () => {
    const samples = [
        Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]), Buffer.alloc(20)]),
        Buffer.concat([Buffer.from([0xcf, 0xfa, 0xed, 0xfe]), Buffer.alloc(20)]),
    ];

    for (const buffer of samples) {
        const result = await analyzeAttachmentType({
            buffer,
            declaredMimeType: 'application/pdf',
        });

        assert.equal(result.mismatch, 'dangerous');
    }
});

test('detects double-extension and RTL filename tricks without retaining bytes', () => {
    assert.deepEqual(analyzeAttachmentFilename('invoice.pdf.exe'), {
        filenameLength: 'invoice.pdf.exe'.length,
        extension: 'exe',
        hasRtlOverride: false,
        hasDoubleExtension: true,
        hasDangerousDoubleExtension: true,
    });

    const rtlFilename = `invoice\u202efdp.exe`;
    const result = analyzeAttachmentFilename(rtlFilename);

    assert.equal(result.hasRtlOverride, true);
    assert.equal(result.extension, 'exe');
});
