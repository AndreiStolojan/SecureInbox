import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzeOfficeDocument } from '../../src/services/attachment/office.service.js';

const createSyntheticZip = (entryNames) => {
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    const centralDirectory = entryNames.map((name) => {
        const nameBuffer = Buffer.from(name);
        const header = Buffer.alloc(46 + nameBuffer.length);

        header.writeUInt32LE(0x02014b50, 0);
        header.writeUInt16LE(20, 4);
        header.writeUInt16LE(20, 6);
        header.writeUInt16LE(nameBuffer.length, 28);
        nameBuffer.copy(header, 46);

        return header;
    });
    const centralDirectoryBuffer = Buffer.concat(centralDirectory);
    const endOfCentralDirectory = Buffer.alloc(22);

    endOfCentralDirectory.writeUInt32LE(0x06054b50, 0);
    endOfCentralDirectory.writeUInt16LE(entryNames.length, 8);
    endOfCentralDirectory.writeUInt16LE(entryNames.length, 10);
    endOfCentralDirectory.writeUInt32LE(centralDirectoryBuffer.length, 12);
    endOfCentralDirectory.writeUInt32LE(localHeader.length, 16);

    return Buffer.concat([localHeader, centralDirectoryBuffer, endOfCentralDirectory]);
};

test('finds vbaProject.bin from OOXML central-directory names only', async () => {
    const result = await analyzeOfficeDocument({
        buffer: createSyntheticZip([
            '[Content_Types].xml',
            'word/vbaProject.bin',
        ]),
        filename: 'agenda.docx',
    });

    assert.equal(result.status, 'analyzed');
    assert.equal(result.isOoxmlExtension, true);
    assert.equal(result.declaresMacroEnabled, false);
    assert.equal(result.hasVbaProject, true);
    assert.equal(Object.hasOwn(result, 'entryNames'), false);
});

test('records a declared macro-enabled extension separately from macro presence', async () => {
    const result = await analyzeOfficeDocument({
        buffer: createSyntheticZip(['xl/workbook.xml']),
        filename: 'budget.xlsm',
    });

    assert.equal(result.declaresMacroEnabled, true);
    assert.equal(result.hasVbaProject, false);
});

test('passes cancellation through to the central-directory inspection', async () => {
    const controller = new AbortController();
    controller.abort();

    const result = await analyzeOfficeDocument({
        buffer: createSyntheticZip(['word/vbaProject.bin']),
        filename: 'agenda.docx',
        signal: controller.signal,
    });

    assert.equal(result.status, 'aborted');
    assert.equal(result.hasVbaProject, false);
});
