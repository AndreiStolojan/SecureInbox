import assert from 'node:assert/strict';
import test from 'node:test';

import {
    isZipBuffer,
    listZipCentralDirectory,
} from '../../src/services/attachment/archive.service.js';

const createSyntheticZip = (entries) => {
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);

    const centralDirectory = entries.map(({
        name,
        flags = 0,
        compressedSize = 10,
        uncompressedSize = 100,
    }) => {
        const nameBuffer = Buffer.from(name);
        const header = Buffer.alloc(46 + nameBuffer.length);

        header.writeUInt32LE(0x02014b50, 0);
        header.writeUInt16LE(20, 4);
        header.writeUInt16LE(20, 6);
        header.writeUInt16LE(flags, 8);
        header.writeUInt16LE(8, 10);
        header.writeUInt32LE(compressedSize, 20);
        header.writeUInt32LE(uncompressedSize, 24);
        header.writeUInt16LE(nameBuffer.length, 28);
        nameBuffer.copy(header, 46);

        return header;
    });
    const centralDirectoryBuffer = Buffer.concat(centralDirectory);
    const endOfCentralDirectory = Buffer.alloc(22);

    endOfCentralDirectory.writeUInt32LE(0x06054b50, 0);
    endOfCentralDirectory.writeUInt16LE(entries.length, 8);
    endOfCentralDirectory.writeUInt16LE(entries.length, 10);
    endOfCentralDirectory.writeUInt32LE(centralDirectoryBuffer.length, 12);
    endOfCentralDirectory.writeUInt32LE(localHeader.length, 16);

    return Buffer.concat([localHeader, centralDirectoryBuffer, endOfCentralDirectory]);
};

test('lists bounded ZIP central-directory metadata without extracting entries', async () => {
    const buffer = createSyntheticZip([
        {
            name: 'nested/payload.zip',
            flags: 0x0001,
            compressedSize: 10,
            uncompressedSize: 2_000,
        },
        { name: 'runme.exe' },
    ]);
    const result = await listZipCentralDirectory(buffer);

    assert.equal(isZipBuffer(buffer), true);
    assert.equal(result.status, 'analyzed');
    assert.equal(result.entryCount, 2);
    assert.equal(result.encryptedEntryCount, 1);
    assert.equal(result.nestedArchiveEntryCount, 1);
    assert.equal(result.dangerousEntryCount, 1);
    assert.equal(result.highCompressionRatio, true);
    assert.deepEqual(result.entryNames, []);
});

test('handles yauzl path validation as a traversal finding without opening an entry', async () => {
    const result = await listZipCentralDirectory(
        createSyntheticZip([{ name: '../escape.exe' }])
    );

    assert.equal(result.status, 'invalid_archive');
    assert.equal(result.pathTraversalEntryCount, 1);
});

test('stops central-directory enumeration at the configured entry cap', async () => {
    const result = await listZipCentralDirectory(
        createSyntheticZip([
            { name: 'one.txt' },
            { name: 'two.txt' },
            { name: 'three.txt' },
        ]),
        { maxEntries: 2 }
    );

    assert.equal(result.status, 'truncated');
    assert.equal(result.entryCount, 2);
    assert.equal(result.entryLimitReached, true);
});

test('aborting an open central-directory listing closes it and returns promptly', async () => {
    const controller = new AbortController();
    const pending = listZipCentralDirectory(
        createSyntheticZip([{ name: 'payload.txt' }]),
        { signal: controller.signal }
    );

    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();

    const result = await pending;
    assert.equal(result.status, 'aborted');
    assert.equal(result.entryCount, 0);
});
