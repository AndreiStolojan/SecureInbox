import yauzl from 'yauzl';

const ZIP_LOCAL_FILE_HEADER = 0x04034b50;
const ZIP_EMPTY_ARCHIVE = 0x06054b50;
const ZIP_SPANNED_ARCHIVE = 0x08074b50;
const DEFAULT_MAX_ARCHIVE_BYTES = 10 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 200;
const DEFAULT_MAX_ENTRY_NAME_CHARS = 512;
const DEFAULT_MAX_AGGREGATE_BYTES = 1024 * 1024 * 1024;
const DEFAULT_HIGH_COMPRESSION_RATIO = 100;

const DANGEROUS_ARCHIVE_EXTENSIONS = new Set([
    'apk',
    'bat',
    'cmd',
    'com',
    'exe',
    'hta',
    'jar',
    'js',
    'lnk',
    'msi',
    'pif',
    'ps1',
    'scr',
    'vbe',
    'vbs',
]);

const ARCHIVE_EXTENSIONS = new Set([
    '7z',
    'gz',
    'rar',
    'tar',
    'zip',
]);

const boundedInteger = (value, fallback, minimum, maximum) => {
    const parsed = Number.parseInt(String(value), 10);

    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(Math.max(parsed, minimum), maximum);
};

const getEntryExtension = (entryName) => {
    const basename = entryName.split('/').at(-1) || '';
    const finalDotIndex = basename.lastIndexOf('.');

    return finalDotIndex > 0 && finalDotIndex < basename.length - 1
        ? basename.slice(finalDotIndex + 1).toLowerCase()
        : '';
};

const isTraversalError = (error) =>
    /(?:absolute path|invalid relative path|invalid characters in fileName)/iu.test(
        String(error?.message || '')
    );

const isHighCompressionRatio = ({ compressedSize, uncompressedSize, threshold }) => {
    if (uncompressedSize <= 0) return false;
    if (compressedSize === 0) return true;

    return uncompressedSize / compressedSize >= threshold;
};

export const isZipBuffer = (buffer) => {
    if (!Buffer.isBuffer(buffer) || buffer.length < 4) return false;

    const signature = buffer.readUInt32LE(0);

    return [ZIP_LOCAL_FILE_HEADER, ZIP_EMPTY_ARCHIVE, ZIP_SPANNED_ARCHIVE].includes(signature);
};

const emptyArchiveAnalysis = (status, extra = {}) => ({
    status,
    entryCount: 0,
    entryLimitReached: false,
    encryptedEntryCount: 0,
    nestedArchiveEntryCount: 0,
    dangerousEntryCount: 0,
    pathTraversalEntryCount: 0,
    highCompressionRatio: false,
    aggregateSizeExceeded: false,
    totalCompressedBytes: 0,
    totalUncompressedBytes: 0,
    entryNames: [],
    ...extra,
});

// Lists ZIP central-directory metadata only. It intentionally never calls
// `openReadStream`, so no archive entry is extracted or decompressed.
export const listZipCentralDirectory = async (buffer, options = {}) => {
    const maxArchiveBytes = boundedInteger(
        options.maxArchiveBytes,
        DEFAULT_MAX_ARCHIVE_BYTES,
        1,
        DEFAULT_MAX_ARCHIVE_BYTES
    );
    const maxEntries = boundedInteger(
        options.maxEntries,
        DEFAULT_MAX_ENTRIES,
        1,
        1_000
    );
    const maxEntryNameChars = boundedInteger(
        options.maxEntryNameChars,
        DEFAULT_MAX_ENTRY_NAME_CHARS,
        1,
        4_096
    );
    const maxAggregateBytes = boundedInteger(
        options.maxAggregateBytes,
        DEFAULT_MAX_AGGREGATE_BYTES,
        1,
        DEFAULT_MAX_AGGREGATE_BYTES
    );
    const highCompressionRatio = boundedInteger(
        options.highCompressionRatio,
        DEFAULT_HIGH_COMPRESSION_RATIO,
        2,
        10_000
    );
    const includeEntryNames = options.includeEntryNames === true;
    const signal = options.signal;

    if (!Buffer.isBuffer(buffer)) return emptyArchiveAnalysis('invalid_input');
    if (buffer.length > maxArchiveBytes) {
        return emptyArchiveAnalysis('skipped_too_large');
    }
    if (!isZipBuffer(buffer)) return emptyArchiveAnalysis('not_zip');
    if (signal?.aborted) return emptyArchiveAnalysis('aborted');

    return new Promise((resolve) => {
        let settled = false;
        let zipFile = null;
        const analysis = emptyArchiveAnalysis('analyzed');

        const finish = (status, extra = {}) => {
            if (settled) return;
            settled = true;
            signal?.removeEventListener?.('abort', onAbort);
            if (zipFile?.isOpen) zipFile.close();
            resolve({ ...analysis, status, ...extra });
        };
        const onAbort = () => finish('aborted');
        signal?.addEventListener?.('abort', onAbort, { once: true });

        if (signal?.aborted) {
            onAbort();
            return;
        }

        const addAggregateSize = (key, value) => {
            const currentValue = analysis[key];
            const nextValue = currentValue + value;

            if (!Number.isSafeInteger(nextValue) || nextValue > maxAggregateBytes) {
                analysis[key] = maxAggregateBytes;
                analysis.aggregateSizeExceeded = true;
                return;
            }

            analysis[key] = nextValue;
        };

        try {
            yauzl.fromBuffer(
                buffer,
                {
                    autoClose: true,
                    decodeStrings: true,
                    lazyEntries: true,
                    strictFileNames: false,
                    validateEntrySizes: false,
                },
                (openError, openedZipFile) => {
                    if (settled) {
                        if (openedZipFile?.isOpen) openedZipFile.close();
                        return;
                    }
                    if (openError || !openedZipFile) {
                        finish('invalid_archive', {
                            pathTraversalEntryCount: isTraversalError(openError) ? 1 : 0,
                        });
                        return;
                    }

                    zipFile = openedZipFile;
                    zipFile.on('error', (error) => {
                        finish('invalid_archive', {
                            pathTraversalEntryCount: isTraversalError(error)
                                ? Math.max(analysis.pathTraversalEntryCount, 1)
                                : analysis.pathTraversalEntryCount,
                        });
                    });
                    zipFile.on('end', () => finish('analyzed'));
                    zipFile.on('entry', (entry) => {
                        if (analysis.entryCount >= maxEntries) {
                            analysis.entryLimitReached = true;
                            finish('truncated');
                            return;
                        }

                        analysis.entryCount += 1;
                        const entryName = typeof entry.fileName === 'string'
                            ? entry.fileName
                            : '';
                        const entryExtension = getEntryExtension(entryName);
                        const compressedSize = Number(entry.compressedSize) || 0;
                        const uncompressedSize = Number(entry.uncompressedSize) || 0;

                        if (entryName.length > maxEntryNameChars) {
                            analysis.entryLimitReached = true;
                            finish('truncated');
                            return;
                        }

                        if (includeEntryNames) analysis.entryNames.push(entryName);
                        if ((entry.generalPurposeBitFlag & 0x0001) !== 0) {
                            analysis.encryptedEntryCount += 1;
                        }
                        if (ARCHIVE_EXTENSIONS.has(entryExtension)) {
                            analysis.nestedArchiveEntryCount += 1;
                        }
                        if (DANGEROUS_ARCHIVE_EXTENSIONS.has(entryExtension)) {
                            analysis.dangerousEntryCount += 1;
                        }
                        if (isHighCompressionRatio({
                            compressedSize,
                            uncompressedSize,
                            threshold: highCompressionRatio,
                        })) {
                            analysis.highCompressionRatio = true;
                        }

                        addAggregateSize('totalCompressedBytes', compressedSize);
                        addAggregateSize('totalUncompressedBytes', uncompressedSize);

                        zipFile.readEntry();
                    });
                    zipFile.readEntry();
                }
            );
        } catch (error) {
            finish('invalid_archive', {
                pathTraversalEntryCount: isTraversalError(error) ? 1 : 0,
            });
        }
    });
};
