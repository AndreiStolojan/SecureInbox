import { fileTypeFromBuffer } from 'file-type';

const MAX_MAGIC_BYTES = 4_100;

const DANGEROUS_FILE_TYPES = new Set([
    'exe',
    'elf',
    'macho',
    'script',
]);

const DOCUMENT_OR_IMAGE_EXTENSIONS = new Set([
    'doc',
    'docx',
    'dotx',
    'pdf',
    'ppt',
    'pptx',
    'ppsx',
    'xls',
    'xlsx',
    'xltx',
    'jpg',
    'jpeg',
    'png',
    'gif',
    'webp',
]);

const OOXML_EXTENSIONS = new Set([
    'docx',
    'docm',
    'dotx',
    'dotm',
    'xlsx',
    'xlsm',
    'xltx',
    'xltm',
    'pptx',
    'pptm',
    'ppsx',
    'ppsm',
]);

const OOXML_MIME_TYPES = new Set([
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-word.document.macroenabled.12',
    'application/vnd.ms-excel.sheet.macroenabled.12',
    'application/vnd.ms-powerpoint.presentation.macroenabled.12',
]);

const DOCUMENT_MIME_TYPES = new Set([
    'application/msword',
    'application/pdf',
    'application/vnd.ms-excel',
    'application/vnd.ms-powerpoint',
    ...OOXML_MIME_TYPES,
]);

const DANGEROUS_FILENAME_EXTENSIONS = new Set([
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

const SCRIPT_PREFIXES = [
    '#!',
    '<?php',
    '<script',
];

const normalizeFilename = (filename) =>
    typeof filename === 'string'
        ? filename.normalize('NFC').trim()
        : '';

export const getAttachmentExtension = (filename) => {
    const normalizedFilename = normalizeFilename(filename);
    const basename = normalizedFilename.split(/[\\/]/u).at(-1) || '';
    const finalDotIndex = basename.lastIndexOf('.');

    if (finalDotIndex <= 0 || finalDotIndex === basename.length - 1) {
        return '';
    }

    return basename.slice(finalDotIndex + 1).toLowerCase();
};

const isOoxmlDeclaration = ({ extension, mimeType }) => {
    const genericMimeType = !mimeType || mimeType === 'application/octet-stream';

    return (
        (OOXML_EXTENSIONS.has(extension) && (genericMimeType || OOXML_MIME_TYPES.has(mimeType))) ||
        (OOXML_MIME_TYPES.has(mimeType) && (!extension || OOXML_EXTENSIONS.has(extension)))
    );
};

const hasScriptMagic = (buffer) => {
    const head = buffer.subarray(0, 256).toString('latin1').toLowerCase();

    return SCRIPT_PREFIXES.some((prefix) => head.startsWith(prefix));
};

const detectType = async (buffer) => {
    const detected = await fileTypeFromBuffer(buffer.subarray(0, MAX_MAGIC_BYTES));

    if (detected) {
        return {
            extension: detected.ext || '',
            mimeType: detected.mime || '',
        };
    }

    if (hasScriptMagic(buffer)) {
        return {
            extension: 'script',
            mimeType: 'text/x-script',
        };
    }

    return {
        extension: '',
        mimeType: '',
    };
};

const classifyMismatch = ({ declaredExtension, declaredMimeType, detectedExtension, detectedMimeType }) => {
    if (!detectedExtension && !detectedMimeType) return 'unknown';

    const comparableDeclaredMimeType = declaredMimeType === 'application/octet-stream'
        ? ''
        : declaredMimeType;

    if (
        DANGEROUS_FILE_TYPES.has(detectedExtension) &&
        (
            DOCUMENT_OR_IMAGE_EXTENSIONS.has(declaredExtension) ||
            comparableDeclaredMimeType.startsWith('image/') ||
            DOCUMENT_MIME_TYPES.has(comparableDeclaredMimeType)
        )
    ) {
        return 'dangerous';
    }

    if (
        detectedExtension === 'zip' &&
        isOoxmlDeclaration({ extension: declaredExtension, mimeType: comparableDeclaredMimeType })
    ) {
        return 'benign';
    }

    const extensionMatches = !declaredExtension || declaredExtension === detectedExtension;
    const mimeTypeMatches =
        !comparableDeclaredMimeType || comparableDeclaredMimeType === detectedMimeType;

    return extensionMatches && mimeTypeMatches
        ? 'none'
        : 'suspicious';
};

export const analyzeAttachmentFilename = (filename) => {
    const normalizedFilename = normalizeFilename(filename);
    const basename = normalizedFilename.split(/[\\/]/u).at(-1) || '';
    const parts = basename.split('.').filter(Boolean);
    const extension = getAttachmentExtension(basename);

    return {
        filenameLength: normalizedFilename.length,
        extension,
        hasRtlOverride: normalizedFilename.includes('\u202e'),
        hasDoubleExtension: parts.length >= 3,
        hasDangerousDoubleExtension:
            parts.length >= 3 && DANGEROUS_FILENAME_EXTENSIONS.has(extension),
    };
};

// Inspects only a bounded prefix of an already in-memory attachment. It returns
// classification metadata, never the buffer or any of its contents.
export const analyzeAttachmentType = async ({
    buffer,
    filename = '',
    declaredMimeType = '',
} = {}) => {
    if (!Buffer.isBuffer(buffer)) {
        return {
            status: 'invalid_input',
            mismatch: 'unknown',
            ...analyzeAttachmentFilename(filename),
            declaredMimeType: '',
            detectedExtension: '',
            detectedMimeType: '',
        };
    }

    const filenameAnalysis = analyzeAttachmentFilename(filename);
    const normalizedDeclaredMimeType = typeof declaredMimeType === 'string'
        ? declaredMimeType.trim().toLowerCase()
        : '';
    const detected = await detectType(buffer);
    const mismatch = classifyMismatch({
        declaredExtension: filenameAnalysis.extension,
        declaredMimeType: normalizedDeclaredMimeType,
        detectedExtension: detected.extension,
        detectedMimeType: detected.mimeType,
    });

    return {
        status: 'analyzed',
        ...filenameAnalysis,
        declaredMimeType: normalizedDeclaredMimeType,
        detectedExtension: detected.extension,
        detectedMimeType: detected.mimeType,
        mismatch,
    };
};
