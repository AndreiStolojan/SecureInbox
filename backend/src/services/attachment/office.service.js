import { getAttachmentExtension } from './type-detection.service.js';
import { listZipCentralDirectory } from './archive.service.js';

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

const MACRO_ENABLED_EXTENSIONS = new Set([
    'docm',
    'dotm',
    'xlsm',
    'xltm',
    'pptm',
    'ppsm',
]);

const VBA_PROJECT_NAME = /(?:^|\/)vbaProject\.bin$/iu;

// Checks names already present in the ZIP central directory. No Office parser,
// macro runtime, or archive entry stream is ever opened.
export const analyzeOfficeDocument = async ({
    buffer,
    filename = '',
    archiveOptions = {},
    signal = archiveOptions?.signal,
} = {}) => {
    const extension = getAttachmentExtension(filename);
    const archive = await listZipCentralDirectory(buffer, {
        ...archiveOptions,
        includeEntryNames: true,
        signal,
    });
    const hasVbaProject = archive.entryNames.some((entryName) => VBA_PROJECT_NAME.test(entryName));

    return {
        status: archive.status,
        isOoxmlExtension: OOXML_EXTENSIONS.has(extension),
        declaresMacroEnabled: MACRO_ENABLED_EXTENSIONS.has(extension),
        hasVbaProject,
        entryCount: archive.entryCount,
        entryLimitReached: archive.entryLimitReached,
    };
};
