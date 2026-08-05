import { mapWithConcurrency } from '../../common/async/map-with-concurrency.js';
import { listZipCentralDirectory } from './archive.service.js';
import { analyzeOfficeDocument } from './office.service.js';
import { analyzePdfActiveContent } from './pdf.service.js';
import {
    analyzeAttachmentType,
    getAttachmentExtension,
} from './type-detection.service.js';

export const DEFAULT_MAX_ATTACHMENTS = 10;
export const DEFAULT_MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024;
export const DEFAULT_MAX_TOTAL_BYTES = 25 * 1024 * 1024;
export const DEFAULT_ANALYSIS_CONCURRENCY = 3;
export const DEFAULT_ANALYSIS_TIMEOUT_MS = 15_000;

const MAX_BODY_CHARS = 256 * 1024;
const MAX_ANALYSIS_TIMEOUT_MS = 60_000;
const ZIP_EXTENSIONS = new Set([
    'docm', 'docx', 'dotm', 'dotx', 'ppsm', 'ppsx', 'pptm', 'pptx',
    'xlsm', 'xlsx', 'xltm', 'xltx', 'zip',
]);
const UNSUPPORTED_ARCHIVE_EXTENSIONS = new Set(['7z', 'rar']);
const LEGACY_OFFICE_EXTENSIONS = new Set(['doc', 'xls']);
const PASSWORD_PATTERN = /\b(?:password|passcode|passwd|pwd|parol[aă])\b(?:\s+(?:is|este))?[\s:=-]{0,12}[^\s<>"']{2,64}/iu;
const ARCHIVE_CONTEXT_PATTERN = /\b(?:attach(?:ed|ment)?|archive|file|zip|atașament|atasament|arhiv[aă]|fișier|fisier)\b/iu;

const boundedInteger = (value, fallback, minimum, maximum) => {
    const parsed = Number.parseInt(String(value), 10);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(Math.max(parsed, minimum), maximum);
};

const boundedString = (value, maximum) =>
    typeof value === 'string' ? value.normalize('NFC').trim().slice(0, maximum) : '';

const safeAnalyze = async (analyzer, input, fallback, options) => {
    try {
        return await (Array.isArray(input)
            ? analyzer(...input, options)
            : analyzer(input, options));
    } catch {
        return fallback;
    }
};

const timeoutOutcome = (timeoutMs) => new Promise((resolve) => {
    const timer = setTimeout(() => resolve('timed_out'), timeoutMs);
    timer.unref?.();
});

const hasPasswordNearArchiveReference = (textBody, htmlBody) => {
    const body = `${boundedString(textBody, MAX_BODY_CHARS)}\n${boundedString(
        htmlBody,
        MAX_BODY_CHARS
    )}`;
    const match = PASSWORD_PATTERN.exec(body);
    if (!match) return false;

    const start = Math.max(0, match.index - 180);
    const end = Math.min(body.length, match.index + match[0].length + 180);
    return ARCHIVE_CONTEXT_PATTERN.test(body.slice(start, end));
};

const skippedItem = (attachmentIndex, reason) => ({
    attachmentIndex,
    status: 'skipped',
    reason,
    detectedMimeType: null,
    detectedExtension: null,
    findings: [],
});

const unavailableItem = (attachmentIndex, reason) => ({
    ...skippedItem(attachmentIndex, reason),
    status: 'unavailable',
});

const classifyFindings = ({
    type,
    archive,
    office,
    pdf,
    hash,
    passwordInBody,
    legacyOfficeUnverified,
}) => {
    const findings = new Set();

    if (hash?.status === 'ok' && hash.malicious) {
        findings.add('attachment_known_malware_hash');
    }
    if (type?.mismatch === 'dangerous') {
        findings.add('attachment_type_mismatch_dangerous');
    } else if (type?.mismatch === 'suspicious') {
        findings.add('attachment_type_mismatch_suspicious');
    }
    if (type?.hasDangerousDoubleExtension) {
        findings.add('attachment_double_extension');
    }
    if (type?.hasRtlOverride) {
        findings.add('attachment_rtl_override_filename');
    }
    if (archive?.encryptedEntryCount > 0) {
        findings.add(passwordInBody
            ? 'attachment_encrypted_archive_with_password_in_body'
            : 'attachment_encrypted_archive');
    }
    if (archive?.nestedArchiveEntryCount > 0) {
        findings.add('attachment_nested_archive');
    }
    if (archive?.highCompressionRatio) {
        findings.add('attachment_zip_bomb_ratio');
    }
    if (archive?.dangerousEntryCount > 0) {
        findings.add('attachment_dangerous_archive_entry');
    }
    if (archive?.pathTraversalEntryCount > 0) {
        findings.add('attachment_archive_path_traversal');
    }
    if (office?.hasVbaProject) {
        findings.add('attachment_macro_enabled_office');
    }
    if (pdf?.hasOpenActionJavaScript) {
        findings.add('attachment_pdf_openaction_javascript');
    }
    if (pdf?.hasExternalUri) {
        findings.add('attachment_pdf_external_uri');
    }
    if (legacyOfficeUnverified) {
        findings.add('attachment_legacy_office_unverified');
    }

    return [...findings];
};

export const createAttachmentAnalysisService = ({
    enabled = false,
    fetchAttachment,
    typeAnalyzer = analyzeAttachmentType,
    archiveAnalyzer = listZipCentralDirectory,
    officeAnalyzer = analyzeOfficeDocument,
    pdfAnalyzer = analyzePdfActiveContent,
    hashAnalyzer,
    maxAttachments = DEFAULT_MAX_ATTACHMENTS,
    maxAttachmentBytes = DEFAULT_MAX_ATTACHMENT_BYTES,
    maxTotalBytes = DEFAULT_MAX_TOTAL_BYTES,
    concurrency = DEFAULT_ANALYSIS_CONCURRENCY,
    timeoutMs = DEFAULT_ANALYSIS_TIMEOUT_MS,
} = {}) => {
    const attachmentLimit = boundedInteger(
        maxAttachments,
        DEFAULT_MAX_ATTACHMENTS,
        1,
        DEFAULT_MAX_ATTACHMENTS
    );
    const attachmentByteLimit = boundedInteger(
        maxAttachmentBytes,
        DEFAULT_MAX_ATTACHMENT_BYTES,
        1,
        DEFAULT_MAX_ATTACHMENT_BYTES
    );
    const totalByteLimit = boundedInteger(
        maxTotalBytes,
        DEFAULT_MAX_TOTAL_BYTES,
        attachmentByteLimit,
        DEFAULT_MAX_TOTAL_BYTES
    );
    const analysisConcurrency = boundedInteger(concurrency, DEFAULT_ANALYSIS_CONCURRENCY, 1, 3);
    const analysisTimeoutMs = boundedInteger(
        timeoutMs,
        DEFAULT_ANALYSIS_TIMEOUT_MS,
        1,
        MAX_ANALYSIS_TIMEOUT_MS
    );

    if (enabled && typeof fetchAttachment !== 'function') {
        throw new TypeError('Enabled attachment analysis requires fetchAttachment');
    }
    for (const analyzer of [typeAnalyzer, archiveAnalyzer, officeAnalyzer, pdfAnalyzer]) {
        if (typeof analyzer !== 'function') {
            throw new TypeError('Attachment analyzer dependencies must be functions');
        }
    }
    if (hashAnalyzer !== undefined && typeof hashAnalyzer !== 'function') {
        throw new TypeError('Attachment hash analyzer must be a function');
    }

    const analyze = async ({
        mailAccount,
        messageId,
        attachments = [],
        textBody = '',
        htmlBody = '',
        senderDomain = '',
        senderVerified = false,
    } = {}) => {
        if (!enabled) {
            return { status: 'skipped', reason: 'disabled', evaluatedAt: null, items: [] };
        }
        if (!Array.isArray(attachments)) {
            return { status: 'unavailable', reason: 'invalid_input', evaluatedAt: null, items: [] };
        }

        const selected = attachments.slice(0, attachmentLimit);
        const items = [];
        const workItems = [];
        let totalDeclaredBytes = 0;
        const passwordInBody = hasPasswordNearArchiveReference(textBody, htmlBody);

        for (const [attachmentIndex, attachment] of selected.entries()) {
            const size = Number.isSafeInteger(attachment?.size) && attachment.size >= 0
                ? attachment.size
                : null;
            const attachmentId = attachment?.attachmentId;

            if (typeof attachmentId !== 'string' || !attachmentId || attachmentId.length > 1_024) {
                items.push(skippedItem(attachmentIndex, 'missing_attachment_id'));
                continue;
            }
            if (size === null) {
                items.push(skippedItem(attachmentIndex, 'invalid_size'));
                continue;
            }
            if (size > attachmentByteLimit) {
                items.push(skippedItem(attachmentIndex, 'too_large'));
                continue;
            }
            if (size > totalByteLimit - totalDeclaredBytes) {
                items.push(skippedItem(attachmentIndex, 'total_size_limit'));
                continue;
            }

            totalDeclaredBytes += size;
            const resultIndex = items.length;
            items.push(unavailableItem(attachmentIndex, 'pending'));
            workItems.push({
                attachmentIndex,
                resultIndex,
                attachmentId,
                size,
                filename: boundedString(attachment?.filename, 512),
                declaredMimeType: boundedString(attachment?.declaredMimeType, 255).toLowerCase(),
            });
        }

        const controller = new AbortController();
        const deadline = Date.now() + analysisTimeoutMs;
        const runItem = async (workItem) => {
            const {
                attachmentIndex,
                resultIndex,
                attachmentId,
                size,
                filename,
                declaredMimeType,
            } = workItem;
            if (controller.signal.aborted) {
                items[resultIndex] = unavailableItem(attachmentIndex, 'timed_out');
                return;
            }

            let buffer;
            try {
                buffer = await fetchAttachment({
                    mailAccount,
                    messageId,
                    attachmentId,
                    declaredSize: size,
                    maxBytes: attachmentByteLimit,
                    timeoutMs: Math.max(1, deadline - Date.now()),
                    signal: controller.signal,
                });
                if (!Buffer.isBuffer(buffer) || buffer.length !== size) {
                    throw new TypeError('Attachment fetch returned invalid bytes');
                }
            } catch {
                items[resultIndex] = unavailableItem(
                    attachmentIndex,
                    controller.signal.aborted ? 'timed_out' : 'fetch_failed'
                );
                return;
            }
            if (controller.signal.aborted) {
                items[resultIndex] = unavailableItem(attachmentIndex, 'timed_out');
                return;
            }

            const type = await safeAnalyze(
                typeAnalyzer,
                { buffer, filename, declaredMimeType },
                { status: 'error', mismatch: 'unknown' }
            );
            if (controller.signal.aborted) {
                items[resultIndex] = unavailableItem(attachmentIndex, 'timed_out');
                return;
            }
            const extension = getAttachmentExtension(filename);
            const detectedExtension = boundedString(type?.detectedExtension, 32).toLowerCase();
            const likelyZip = ZIP_EXTENSIONS.has(extension) || detectedExtension === 'zip';
            const likelyPdf = extension === 'pdf' || detectedExtension === 'pdf';
            const [archive, office, pdf, hash] = await Promise.all([
                likelyZip
                    ? safeAnalyze(
                        archiveAnalyzer,
                        buffer,
                        { status: 'error' },
                        { signal: controller.signal }
                    )
                    : Promise.resolve({ status: 'skipped' }),
                likelyZip
                    ? safeAnalyze(
                        officeAnalyzer,
                        { buffer, filename, signal: controller.signal },
                        { status: 'error' }
                    )
                    : Promise.resolve({ status: 'skipped' }),
                likelyPdf
                    ? safeAnalyze(
                        pdfAnalyzer,
                        [buffer, { senderDomain }],
                        { status: 'error' }
                    )
                    : Promise.resolve({ status: 'skipped' }),
                hashAnalyzer
                    ? safeAnalyze(
                        hashAnalyzer,
                        buffer,
                        { status: 'unavailable' },
                        { signal: controller.signal }
                    )
                    : Promise.resolve({ status: 'unavailable' }),
            ]);
            if (controller.signal.aborted) {
                items[resultIndex] = unavailableItem(attachmentIndex, 'timed_out');
                return;
            }
            const unsupportedArchive = UNSUPPORTED_ARCHIVE_EXTENSIONS.has(
                detectedExtension || extension
            );

            items[resultIndex] = {
                attachmentIndex,
                status: 'evaluated',
                reason: unsupportedArchive ? 'unsupported_archive_type' : null,
                detectedMimeType: boundedString(type?.detectedMimeType, 255).toLowerCase() || null,
                detectedExtension: detectedExtension || null,
                findings: classifyFindings({
                    type,
                    archive,
                    office,
                    pdf,
                    hash,
                    passwordInBody,
                    legacyOfficeUnverified:
                        LEGACY_OFFICE_EXTENSIONS.has(extension) && !senderVerified,
                }),
            };
        };

        const work = mapWithConcurrency(workItems, analysisConcurrency, runItem)
            .then(() => 'completed')
            .catch(() => 'failed');
        const outcome = await Promise.race([work, timeoutOutcome(analysisTimeoutMs)]);
        if (outcome === 'timed_out') {
            controller.abort();
        }

        const snapshot = items.map((item) =>
            item.reason === 'pending' ? unavailableItem(item.attachmentIndex, 'timed_out') : item
        );
        const partial = outcome !== 'completed' ||
            attachments.length > selected.length ||
            snapshot.some(({ status }) => status !== 'evaluated');

        return {
            status: partial ? 'partial' : 'evaluated',
            reason: outcome === 'timed_out'
                ? 'timed_out'
                : attachments.length > selected.length
                    ? 'attachment_limit'
                    : null,
            evaluatedAt: new Date(),
            items: snapshot,
        };
    };

    return Object.freeze({ analyze });
};
