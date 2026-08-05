const PDF_HEADER = Buffer.from('%PDF-');
const DEFAULT_MAX_PDF_SCAN_BYTES = 1024 * 1024;
const MAX_PDF_SCAN_BYTES = 10 * 1024 * 1024;
const MAX_URI_CANDIDATES = 20;
const PDF_URI_PATTERN = /\/URI\s*\(([^)\r\n]{1,2048})\)/giu;

const ACTIVE_CONTENT_TOKENS = Object.freeze({
    hasAdditionalActions: Buffer.from('/AA'),
    hasEmbeddedFile: Buffer.from('/EmbeddedFile'),
    hasJavaScript: Buffer.from('/JavaScript'),
    hasJs: Buffer.from('/JS'),
    hasLaunch: Buffer.from('/Launch'),
    hasOpenAction: Buffer.from('/OpenAction'),
    hasUri: Buffer.from('/URI'),
});

const getScanLimit = (value) => {
    const parsed = Number.parseInt(String(value), 10);

    if (!Number.isFinite(parsed)) return DEFAULT_MAX_PDF_SCAN_BYTES;
    return Math.min(Math.max(parsed, 1), MAX_PDF_SCAN_BYTES);
};

const emptyPdfAnalysis = (status, extra = {}) => ({
    status,
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
    ...extra,
});

// Scans bounded raw PDF bytes for structural names. It does not render or parse
// a PDF object graph, and the returned metadata never includes byte content.
const hasExternalUri = (sample, senderDomain) => {
    const normalizedSender = typeof senderDomain === 'string'
        ? senderDomain.trim().toLowerCase().replace(/\.$/u, '')
        : '';
    const text = sample.toString('latin1');
    let checked = 0;

    for (const match of text.matchAll(PDF_URI_PATTERN)) {
        if (checked >= MAX_URI_CANDIDATES) break;
        checked += 1;
        try {
            const hostname = new URL(match[1]).hostname.toLowerCase().replace(/\.$/u, '');
            if (
                hostname &&
                (!normalizedSender ||
                    (hostname !== normalizedSender && !hostname.endsWith(`.${normalizedSender}`)))
            ) {
                return true;
            }
        } catch {
            // Malformed or non-web URI actions are covered by the structural URI flag.
        }
    }

    return false;
};

export const analyzePdfActiveContent = (buffer, { maxBytes, senderDomain } = {}) => {
    if (!Buffer.isBuffer(buffer)) return emptyPdfAnalysis('invalid_input');
    if (buffer.length < PDF_HEADER.length || !buffer.subarray(0, PDF_HEADER.length).equals(PDF_HEADER)) {
        return emptyPdfAnalysis('not_pdf');
    }

    const scanLimit = getScanLimit(maxBytes);
    const sample = buffer.subarray(0, scanLimit);
    const findings = Object.fromEntries(
        Object.entries(ACTIVE_CONTENT_TOKENS).map(([key, token]) => [
            key,
            sample.indexOf(token) !== -1,
        ])
    );

    return emptyPdfAnalysis('analyzed', {
        inspectedBytes: sample.length,
        truncated: buffer.length > sample.length,
        ...findings,
        hasOpenActionJavaScript:
            findings.hasOpenAction && (findings.hasJavaScript || findings.hasJs),
        hasExternalUri: findings.hasUri && hasExternalUri(sample, senderDomain),
    });
};
