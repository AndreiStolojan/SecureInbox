import { isAttachmentAnalysisEnabled } from '../../config/env.js';

export const meta = Object.freeze({
    id: 'attachment-analysis',
    version: 1,
    kind: 'rule',
    optional: true,
});

const FINDINGS = Object.freeze({
    attachment_known_malware_hash: {
        reason: 'An attachment hash matches known malware.',
        details: 'At least one attachment matched a malware reputation source.',
    },
    attachment_type_mismatch_dangerous: {
        reason: 'An attachment disguises an executable as a document or image.',
        details: 'Attachment content does not match its declared safe-looking type.',
    },
    attachment_encrypted_archive_with_password_in_body: {
        reason: 'An encrypted archive has a password supplied in the message body.',
        details: 'The attachment and message body use a malware-delivery pattern.',
    },
    attachment_double_extension: {
        reason: 'An attachment filename uses a dangerous double extension.',
        details: 'The final filename extension can conceal an executable type.',
    },
    attachment_rtl_override_filename: {
        reason: 'An attachment filename uses a right-to-left override character.',
        details: 'The filename may render its executable extension misleadingly.',
    },
    attachment_macro_enabled_office: {
        reason: 'An Office attachment contains a VBA macro project.',
        details: 'The document archive contains a macro-bearing VBA project.',
    },
    attachment_pdf_openaction_javascript: {
        reason: 'A PDF contains JavaScript configured to run on open.',
        details: 'The PDF structural scan found both OpenAction and JavaScript.',
    },
    attachment_encrypted_archive: {
        reason: 'An attachment is an encrypted archive.',
        details: 'Encrypted archive contents cannot be inspected safely.',
    },
    attachment_nested_archive: {
        reason: 'An attachment archive contains another archive.',
        details: 'Nested archives are commonly used to hide attachment payloads.',
    },
    attachment_type_mismatch_suspicious: {
        reason: 'An attachment content type does not match its declared type.',
        details: 'The attachment type mismatch could not be explained as benign.',
    },
    attachment_zip_bomb_ratio: {
        reason: 'An attachment archive has an unusually high compression ratio.',
        details: 'The archive metadata indicates a possible decompression bomb.',
    },
    attachment_dangerous_archive_entry: {
        reason: 'An archive contains a dangerous file type.',
        details: 'The archive directory lists an executable or script payload.',
    },
    attachment_archive_path_traversal: {
        reason: 'An archive contains an unsafe path.',
        details: 'The archive directory contains a path-traversal entry.',
    },
    attachment_pdf_external_uri: {
        reason: 'A PDF action points outside the sender domain.',
        details: 'The PDF contains an external URI action unrelated to the sender.',
    },
    attachment_legacy_office_unverified: {
        reason: 'An unverified sender attached a legacy Office document.',
        details: 'Legacy Office formats can contain macros without declaring them.',
    },
});

const signal = (key) => ({
    key,
    rule: key,
    reason: FINDINGS[key].reason,
    details: FINDINGS[key].details,
    order: 49,
});

const normalizedFindings = (analysis) => {
    const findings = new Set();
    for (const item of Array.isArray(analysis?.items) ? analysis.items : []) {
        for (const finding of Array.isArray(item?.findings) ? item.findings : []) {
            if (Object.hasOwn(FINDINGS, finding)) findings.add(finding);
        }
    }

    if (findings.has('attachment_encrypted_archive_with_password_in_body')) {
        findings.delete('attachment_encrypted_archive');
    }
    if (findings.has('attachment_type_mismatch_dangerous')) {
        findings.delete('attachment_type_mismatch_suspicious');
    }

    return [...findings];
};

const providerMeta = (analysis) => ({
    status: ['evaluated', 'partial', 'skipped', 'unavailable'].includes(analysis?.status)
        ? analysis.status
        : 'unavailable',
    itemCount: Math.min(
        Array.isArray(analysis?.items) ? analysis.items.length : 0,
        10
    ),
});

export const collectAttachmentAnalysisSignals = (analysis) =>
    normalizedFindings(analysis).map(signal);

export const analyze = async (ctx = {}) => {
    const enabled = ctx.attachmentAnalysisEnabled ?? isAttachmentAnalysisEnabled();
    if (!enabled) {
        return {
            status: 'skipped',
            signals: [],
            meta: { status: 'disabled', itemCount: 0 },
        };
    }

    const analysis = ctx.email?.attachmentAnalysis;
    if (!analysis || !['evaluated', 'partial'].includes(analysis.status)) {
        return {
            status: 'skipped',
            signals: [],
            meta: providerMeta(analysis),
        };
    }

    return {
        signals: collectAttachmentAnalysisSignals(analysis),
        meta: providerMeta(analysis),
    };
};

export const collectSignals = collectAttachmentAnalysisSignals;
