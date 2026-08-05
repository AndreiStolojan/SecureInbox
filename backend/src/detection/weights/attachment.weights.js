// ─────────────────────────────────────────────────────────────────────────────
// attachment.weights.js — greutățile semnalelor despre atașamente.
//
// Numerele sunt mutate fără modificări din scoring.config.js. Detalii:
// docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

export const ATTACHMENT_RULE_WEIGHTS = Object.freeze({
    attachment_known_malware_hash: 50,
    attachment_type_mismatch_dangerous: 40,
    attachment_encrypted_archive_with_password_in_body: 40,
    attachment_double_extension: 35,
    attachment_rtl_override_filename: 35,
    attachment_macro_enabled_office: 30,
    attachment_pdf_openaction_javascript: 30,
    attachment_zip_bomb_ratio: 25,
    attachment_encrypted_archive: 20,
    attachment_nested_archive: 15,
    attachment_type_mismatch_suspicious: 12,
    attachment_dangerous_archive_entry: 35,
    attachment_archive_path_traversal: 25,
    attachment_pdf_external_uri: 12,
    attachment_legacy_office_unverified: 20,
    high_risk_attachment_extension: 35,
    archive_attachment_extension: 12,
});
