// ─────────────────────────────────────────────────────────────────────────────
// scan-explanation.service.js — explicația "de rezervă" (fără AI) a scanării.
//
// Ce face, pe scurt: construiește un text în limbaj natural care explică DE CE
// un email a primit un anumit verdict (safe / suspicious / likely_phishing),
// folosind DOAR informații deterministe: regulile declanșate, semnalele AI (dacă
// există), contextul de brand verificat și contextul de liste ale userului
// (allowlist/blocklist). Acesta e textul de rezervă folosit când AI e dezactivat
// sau a eșuat — vezi `resolveExplanationResult` din scan.service.js.
//
// Detalii: docs/EXPLICATIE_BACKEND.md §4.6.
// ─────────────────────────────────────────────────────────────────────────────

// Propoziția de bază pentru fiecare verdict posibil — prima frază din explicație.
const verdictToSentence = {
    safe:
        'The current verdict shows a low risk based on the active checks. Still, verify the sender before sending any sensitive information.',
    suspicious:
        'The current verdict shows a suspicious email based on the detected signals. Avoid the links and verify the sender through a trusted channel.',
    likely_phishing:
        'The current verdict shows a high likelihood of phishing based on the detected signals. Do not open the links and do not send any sensitive information.',
};

// Traduceri în limbaj uman pentru câteva id-uri de regulă (cele care nu au un
// tipar special). Restul regulilor sunt tratate în `ruleToPhrase` mai jos.
const RULE_PHRASES = {
    reply_to_mismatch: 'the Reply-To address does not match the sender',
    shortened_url_detected: 'the email contains shortened links',
    high_risk_attachment_extension: 'the email contains a high-risk attachment',
    archive_attachment_extension:
        'the email contains a compressed archive attachment',
    attachment_known_malware_hash: 'an attachment matches known malware',
    attachment_type_mismatch_dangerous: 'an attachment disguises executable content',
    attachment_encrypted_archive_with_password_in_body:
        'an encrypted archive password appears in the message',
    attachment_double_extension: 'an attachment uses a misleading double extension',
    attachment_rtl_override_filename: 'an attachment uses a misleading filename direction',
    attachment_macro_enabled_office: 'an Office attachment contains macros',
    attachment_pdf_openaction_javascript: 'a PDF runs JavaScript when opened',
    attachment_encrypted_archive: 'an attachment is an encrypted archive',
    attachment_nested_archive: 'an archive contains another archive',
    attachment_type_mismatch_suspicious: 'an attachment type does not match its name',
    attachment_zip_bomb_ratio: 'an archive has an unsafe compression ratio',
    attachment_dangerous_archive_entry: 'an archive contains an executable or script',
    attachment_archive_path_traversal: 'an archive contains an unsafe path',
    attachment_pdf_external_uri: 'a PDF points outside the sender domain',
    attachment_legacy_office_unverified:
        'an unverified sender attached a legacy Office document',
    'threat_intelligence:url_known_malicious':
        'Google Web Risk or URLhaus identified a known malicious link',
    'threat_intelligence:url_known_phishing_campaign':
        'Google Web Risk identified a known phishing link',
    'threat_intelligence:domain_registered_days_ago_lt_7':
        'a linked domain was registered less than seven days ago',
    'threat_intelligence:domain_registered_days_ago_lt_30':
        'a linked domain was registered less than thirty days ago',
    'threat_intelligence:link_text_href_mismatch':
        'a displayed link address differs from its real destination',
    'threat_intelligence:redirect_chain_to_different_tld':
        'a shortened link redirects away from the sender domain',
    'threat_intelligence:excessive_redirect_chain':
        'a shortened link uses an unusually long redirect chain',
    'threat_intelligence:redirect_to_private_address':
        'a redirect attempted to reach a private network address',
};

// Transformă un id de regulă (ex: "ip_address_link", "too_many_links_high") într-o
// frază scurtă, ușor de înțeles, care explică ce s-a detectat.
const ruleToPhrase = (ruleId) => {
    if (!ruleId) {
        return '';
    }

    // Toate tiparele de link suspecte (ip_address_link, embedded_credentials etc.)
    // au id-uri de forma "suspicious_link_pattern:<tipar>" — le tratăm la grup.
    if (ruleId.startsWith('suspicious_link_pattern:')) {
        return 'the email contains suspicious link patterns';
    }

    // Cele două variante ale regulii "prea multe linkuri" (prag mediu/mare) au
    // aceeași explicație pentru user.
    if (ruleId === 'too_many_links_high' || ruleId === 'too_many_links_medium') {
        return 'the email has an unusually high number of links';
    }

    return RULE_PHRASES[ruleId] || '';
};

// Construiește propoziția despre regulile declanșate: ia primele 2 reguli care au
// o frază asociată (ca să nu fie explicația prea lungă) și le combină într-o
// singură frază.
const buildRuleSentence = (triggeredRules = []) => {
    const phrases = triggeredRules
        .map((ruleItem) => ruleToPhrase(ruleItem.rule))
        .filter(Boolean)
        .slice(0, 2);

    if (phrases.length === 0) {
        return '';
    }

    if (phrases.length === 1) {
        return `The security checks flagged that ${phrases[0]}.`;
    }

    return `The security checks flagged that ${phrases[0]} and ${phrases[1]}.`;
};

// Construiește propoziția despre semnalele AI (dacă AI a rulat cu succes).
// Dacă AI e dezactivat / a eșuat (status !== 'evaluated'), nu adăugăm nimic.
const buildAiSentence = (aiSignals) => {
    if (!aiSignals || aiSignals.status !== 'evaluated') {
        return '';
    }

    const fragments = [];

    // Urgență medie/mare în text ("acționează acum!", "contul va fi suspendat").
    if (['medium', 'high'].includes(aiSignals.urgencyLevel)) {
        fragments.push('the text uses pressure or urgency');
    }

    // AI a detectat o cerere de date sensibile (parolă, cod OTP, card etc.).
    if (aiSignals.sensitiveDataRequest) {
        fragments.push('the message asks for sensitive information');
    }

    // AI a detectat un îndemn de tip "conectează-te acum" / "apasă aici urgent".
    if (aiSignals.loginOrActionRequest) {
        fragments.push('the message pushes you to sign in or act quickly');
    }

    // Semne de inginerie socială (manipulare psihologică) la nivel mediu/mare.
    if (['medium', 'high'].includes(aiSignals.socialEngineeringLevel)) {
        fragments.push('there are signs of social engineering');
    }

    // AI suspectează că emailul se dă drept un brand cunoscut (impersonare).
    if (aiSignals.brandImpersonationSuspected) {
        fragments.push('there are signs of brand impersonation');
    }

    // AI a rulat, dar nu a găsit niciun semnal relevant — spunem explicit asta.
    if (fragments.length === 0) {
        return 'The AI analysis did not add any strong risk signals.';
    }

    // Combinăm maximum 2 semnale într-o frază, ca explicația să rămână concisă.
    return `The AI analysis indicates that ${fragments.slice(0, 2).join(' and ')}.`;
};

// Construiește propoziția despre stratul "brand verificat" (vezi §4.4 din docs):
// dacă emailul vine de pe un domeniu oficial al unui brand cunoscut, explicăm
// userului că semnalele tipice de brand (urgență, multe linkuri, butoane "Sign in")
// au fost reduse pentru că sunt normale pentru acel brand.
const buildVerifiedBrandSentence = (senderVerifiedBrand, verifiedBrandName) => {
    if (!senderVerifiedBrand) {
        return '';
    }

    const brandLabel = verifiedBrandName ? ` of ${verifiedBrandName}` : '';

    return `This email comes from a verified official domain${brandLabel}, so brand-typical signals (urgency, links, sign-in prompts) were weighted down.`;
};

// Construiește propoziția despre stratul "liste de expeditori ale userului"
// (allowlist/blocklist — vezi §4.4 din docs). Dacă userul a blocat expeditorul,
// explicăm că verdictul e mereu "probabil phishing"; dacă l-a pus pe lista de
// încredere, explicăm că semnalele contextuale au fost reduse (dar nu cele critice).
const buildSenderListSentence = (senderListMatch) => {
    if (!senderListMatch) {
        return '';
    }

    // "domain" sau "sender" — în funcție de ce a blocat/permis userul.
    const target = senderListMatch.kind === 'domain' ? 'domain' : 'sender';

    if (senderListMatch.listType === 'block') {
        return `You blocked this ${target} (${senderListMatch.value}), so the email is always treated as likely phishing.`;
    }

    return `This ${target} (${senderListMatch.value}) is on your trusted list, so contextual signals were weighted down; critical signals like requests for passwords or dangerous attachments still count in full.`;
};

// Funcția principală: combină toate propozițiile de mai sus într-un singur text.
// Ordinea contează pentru cititor: întâi verdictul, apoi contextul (liste user,
// brand verificat), apoi regulile concrete declanșate, apoi semnalele AI.
export const buildControlledExplanation = ({
    verdict,
    triggeredRules,
    aiSignals,
    senderVerifiedBrand = false,
    verifiedBrandName = null,
    senderListMatch = null,
}) => {
    const sentences = [];

    // 1. Fraza de verdict (mereu prezentă; fallback pe "safe" dacă verdictul e necunoscut).
    sentences.push(verdictToSentence[verdict] || verdictToSentence.safe);

    // 2. Contextul listelor userului (allowlist/blocklist), dacă există.
    const senderListSentence = buildSenderListSentence(senderListMatch);
    if (senderListSentence) {
        sentences.push(senderListSentence);
    }

    // 3. Contextul de brand verificat, dacă există.
    const verifiedBrandSentence = buildVerifiedBrandSentence(
        senderVerifiedBrand,
        verifiedBrandName
    );
    if (verifiedBrandSentence) {
        sentences.push(verifiedBrandSentence);
    }

    // 4. Regulile deterministe declanșate (max 2 fraze, vezi buildRuleSentence).
    const ruleSentence = buildRuleSentence(triggeredRules);
    if (ruleSentence) {
        sentences.push(ruleSentence);
    }

    // 5. Semnalele AI, dacă AI a rulat cu succes.
    const aiSentence = buildAiSentence(aiSignals);
    if (aiSentence) {
        sentences.push(aiSentence);
    }

    // Toate fragmentele se unesc cu spațiu, formând paragraful final de explicație.
    return sentences.join(' ').trim();
};

// Înveleș simplu: scan.service.js salvează explicația ca obiect (cu cheia "summary"),
// nu ca string simplu — util pentru a putea extinde formatul mai târziu (ex: liste).
export const buildControlledExplanationObject = (input) => ({
    summary: buildControlledExplanation(input),
});
