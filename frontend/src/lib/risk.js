// ─────────────────────────────────────────────────────────────────────────────
// risk.js — sursa unică de adevăr pentru cum arată riscul în UI.
//
// Ce face, pe scurt: backend-ul trimite două câmpuri pentru fiecare email:
//   - riskBucket: safe | needs_review | quarantine | reviewed_safe |
//                 confirmed_phishing | unscanned
//   - effectiveVerdict: safe | suspicious | likely_phishing | phishing | null
// Acest fișier mapează fiecare valoare la o "meta" (etichetă, descriere, ton —
// adică icon + clase de culoare). Toate badge-urile, bannerele, graficele și
// filtrele citesc culorile/etichetele de aici, ca aspectul să fie consistent
// peste tot. Tot aici sunt și etichetele/descrierile prietenoase pentru regulile
// de detecție (transformă un cod tehnic ca
// "suspicious_link_pattern:ip_address_link" în text ușor de citit pentru user).
//
// Detalii: docs/EXPLICATIE_FRONTEND.md §6.1.
// ─────────────────────────────────────────────────────────────────────────────

import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  AlertTriangle,
  HelpCircle,
} from 'lucide-react';

// TONES = "tonurile" vizuale posibile pentru un risc: icon, clase Tailwind
// pentru text/fundal/bordură, plus un "hex" care e de fapt o variabilă CSS
// (--color-risk-*) definită în index.css — nu există culori hardcodate aici.
// Cele 4 tonuri (safe/review/quarantine/phishing) + unscanned sunt distincte
// pe tema întunecată (verde / chihlimbar / roz / violet / gri), verificate să
// respecte contrastul WCAG 2.1 AA (accesibilitate = text lizibil pentru toți).
const TONES = {
  safe: {
    icon: ShieldCheck,
    emphasis: 'quiet',
    text: 'text-risk-safe',
    soft: 'bg-risk-safe-soft text-risk-safe border border-risk-safe/30',
    dot: 'bg-risk-safe',
    bar: 'bg-risk-safe',
    hex: 'var(--color-risk-safe)',
  },
  review: {
    icon: AlertTriangle,
    emphasis: 'loud',
    text: 'text-risk-review',
    soft: 'bg-risk-review-soft text-risk-review border border-risk-review/30',
    dot: 'bg-risk-review',
    bar: 'bg-risk-review',
    hex: 'var(--color-risk-review)',
  },
  quarantine: {
    icon: ShieldAlert,
    emphasis: 'loud',
    text: 'text-risk-quarantine',
    soft: 'bg-risk-quarantine-soft text-risk-quarantine border border-risk-quarantine/30',
    dot: 'bg-risk-quarantine',
    bar: 'bg-risk-quarantine',
    hex: 'var(--color-risk-quarantine)',
  },
  phishing: {
    icon: ShieldX,
    emphasis: 'loud',
    text: 'text-risk-phishing',
    soft: 'bg-risk-phishing-soft text-risk-phishing border border-risk-phishing/30',
    dot: 'bg-risk-phishing',
    bar: 'bg-risk-phishing',
    hex: 'var(--color-risk-phishing)',
  },
  unscanned: {
    icon: HelpCircle,
    emphasis: 'quiet',
    text: 'text-risk-unscanned',
    soft: 'bg-risk-unscanned-soft text-risk-unscanned border border-risk-unscanned/30',
    dot: 'bg-risk-unscanned',
    bar: 'bg-risk-unscanned',
    hex: 'var(--color-risk-unscanned)',
  },
};

// RISK_BUCKET_META — pentru fiecare valoare posibilă a câmpului `riskBucket`
// (categoria vizuală a unui email), ce etichetă și ce descriere se arată, și
// cu ce ton (din TONES de mai sus). "reviewed_safe" și "confirmed_phishing"
// sunt cazurile în care USERUL a decis manual (vezi §6.4 din docs).
const RISK_BUCKET_META = {
  safe: { label: 'Safe', tone: TONES.safe, description: 'No threats detected in this email.' },
  reviewed_safe: {
    label: 'Reviewed safe',
    tone: TONES.safe,
    description: 'You confirmed this email is safe.',
  },
  needs_review: {
    label: 'Suspicious',
    tone: TONES.review,
    description: 'This email has suspicious patterns — worth a closer look.',
  },
  quarantine: {
    label: 'Likely phishing',
    tone: TONES.quarantine,
    description: 'This email looks like phishing. Review it before taking any action.',
  },
  confirmed_phishing: {
    label: 'Confirmed phishing',
    tone: TONES.phishing,
    description: 'You marked this email as phishing.',
  },
  unscanned: {
    label: 'Unscanned',
    tone: TONES.unscanned,
    description: 'This email has not been scanned yet.',
  },
};

// VERDICT_META — la fel ca mai sus, dar pentru câmpul `effectiveVerdict`
// (verdictul tehnic/efectiv al scanului, nu categoria vizuală "bucket").
const VERDICT_META = {
  safe: { label: 'Safe', tone: TONES.safe },
  suspicious: { label: 'Suspicious', tone: TONES.review },
  likely_phishing: { label: 'Likely phishing', tone: TONES.quarantine },
  phishing: { label: 'Phishing', tone: TONES.phishing },
};

// Valoare implicită folosită când riskBucket nu se potrivește cu nimic cunoscut.
const UNKNOWN = {
  label: 'Unknown',
  tone: TONES.unscanned,
  description: '',
};

// CATEGORY_COLORS — sursa unică de adevăr pentru culoarea fiecărei categorii de
// date de phishing, folosită oriunde se desenează aceleași categorii: trendul
// + donutul de risc din dashboard, defalcarea din rapoarte și badge-urile din
// inbox.
//
// Cheile sunt id-urile canonice ale categoriilor. Fiecare grafic își mapează
// propriul nume local de câmp (ex: `needs_review`, `quarantine`,
// `likelyPhishing`) la una din aceste chei, ca o categorie să fie desenată
// mereu cu aceeași culoare în toată aplicația. Valorile sunt variabilele CSS
// stabile `--color-risk-*` din index.css, deci nu există valori hex duplicate
// sau care pot "deriva" (să devină diferite în timp).
//
// Cele 4 culori sunt nuanțe distincte deliberat pe tema întunecată folosită de
// aplicație: verde / chihlimbar / roz / violet. Aplicația e doar pe temă
// întunecată, deci se țintește doar fundalul dark (vezi PROJECT_STATE.md).
export const CATEGORY_COLORS = {
  safe: 'var(--color-risk-safe)',
  suspicious: 'var(--color-risk-review)',
  likely_phishing: 'var(--color-risk-quarantine)',
  confirmed_phishing: 'var(--color-risk-phishing)',
  unscanned: 'var(--color-risk-unscanned)',
};

// Etichetele afișate pentru fiecare categorie din CATEGORY_COLORS de mai sus.
export const CATEGORY_LABELS = {
  safe: 'Safe',
  suspicious: 'Suspicious',
  likely_phishing: 'Likely phishing',
  confirmed_phishing: 'Confirmed phishing',
  unscanned: 'Unscanned',
};

// Întoarce "meta" (etichetă, descriere, ton) pentru un `riskBucket`. Dacă
// valoarea nu e cunoscută, întoarce UNKNOWN — așa nu pică UI-ul dacă backend-ul
// trimite o valoare nouă/necunoscută.
export const getRiskMeta = (riskBucket) => RISK_BUCKET_META[riskBucket] || UNKNOWN;

// Întoarce "meta" pentru un `effectiveVerdict`. Dacă verdictul e null/necunoscut
// (emailul nu a fost încă scanat), arată "No verdict" cu tonul "unscanned".
export const getVerdictMeta = (verdict) =>
  VERDICT_META[verdict] || { label: 'No verdict', tone: TONES.unscanned };

/** Chipurile de filtrare din inbox, în ordinea priorității de afișare. */
export const RISK_FILTERS = [
  { key: '', label: 'All' },
  { key: 'quarantine', label: 'Likely phishing' },
  { key: 'needs_review', label: 'Suspicious' },
  { key: 'confirmed_phishing', label: 'Confirmed phishing' },
  { key: 'safe', label: 'Safe' },
];

// Transformă un enum snake_case într-o etichetă lizibilă, ca ultimă soluție
// (fallback) — ex: "needs_review" -> "Needs review".
export const humanize = (value) => {
  if (!value) return '';
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
};

// RULE_LABELS — denumiri scurte, prietenoase, pentru fiecare cod de regulă din
// motorul de scanare (vezi scan.service.js / scoring.config.js din backend).
// Folosite în grafice și tooltip-uri, ca userul să vadă "Shortened link" în
// loc de "shortened_url_detected".
const RULE_LABELS = {
  user_blocklist_match: 'Blocked by you',
  reply_to_mismatch: 'Reply address differs',
  shortened_url_detected: 'Shortened link',
  'suspicious_link_pattern:ip_address_link': 'Link uses IP address',
  'suspicious_link_pattern:embedded_credentials': 'Login details in link',
  'suspicious_link_pattern:punycode_domain': 'Lookalike domain',
  'suspicious_link_pattern:very_long_url': 'Unusually long link',
  high_risk_attachment_extension: 'Dangerous attachment',
  archive_attachment_extension: 'Archive attachment',
  attachment_known_malware_hash: 'Known malware',
  attachment_type_mismatch_dangerous: 'Disguised executable',
  attachment_encrypted_archive_with_password_in_body: 'Password-protected archive',
  attachment_double_extension: 'Misleading double extension',
  attachment_rtl_override_filename: 'Misleading filename direction',
  attachment_macro_enabled_office: 'Office macros detected',
  attachment_pdf_openaction_javascript: 'PDF runs JavaScript on open',
  attachment_encrypted_archive: 'Encrypted archive',
  attachment_nested_archive: 'Nested archive',
  attachment_type_mismatch_suspicious: 'File type mismatch',
  attachment_zip_bomb_ratio: 'Unsafe compression ratio',
  attachment_dangerous_archive_entry: 'Dangerous file inside archive',
  attachment_archive_path_traversal: 'Unsafe archive path',
  attachment_pdf_external_uri: 'PDF links outside sender domain',
  attachment_legacy_office_unverified: 'Legacy Office document',
  too_many_links_high: 'Too many links',
  too_many_links_medium: 'Too many links',
  'ai_semantic:urgency_high': 'Urgency language',
  'ai_semantic:urgency_medium': 'Urgency language',
  'ai_semantic:sensitive_data_request': 'Asks for personal info',
  'ai_semantic:login_or_action_request': 'Pressures to act',
  'ai_semantic:social_engineering_high': 'Social engineering',
  'ai_semantic:social_engineering_medium': 'Social engineering',
  'ai_semantic:brand_impersonation_suspected': 'Brand impersonation',
  // Sender authentication (email_auth provider). Without these the fallback
  // renders the raw rule id — "Email Auth Dmarc Fail Policy Reject".
  'email_auth:dmarc_fail_policy_reject': 'Sender authentication failed',
  'email_auth:dmarc_fail_policy_quarantine': 'Sender authentication failed',
  'email_auth:dmarc_fail_policy_none': 'Sender authentication failed',
  'email_auth:spf_hardfail': 'Unauthorised sending server',
  'email_auth:dkim_invalid_signature': 'Invalid sender signature',
  'email_auth:no_authentication_at_all': 'Unverified sender',
  'email_auth:claimed_brand_authentication_failed': 'Unverified brand claim',
  // Threat intelligence provider. Same problem: the fallback produced strings
  // like "Threat Intelligence Domain Registered Days Ago Lt 7".
  'threat_intelligence:url_known_malicious': 'Known malicious link',
  'threat_intelligence:url_known_phishing_campaign': 'Known phishing link',
  'threat_intelligence:domain_registered_days_ago_lt_7': 'Very new linked domain',
  'threat_intelligence:domain_registered_days_ago_lt_30': 'Recently created linked domain',
  'threat_intelligence:link_text_href_mismatch': 'Link text hides destination',
  'threat_intelligence:redirect_chain_to_different_tld': 'Link redirects elsewhere',
  'threat_intelligence:excessive_redirect_chain': 'Long redirect chain',
  'threat_intelligence:redirect_to_private_address': 'Link redirects to private address',
};

// Întoarce eticheta prietenoasă pentru un cod de regulă. Dacă nu e în
// RULE_LABELS, dar e un subtip de "suspicious_link_pattern", arată generic
// "Suspicious link". În rest, face un fallback generic: scoate prefixul
// "ai_semantic:" și sufixul de severitate (_high/_medium/_low), înlocuiește
// "_"/":" cu spațiu și pune Title Case (prima literă din fiecare cuvânt mare).
export const getRuleLabel = (rule) => {
  const key = String(rule || '');
  if (RULE_LABELS[key]) return RULE_LABELS[key];
  if (key.startsWith('suspicious_link_pattern:')) return 'Suspicious link';
  return key
    .replace(/^ai_semantic:/, '')
    .replace(/_(high|medium|low)$/, '')
    .replace(/[_:]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
};

// Descrieri scurte, în limbaj uman, pentru cele mai comune coduri de regulă —
// folosite în legenda "Most common warning signs" din dashboard. Dacă o regulă
// nu e în listă, getRuleDescription() de mai jos face un fallback generic.
const RULE_DESCRIPTIONS = {
  reply_to_mismatch: 'Reply address differs from the sender — a common phishing trick',
  shortened_url_detected: 'Email contains shortened links that hide the real destination',
  too_many_links_high: 'Unusually high number of links in the message',
  too_many_links_medium: 'Higher than normal number of links in the message',
  high_risk_attachment_extension: 'Attachment has a file type that could be used to install malware (.exe, .bat, etc.)',
  archive_attachment_extension: 'Attachment is a compressed archive that may hide malicious files (.zip, .rar, etc.)',
  'suspicious_link_pattern:ip_address_link': 'A link points to a raw IP address instead of a normal website name',
  'suspicious_link_pattern:embedded_credentials': 'A link contains login details — a strong sign of phishing',
  'suspicious_link_pattern:punycode_domain': 'A link uses a lookalike web address that imitates a real brand',
  'suspicious_link_pattern:very_long_url': 'A link is unusually long, which can hide where it really leads',
  'ai_semantic:urgency_high': 'AI detected language designed to create panic and rush you into acting',
  'ai_semantic:urgency_medium': 'AI detected words pressuring you to act immediately',
  'ai_semantic:social_engineering_high': 'AI detected manipulative tactics — using fear, authority, or rewards to trick you',
  'ai_semantic:social_engineering_medium': 'AI detected some manipulation tactics in the email',
  'ai_semantic:login_or_action_request': 'AI detected language pushing you to click a link or sign in right away',
  'ai_semantic:sensitive_data_request': 'AI detected a request for your password, payment details, or personal codes',
  'ai_semantic:brand_impersonation_suspected': 'AI suspects this email is impersonating a company or brand you know',
  'email_auth:dmarc_fail_policy_reject': 'The sender domain rejects unauthenticated mail, and this message failed that check',
  'email_auth:dmarc_fail_policy_quarantine': 'The sender domain asks that unauthenticated mail be quarantined, and this message failed that check',
  'email_auth:dmarc_fail_policy_none': 'This message did not pass the sender domain’s authentication checks',
  'email_auth:spf_hardfail': 'The server that sent this message is not authorised to send for the sender domain',
  'email_auth:dkim_invalid_signature': 'The message carries a cryptographic signature that does not verify',
  'email_auth:no_authentication_at_all': 'The sender provided no way to verify that this message really came from them',
  'email_auth:claimed_brand_authentication_failed': 'The sender claims a known brand, but could not prove it owns that domain',
  'threat_intelligence:url_known_malicious': 'A link matches a threat intelligence source for malware',
  'threat_intelligence:url_known_phishing_campaign': 'A link matches a known phishing campaign',
  'threat_intelligence:domain_registered_days_ago_lt_7': 'A linked domain was registered in the last week — common for throwaway phishing sites',
  'threat_intelligence:domain_registered_days_ago_lt_30': 'A linked domain was registered within the last month',
  'threat_intelligence:link_text_href_mismatch': 'A link displays one address but actually leads somewhere else',
  'threat_intelligence:redirect_chain_to_different_tld': 'A link redirects to a different site than the sender’s',
  'threat_intelligence:excessive_redirect_chain': 'A link passes through an unusually long chain of redirects',
  'threat_intelligence:redirect_to_private_address': 'A link redirects to a private network address',
};

export const getRuleDescription = (rule) => {
  const key = String(rule || '');
  if (RULE_DESCRIPTIONS[key]) return RULE_DESCRIPTIONS[key];
  // Orice alt subtip de "suspicious link": text prietenos, niciodată codul brut al pattern-ului.
  if (key.startsWith('suspicious_link_pattern:')) {
    return 'A link in the email looks suspicious';
  }
  // Fallback generic: scoate eventualul prefix AI și sufixul de severitate, apoi Title Case.
  return key
    .replace(/^ai_semantic:/, '')
    .replace(/_(high|medium|low)$/, '')
    .replace(/[_:]/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
};
