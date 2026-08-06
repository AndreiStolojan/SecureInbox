// ─────────────────────────────────────────────────────────────────────────────
// scoring.config.js — REGULILE de detecție: singura sursă de adevăr pentru
// puncte, plafoane și praguri.
//
// Ce face, pe scurt: definește TOATE numerele folosite de motorul de scanare
// (scan.service.js) pentru a calcula scorul de risc al unui email și a-l
// transforma într-un verdict (safe / suspicious / likely_phishing). Conține:
//   - praguri de verdict (RISK_THRESHOLDS),
//   - punctele fiecărei reguli deterministe (RULE_WEIGHTS),
//   - punctele fiecărui semnal AI (AI_SIGNAL_WEIGHTS) + plafonul AI (AI_SCORE_MAX),
//   - două straturi de "context" care pot REDUCE (niciodată crește) punctele:
//     brand verificat (VERIFIED_BRAND_MODIFIERS) și liste ale userului
//     (USER_ALLOWLIST_MODIFIERS / USER_BLOCKLIST_RULE_POINTS).
//
// Modelul de scor: scorFinal = min(SCORE_MAX, scorReguli + scorAI), apoi
// RISK_THRESHOLDS traduce scorul în verdict. Scala e 0–100 (echivalent cu 1.0
// normalizat).
//
// Cele trei invariante (regulile de aur) care trebuie păstrate de orice modificare
// a numerelor de mai jos (vezi și docs/SCORING_WEIGHTS_REVIEW.md §4):
//   1. Niciun semnal singur nu atinge pragul HIGH_RISK (60).
//   2. Niciun semnal slab singur nu trece de banda MEDIUM (>=30).
//   3. AI singur nu poate declara phishing (AI_SCORE_MAX < pragul de 60);
//      pragul de 60 se atinge prin reguli doar dacă DOUĂ reguli forte se
//      confirmă reciproc (corroborare).
//
// Detalii: docs/EXPLICATIE_BACKEND.md §4.1, §4.3, §4.4.
// ─────────────────────────────────────────────────────────────────────────────

import {
    AI_SIGNAL_WEIGHTS,
    RULE_WEIGHTS,
} from '../detection/weights/index.js';

export {
    AI_SIGNAL_WEIGHTS,
    RULE_WEIGHTS,
};

// Capătul de sus al scalei 0–100. Scorul final e plafonat (clamp) la această valoare.
export const SCORE_MAX = 100;

// Pragurile care transformă scorul numeric în verdict. Sunt "blocate" de
// tests/unit/schema-contract.test.js — nu le schimbăm fără să actualizăm și testul.
export const RISK_THRESHOLDS = {
    suspicious: 30, // scor >= 30 -> "suspicious" (risc mediu)
    likelyPhishing: 60, // scor >= 60 -> "likely_phishing" (risc mare)
};

// Punctele regulilor sunt împărțite pe domenii în detection/weights/*.weights.js
// și reunite cu verificare de duplicate în detection/weights/index.js.

// Plafonul (cap) strict pentru contribuția AI la scorul final. Ținut sub
// RISK_THRESHOLDS.likelyPhishing (60) ca AI să poată RIDICA suspiciunea și
// confirma regulile, dar NICIODATĂ să nu poată declara singur "likely_phishing"
// fără ca regulile deterministe să fie de acord. Asta e invarianta #3 de mai sus.
export const AI_SCORE_MAX = 50;

// Plafonul AI când NICIO regulă deterministă nu s-a declanșat (scorReguli === 0).
// Invarianta #4, simetrică celor trei de mai sus: AI-ul singur, neconfirmat de
// nicio dovadă tehnică, nu poate scoate un email din banda "safe". Ținut STRICT
// sub RISK_THRESHOLDS.suspicious (30), nu egal, ca semnalele AI să rămână
// vizibile în interfață fără să schimbe singure verdictul.
//
// Motivul e măsurat, nu teoretic: pe qwen2.5:1.5b (modelul din deployment-ul
// Raspberry Pi), stratul semantic împingea singur 46% din mailurile benigne de
// evaluare peste pragul de 30. Un model local mic confirmă dovezi, nu le creează.
export const AI_UNCORROBORATED_SCORE_MAX = 25;

// Valoarea maximă de referință pentru bara de progres "scor reguli" din UI.
// scorReguli nu e plafonat individual în motor, dar folosește aceeași scală
// 0–100 ca scorul final — deci bara se desenează relativ la SCORE_MAX. Expus
// aici ca frontendul să nu "hardcodeze" o valoare separat.
export const RULE_SCORE_MAX = SCORE_MAX;

/*
 * ── Stratul de modificatori pentru "brand verificat" ───────────────────────────
 *
 * Acestea sunt MULTIPLICATORI DE CONTEXT, nu greutăți noi. Se aplică PESTE
 * greutățile de bază de mai sus, DOAR când verificarea de brand a expeditorului
 * a reușit (senderVerifiedBrand === true — vezi brand-verification.service.js).
 * Greutățile de bază din RULE_WEIGHTS / AI_SIGNAL_WEIGHTS nu sunt modificate
 * niciodată; motorul citește greutatea de bază și o înmulțește prin
 * applyVerifiedBrandModifier() în momentul în care o regulă se declanșează.
 *
 * Raționament: când un email vine cu adevărat de pe domeniul propriu al unui
 * brand, semnale care par suspecte în abstract (urgență, multe linkuri, un
 * buton "Sign in", reply-uri redirecționate către un domeniu de suport/ESP)
 * sunt EXACT cum arată mailul real, tranzacțional sau de marketing, al acelui
 * brand. Aici sunt dovezi mult mai slabe, deci le reducem. Un multiplicator pe
 * fiecare semnal ține reducerea auditabilă și într-un singur loc.
 *
 *   cheie                         multiplicator  efect pe un email de brand verificat
 *   ───────────────────────────── ─────────────  ───────────────────────────────────────
 *   brand_impersonation_suspected  0.0   anulat — a venit chiar de la brandul real
 *   login_or_action_request        0.3   butoanele CTA sunt standard în mailul de brand
 *   too_many_links_high            0.4   newsletterele de brand au, în mod normal, multe linkuri
 *   too_many_links_medium          0.4   la fel
 *   urgency_high                   0.5   companiile reale trimit și alerte de cont/securitate
 *   urgency_medium                 0.5   la fel
 *   social_engineering_high        0.5   se suprapune cu "alerta de cont" de mai sus
 *   social_engineering_medium      0.5   la fel
 *   reply_to_mismatch              0.5   brandurile verificate despart frecvent domeniul de trimitere de cel de reply
 *
 * Semnale lăsate INTENȚIONAT la greutate plină pentru branduri verificate (NU apar
 * în tabelul de mai jos):
 *   - sensitive_data_request — un brand real nu cere parola/OTP/cardul prin email;
 *     rămâne semnal de top chiar și de la un expeditor "verificat" (acoperă conturi
 *     compromise și orice spoofing pe care verificarea de domeniu nu-l prinde).
 *   - shortened_url_detected — mailul controlat de brand rareori are nevoie de un
 *     link scurtat (bit.ly).
 *   - ip_address_link, embedded_credentials, punycode_domain, very_long_url,
 *     high_risk_attachment_extension, archive_attachment_extension — semnale de
 *     transport/payload care sunt anormale indiferent cine pretinde că trimite.
 *
 * Nu există în acest motor o regulă "mult HTML / multe imagini" sau "salut generic",
 * deci rândurile pentru ele din cerință nu au o greutate de modificat (documentat,
 * nu inventat — a adăuga o astfel de penalizare ar crea doar fals-pozitive noi
 * pentru mailul neverificat).
 */
export const VERIFIED_BRAND_MODIFIERS = {
    brand_impersonation_suspected: 0,
    login_or_action_request: 0.3,
    too_many_links_high: 0.4,
    too_many_links_medium: 0.4,
    urgency_high: 0.5,
    urgency_medium: 0.5,
    social_engineering_high: 0.5,
    social_engineering_medium: 0.5,
    reply_to_mismatch: 0.5,
};

/*
 * Aplică modificatorul de context "brand verificat" peste o greutate de bază.
 *   - Nu e email de brand verificat → punctele de bază rămân neschimbate.
 *   - Verificat, dar semnalul nu e în tabelul de modificatori → punctele de bază
 *     rămân neschimbate (greutate plină).
 *   - Verificat și semnalul e în tabel → puncte reduse, rotunjite (0 = anulat).
 * Greutățile de bază sunt citite doar (read-only) aici; funcția doar scalează
 * punctele pe care le contribuie o regulă.
 */
export const applyVerifiedBrandModifier = (signalKey, basePoints, { senderVerifiedBrand } = {}) => {
    if (!senderVerifiedBrand) {
        return basePoints;
    }

    const multiplier = VERIFIED_BRAND_MODIFIERS[signalKey];

    if (multiplier === undefined) {
        return basePoints;
    }

    return Math.round(basePoints * multiplier);
};

/*
 * ── Stratul listelor de expeditori ale userului (allowlist / blocklist) ────────
 *
 * Diferit de toate greutățile de mai sus, acestea codifică o DECIZIE EXPLICITĂ A
 * USERULUI, nu o euristică. De aceea greutatea blocklist-ului trăiește separat de
 * RULE_WEIGHTS: invarianta "niciun semnal singur nu atinge HIGH_RISK" se aplică
 * euristicilor de detecție, care pot greși; dar un user care spune "blochează acest
 * expeditor" nu e o euristică — i se permite să decidă singur verdictul.
 *
 * Blocklist — prag minim garantat (hard floor). Regula contribuie EXACT pragul
 * likely_phishing, deci un expeditor/domeniu blocat are GARANTAT acest verdict
 * prin construcție (legarea de RISK_THRESHOLDS păstrează garanția chiar dacă
 * pragurile se schimbă vreodată). Semnalele reale se adună tot pe deasupra, deci
 * scorul rămâne informativ.
 *
 * Allowlist — reducere puternică, dar NU "sigur" garantat. Userul are încredere în
 * expeditor, deci semnalele CONTEXTUALE (urgență, număr de linkuri, butoane CTA,
 * discrepanțe reply-to) sunt reduse. Semnalele de PAYLOAD care indică un cont de
 * încredere compromis sau falsificat rămân la greutate plină:
 *   - sensitive_data_request (un expeditor de încredere tot nu cere parole/OTP)
 *   - high_risk_attachment_extension, ip_address_link, embedded_credentials,
 *     punycode_domain — anormale la nivel de transport/payload, indiferent de încredere.
 * Acest strat e intenționat MAI PUTERNIC decât stratul "brand verificat" (intenția
 * userului bate reputația domeniului), dar niciodată mai slab decât el: motorul
 * folosește multiplicatorul MINIM când ambele se aplică.
 */
export const USER_BLOCKLIST_RULE_POINTS = RISK_THRESHOLDS.likelyPhishing;

export const USER_ALLOWLIST_MODIFIERS = {
    reply_to_mismatch: 0,
    too_many_links_high: 0,
    too_many_links_medium: 0,
    very_long_url: 0,
    shortened_url_detected: 0,
    archive_attachment_extension: 0.5,
    urgency_high: 0,
    urgency_medium: 0,
    login_or_action_request: 0,
    social_engineering_high: 0.5,
    social_engineering_medium: 0.5,
    brand_impersonation_suspected: 0,
};

/*
 * Modificatorul de context combinat: aplică straturile "brand verificat" și
 * "allowlist al userului" împreună, luând multiplicatorul MINIM (reducerile nu
 * se cumulează multiplicativ, iar un strat poate doar reduce o greutate, niciodată
 * să o crească).
 */
export const applyScoreContextModifiers = (signalKey, basePoints, context = {}) => {
    let multiplier = 1;

    // Dacă emailul e de la un brand verificat și acest semnal are un modificator
    // definit, folosim modificatorul (dar doar dacă e mai mic decât ce avem deja).
    if (context.senderVerifiedBrand && VERIFIED_BRAND_MODIFIERS[signalKey] !== undefined) {
        multiplier = Math.min(multiplier, VERIFIED_BRAND_MODIFIERS[signalKey]);
    }

    // Același lucru pentru allowlist-ul userului.
    if (context.senderAllowlisted && USER_ALLOWLIST_MODIFIERS[signalKey] !== undefined) {
        multiplier = Math.min(multiplier, USER_ALLOWLIST_MODIFIERS[signalKey]);
    }

    // Niciun strat nu s-a aplicat → punctele de bază rămân neschimbate.
    if (multiplier === 1) {
        return basePoints;
    }

    return Math.round(basePoints * multiplier);
};
