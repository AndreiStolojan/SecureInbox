// ─────────────────────────────────────────────────────────────────────────────
// brand-verification.service.js — primul strat de context peste motorul de reguli:
// verificarea brandului expeditorului.
//
// Ce face, pe scurt: verifică dacă un email vine CHIAR de pe domeniul oficial al
// unui brand cunoscut (ex: paypal.com). Dacă da, motorul de scanare (scan.service.js)
// (1) nu mai dă puncte pentru "impersonare de brand", (2) reduce greutatea unor
// semnale care la un brand real sunt normale (urgență, multe linkuri, buton
// "Sign in"), și (3) spune promptului Ollama să nu mai caute impersonare, ci să se
// concentreze pe semnale reale de risc din conținut.
//
// De ce verificăm pe DOMENIUL expeditorului și nu pe textul din email? Pentru că
// domeniul de trimitere e singurul lucru pe care un atacator NU îl poate falsifica
// pentru un domeniu controlat de brand. Dacă în text e scris "PayPal" dar domeniul
// e paypal-secure.ru (impersonare prin text), asta rămâne în grija semnalului AI de
// impersonare din Ollama, care rulează doar când expeditorul NU e verificat aici.
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    BRAND_OFFICIAL_DOMAINS,
    CONSUMER_MAILBOX_DOMAINS,
} from '../config/brand-domains.config.js';

// Normalizează un domeniu pentru comparație: litere mici, fără spații, fără
// prefixul "www." și fără punctul final (ex: "WWW.PayPal.com." -> "paypal.com").
const normalizeDomain = (value) =>
    String(value || '')
        .trim()
        .toLowerCase()
        .replace(/^www\./, '')
        .replace(/\.$/, '');

// Comparație "suffix-aware" (ține cont de sufix): domeniul expeditorului se
// potrivește dacă e identic cu domeniul oficial SAU dacă e un subdomeniu al lui
// (ex: "mail.paypal.com" se potrivește cu "paypal.com"). Asta ne protejează de
// domenii care doar "par" la fel: "evil-paypal.com" și "paypal.com.evil.com" NU
// se potrivesc cu "paypal.com" (nu sunt subdomenii reale).
const domainMatches = (senderDomain, officialDomain) =>
    senderDomain === officialDomain ||
    senderDomain.endsWith(`.${officialDomain}`);

// Domeniile de mail "de consum" (gmail.com, yahoo.com etc.) nu pot fi niciodată
// un semnal de încredere pentru un brand — oricine își poate face un cont gratuit
// acolo, deci nu dovedesc nimic despre identitatea expeditorului.
const isConsumerMailbox = (senderDomain) =>
    [...CONSUMER_MAILBOX_DOMAINS].some((consumerDomain) =>
        domainMatches(senderDomain, consumerDomain));

// Rezultatul standard pentru "nu e un brand verificat" — păstrăm aceeași formă
// a obiectului în toate cazurile de "nu", ca să fie simplu de folosit mai departe.
const buildUnverifiedResult = (senderDomain) => ({
    senderVerifiedBrand: false,
    brandState: 'unknown',
    brandMatch: false,
    authenticationStatus: 'unavailable',
    brandKey: null,
    brandName: null,
    matchedDomain: null,
    officialDomains: [],
    senderDomain,
});

/*
 * @param {{ senderDomain?: string }} câmpuri derivate din email
 * @returns {{
 *   senderVerifiedBrand: boolean,
 *   brandKey: string|null,
 *   brandName: string|null,
 *   matchedDomain: string|null,
 *   officialDomains: string[],
 *   senderDomain: string,
 * }}
 */
// Funcția principală a fișierului: primește domeniul expeditorului și spune dacă
// e un domeniu oficial al unui brand cunoscut din config/brand-domains.config.js.
export const verifySenderBrand = ({ senderDomain, authResults } = {}) => {
    const normalizedSenderDomain = normalizeDomain(senderDomain);

    // Fără domeniu -> nu putem verifica nimic.
    if (!normalizedSenderDomain) {
        return buildUnverifiedResult('');
    }

    // Domeniile de mail gratuite/personale nu sunt un semnal de încredere de brand.
    if (isConsumerMailbox(normalizedSenderDomain)) {
        return buildUnverifiedResult(normalizedSenderDomain);
    }

    // Parcurgem lista de branduri cunoscute și domeniile lor oficiale; la prima
    // potrivire (suffix-aware) marcăm emailul ca venind de la un brand verificat.
    for (const [brandKey, brand] of Object.entries(BRAND_OFFICIAL_DOMAINS)) {
        for (const officialDomain of brand.domains) {
            if (domainMatches(normalizedSenderDomain, officialDomain)) {
                const dmarcResult = authResults?.dmarc;
                const dmarcPassesWithAlignment =
                    authResults?.status === 'ok' &&
                    dmarcResult?.result === 'pass' &&
                    ['strict', 'relaxed'].includes(dmarcResult.alignment);
                const authenticationStatus = dmarcPassesWithAlignment
                    ? 'pass'
                    : authResults && authResults.status !== 'unavailable'
                        ? 'fail'
                        : 'unavailable';

                return {
                    senderVerifiedBrand: dmarcPassesWithAlignment,
                    brandState: dmarcPassesWithAlignment
                        ? 'verified'
                        : 'claimed_unauthenticated',
                    brandMatch: true,
                    authenticationStatus,
                    brandKey,
                    brandName: brand.displayName,
                    matchedDomain: officialDomain,
                    officialDomains: brand.domains,
                    senderDomain: normalizedSenderDomain,
                };
            }
        }
    }

    // Niciun brand cunoscut nu se potrivește -> expeditor neverificat.
    return buildUnverifiedResult(normalizedSenderDomain);
};
