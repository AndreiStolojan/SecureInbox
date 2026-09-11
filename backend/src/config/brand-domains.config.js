// ─────────────────────────────────────────────────────────────────────────────
// brand-domains.config.js — lista domeniilor oficiale ale brandurilor cunoscute.
//
// Ce face, pe scurt: definește, pentru câteva branduri mari (PayPal, Google,
// Amazon, Microsoft etc.), care domenii sunt deținute/controlate CHIAR de brand.
// Motorul de scanare (prin brand-verification.service.js) verifică dacă domeniul
// expeditorului se potrivește cu unul din această listă (verificare "suffix-aware":
// mail.paypal.com se potrivește cu paypal.com, dar evil-paypal.com și
// paypal.com.evil.com NU se potrivesc). Dacă da, emailul e tratat ca
// "brand verificat" — vezi scoring.config.js (VERIFIED_BRAND_MODIFIERS), care
// reduce anumite semnale de risc pentru mailul real al brandului.
//
// REGULA DE DESIGN importantă: aici intră DOAR domenii pe care brandul le
// controlează exclusiv (paypal.com, accounts.google.com, amazon.com,
// microsoft.com, apple.com...) — un atacator nu le poate obține. Domeniile de
// mailbox de consum (gmail.com, outlook.com, yahoo.com...) sunt EXCLUSE
// INTENȚIONAT mai jos, în CONSUMER_MAILBOX_DOMAINS, pentru că oricine își poate
// face un cont gratuit acolo — a le trata ca "verificat Google" ar fi o gaură de
// securitate (un atacator ar trimite phishing de pe un @gmail.com și ar primi
// reducerea de scor a unui brand verificat).
//
// Lista e intenționat neexhaustivă — conține brandurile întâlnite cel mai des în
// mailul tranzacțional/marketing legitim care era fals marcat ca suspect. Se pot
// adăuga branduri/domenii noi aici fără să se schimbe vreun cod de regulă.
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

// Harta brand -> { nume afișat, listă de domenii oficiale }. Fiecare grup de mai
// jos corespunde unui brand cunoscut, des întâlnit în mailul legitim.
export const BRAND_OFFICIAL_DOMAINS = {
    paypal: {
        displayName: 'PayPal',
        domains: [
            'paypal.com',
            'paypal.co.uk',
            'paypal.de',
            'paypal.fr',
            'paypal.es',
            'paypal.it',
            'paypal.me',
            'paypalobjects.com',
        ],
    },
    google: {
        displayName: 'Google',
        domains: [
            'google.com',
            'accounts.google.com',
            'mail.google.com',
            'docs.google.com',
            'drive.google.com',
            'youtube.com',
            // NOTĂ: gmail.com / googlemail.com sunt mailbox-uri de consum — vezi lista de exclus.
        ],
    },
    amazon: {
        displayName: 'Amazon',
        domains: [
            'amazon.com',
            'amazon.co.uk',
            'amazon.de',
            'amazon.fr',
            'amazon.es',
            'amazon.it',
            'amazon.ca',
            'amazon.in',
            'amazon.co.jp',
            // NOTĂ: amazonses.com e EXCLUS intenționat — e infrastructura partajată AWS SES,
            // prin care poate trimite orice client AWS, nu un domeniu controlat de brand.
            // Includerea lui ar permite unui atacator de pe SES să fie "verificat" ca Amazon.
        ],
    },
    microsoft: {
        displayName: 'Microsoft',
        domains: [
            'microsoft.com',
            'microsoftonline.com',
            'office.com',
            'office365.com',
            'microsoft365.com',
            'azure.com',
            'windows.com',
            'microsoftstore.com',
            'accountprotection.microsoft.com',
            'email.microsoft.com',
            // NOTĂ: outlook.com / live.com / hotmail.com sunt mailbox-uri de consum — excluse.
        ],
    },
    apple: {
        displayName: 'Apple',
        domains: [
            'apple.com',
            'id.apple.com',
            'email.apple.com',
            'itunes.com',
            // NOTĂ: icloud.com / me.com / mac.com sunt mailbox-uri de consum — excluse.
        ],
    },
    netflix: {
        displayName: 'Netflix',
        domains: ['netflix.com', 'netflix.net', 'mailer.netflix.com'],
    },
    meta: {
        displayName: 'Meta / Facebook',
        domains: [
            'facebook.com',
            'facebookmail.com',
            'fb.com',
            'meta.com',
            'instagram.com',
            'mail.instagram.com',
        ],
    },
    linkedin: {
        displayName: 'LinkedIn',
        domains: ['linkedin.com', 'e.linkedin.com'],
    },
    dhl: {
        displayName: 'DHL',
        domains: ['dhl.com', 'dhl.de'],
    },
    fedex: {
        displayName: 'FedEx',
        domains: ['fedex.com'],
    },
    ups: {
        displayName: 'UPS',
        domains: ['ups.com'],
    },
};

// Domenii de furnizori de mailbox pentru consumatori. Oricine poate avea o adresă
// aici, deci o potrivire NU e un semnal de încredere de brand. Logica de verificare
// nu trebuie NICIODATĂ să trateze un expeditor de pe unul din aceste domenii (sau
// subdomeniu al lor) ca "brand verificat", indiferent de listele de mai sus.
export const CONSUMER_MAILBOX_DOMAINS = new Set([
    'gmail.com',
    'googlemail.com',
    'outlook.com',
    'hotmail.com',
    'live.com',
    'msn.com',
    'icloud.com',
    'me.com',
    'mac.com',
    'yahoo.com',
    'ymail.com',
    'aol.com',
    'proton.me',
    'protonmail.com',
    'gmx.com',
    'gmx.net',
    'zoho.com',
]);
