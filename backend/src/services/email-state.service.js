// ─────────────────────────────────────────────────────────────────────────────
// email-state.service.js — "starea finală" a unui email, pentru UI.
//
// Ce face, pe scurt: scanul (vezi scan.service.js) dă un verdict TEHNIC
// (safe / suspicious / likely_phishing / niciun scan). Dar utilizatorul poate
// decide manual altceva ("Mark safe" / "Mark as phishing"), iar decizia lui
// trebuie să "câștige" peste scan. Acest fișier combină cele două verdicte
// (al scanului + al userului) într-o singură "stare finală" pe care o citește
// frontendul: ce verdict să arate (`effectiveVerdict`), în ce categorie vizuală
// (`riskBucket`) și dacă emailul mai are nevoie de atenția userului
// (`reviewStatus`).
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

// Calculează starea de "review" a unui email, combinând:
//   - `email.userVerdict`  — decizia manuală a userului (sau null, dacă nu a decis nimic);
//   - `latestScan.verdict` — verdictul tehnic al ultimei scanări (sau null, dacă emailul
//     nu a fost încă scanat).
//
// Ordinea verificărilor de mai jos ESTE prioritatea: decizia userului (safe/phishing)
// învinge mereu verdictul scanului. Abia dacă userul nu a decis nimic, ne uităm la
// verdictul scanului.
export const deriveEmailReviewState = ({ email, latestScan }) => {
    const userVerdict = email?.userVerdict || null;
    const scanVerdict = latestScan?.verdict || null;

    // Cazul 1: userul a marcat manual emailul ca SIGUR ("Mark safe").
    // Verdictul efectiv devine "safe", indiferent ce a zis scanul, și nu mai
    // necesită review (review-ul s-a întâmplat deja — userul l-a făcut).
    if (userVerdict === 'safe') {
        return {
            reviewStatus: 'reviewed',
            effectiveVerdict: 'safe',
            verdictSource: 'user',
            isQuarantined: false,
            riskBucket: 'reviewed_safe',
        };
    }

    // Cazul 2: userul a marcat manual emailul ca PHISHING ("Mark as phishing").
    // La fel, decizia userului învinge scanul; "confirmed_phishing" e o categorie
    // separată în UI (diferită de "quarantine", care vine din scan automat).
    if (userVerdict === 'phishing') {
        return {
            reviewStatus: 'reviewed',
            effectiveVerdict: 'phishing',
            verdictSource: 'user',
            isQuarantined: false,
            riskBucket: 'confirmed_phishing',
        };
    }

    // De aici încolo, userul NU a decis nimic manual — ne bazăm pe verdictul scanului.

    // Cazul 3: scanul a zis "likely_phishing" (risc mare) → emailul e pus în
    // carantină (`isQuarantined: true`) și așteaptă review-ul userului.
    if (scanVerdict === 'likely_phishing') {
        return {
            reviewStatus: 'pending_review',
            effectiveVerdict: 'likely_phishing',
            verdictSource: 'scan',
            isQuarantined: true,
            riskBucket: 'quarantine',
        };
    }

    // Cazul 4: scanul a zis "suspicious" (risc mediu) → nu e carantină, dar
    // tot are nevoie de atenția userului ("needs_review").
    if (scanVerdict === 'suspicious') {
        return {
            reviewStatus: 'pending_review',
            effectiveVerdict: 'suspicious',
            verdictSource: 'scan',
            isQuarantined: false,
            riskBucket: 'needs_review',
        };
    }

    // Cazul 5: scanul a zis "safe" (risc mic) → nu mai e nevoie de review.
    if (scanVerdict === 'safe') {
        return {
            reviewStatus: 'no_review_needed',
            effectiveVerdict: 'safe',
            verdictSource: 'scan',
            isQuarantined: false,
            riskBucket: 'safe',
        };
    }

    // Cazul 6 (implicit): nu există nici verdict de la user, nici de la scan —
    // emailul nu a fost încă scanat deloc.
    return {
        reviewStatus: 'unscanned',
        effectiveVerdict: null,
        verdictSource: null,
        isQuarantined: false,
        riskBucket: 'unscanned',
    };
};

// Construiește obiectul complet de "stare a emailului" trimis către frontend:
// combină starea de review calculată mai sus cu câteva câmpuri brute despre
// acțiunile manuale ale userului (ce verdict a dat, când, ce acțiune a fost ultima).
// Funcția e async doar pentru a păstra o formă consistentă cu alte servicii care
// pot face operații asincrone (ex: interogări suplimentare) — momentan nu așteaptă nimic.
export const buildEmailStateForUser = async ({ email, latestScan }) => {
    const reviewState = deriveEmailReviewState({ email, latestScan });

    return {
        userVerdict: email.userVerdict || null,
        reviewedAt: email.reviewedAt || null,
        lastManualAction: email.lastManualAction || null,
        ...reviewState,
    };
};
