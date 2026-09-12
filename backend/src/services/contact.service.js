// ─────────────────────────────────────────────────────────────────────────────
// contact.service.js — formularul de contact ("Contactează-ne").
//
// Ce face, pe scurt: userul autentificat trimite un mesaj (subiect + text) către
// echipa de suport. Serviciul normalizează subiectul (dacă e gol/invalid, pune
// unul implicit) și trimite emailul prin sendContactMessageEmail. Dacă trimiterea
// dă eroare, NU se aruncă o eroare către controller — se returnează un obiect cu
// "sent: false" și detaliile erorii, ca răspunsul HTTP să rămână controlat. Ruta
// asociată este protejată separat (în routes) cu Arcjet, împotriva boților și a
// trimiterilor repetate (rate-limit).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { sendContactMessageEmail } from '../../extras/notifications/send-email.js';

// Subiect folosit dacă userul nu trimite unul valid.
const DEFAULT_CONTACT_SUBJECT = 'Support message';

// Curăță subiectul: scoate spațiile de la capete și înlocuiește grupurile de
// spații/tab-uri/linii noi cu un singur spațiu. Dacă rezultatul e gol sau
// subiectul nu era string, se folosește valoarea implicită.
const normalizeSubject = (subject) => {
    if (typeof subject !== 'string') {
        return DEFAULT_CONTACT_SUBJECT;
    }

    const trimmedSubject = subject.trim().replace(/\s+/g, ' ');

    return trimmedSubject || DEFAULT_CONTACT_SUBJECT;
};

// Trimite mesajul de contact pentru userul autentificat. "user" vine din
// req.user (pus de middleware-ul de autentificare), "payload" e corpul cererii
// (subject + message), deja validat de validate.middleware.js.
export const sendContactMessageForUser = async ({ user, payload }) => {
    try {
        return await sendContactMessageEmail({
            userName: user.name,
            userEmail: user.email,
            subject: normalizeSubject(payload.subject),
            message: payload.message,
        });
    } catch (error) {
        // Eroarea la trimiterea emailului NU blochează cererea cu un 500 —
        // se întoarce un răspuns "controlat" cu sent: false, ca frontend-ul
        // să poată afișa un mesaj prietenos în loc de o eroare generică.
        return {
            sent: false,
            recipient: null,
            generatedAt: new Date().toISOString(),
            error: {
                code: 'EMAIL_SEND_FAILED',
                message: 'Contact email could not be sent.',
                detail: error.message,
            },
        };
    }
};
