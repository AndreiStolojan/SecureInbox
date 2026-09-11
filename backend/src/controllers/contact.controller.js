// ─────────────────────────────────────────────────────────────────────────────
// contact.controller.js — formularul de contact ("Contactează-ne").
//
// Ce face, pe scurt: primește mesajul userului (subiect + text), îl trimite
// prin contact.service.js și alege codul de status HTTP potrivit în funcție
// de rezultat (trimis cu succes, eroare de configurare server, sau altă
// eroare la trimitere).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { sendContactMessageForUser } from '../services/contact.service.js';

// Alege codul HTTP în funcție de rezultatul trimiterii emailului:
// - 200 dacă a fost trimis;
// - 503 (serviciu indisponibil) dacă serverul nu are configurat emailul de contact;
// - 502 (eroare la furnizorul de email) pentru orice altă eroare de trimitere.
const statusFromMailResult = (result) => {
    if (result.sent) return 200;
    return result.error?.code === 'EMAIL_CONFIG_MISSING' ? 503 : 502;
};

// POST /contact/message — trimite mesajul de contact al userului autentificat
// către echipa de suport.
export const sendContactMessage = async (req, res, next) => {
    try {
        const result = await sendContactMessageForUser({
            user: req.user,
            payload: req.body,
        });

        res.status(statusFromMailResult(result)).json({
            success: result.sent,
            message: result.sent
                ? 'Contact message sent.'
                : result.error?.message || 'Contact message could not be sent.',
            data: result,
        });
    } catch (error) {
        next(error);
    }
};
