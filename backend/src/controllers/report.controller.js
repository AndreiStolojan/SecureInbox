// ─────────────────────────────────────────────────────────────────────────────
// report.controller.js — controllerul pentru rapoarte (dashboard + rezumat periodic).
//
// Ce face, pe scurt: primește cererile HTTP pentru rezumatul periodic (dashboard
// sau raport trimis pe email), apelează report.service.js pentru a calcula
// datele și formatează răspunsul JSON. Nu face calcule el însuși — doar
// "traduce" cererea/răspunsul HTTP.
//
// Endpoint-uri (vezi report.routes.js):
//   GET  /reports/monthly-summary[?from=&to=&label=]  (sau legacy ?month=)
//   POST /reports/monthly-summary/send
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    getMonthlySummaryForUser,
    sendMonthlySummaryForUser,
} from '../services/report.service.js';

// Alege codul HTTP de răspuns pentru trimiterea emailului, în funcție de
// rezultat: 200 dacă a fost trimis cu succes, 503 dacă serviciul de email nu
// este configurat (eroare de configurare, nu vina userului), altfel 502
// (eroare la trimitere, ex. SMTP a refuzat conexiunea).
const statusFromMailResult = (result) => {
    if (result.sent) return 200;
    return result.error?.code === 'EMAIL_CONFIG_MISSING' ? 503 : 502;
};

// GET /reports/monthly-summary
// Calculează și returnează rezumatul periodic pentru userul logat (folosit de
// dashboard). Query-ul poate conține from/to/label (interval nou) sau month
// (mod vechi, păstrat pentru compatibilitate) — vezi report.service.js.
export const getMonthlySummary = async (req, res, next) => {
    try {
        const summary = await getMonthlySummaryForUser({
            userId: req.user._id,
            query: req.query,
        });

        res.status(200).json({
            success: true,
            data: summary,
        });
    } catch (error) {
        next(error);
    }
};

// POST /reports/monthly-summary/send
// Calculează același rezumat ca mai sus și îl trimite pe adresa de email a
// userului. Codul de status HTTP depinde de rezultatul trimiterii (vezi
// statusFromMailResult): succesul "logic" al cererii (success: true/false în
// body) nu e mereu același cu un cod 2xx, pentru că o trimitere nereușită nu
// e neapărat o eroare de server.
export const sendMonthlySummary = async (req, res, next) => {
    try {
        const result = await sendMonthlySummaryForUser({
            user: req.user,
            query: req.query,
        });

        res.status(statusFromMailResult(result)).json({
            success: result.sent,
            data: result,
        });
    } catch (error) {
        next(error);
    }
};
