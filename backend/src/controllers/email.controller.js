// ─────────────────────────────────────────────────────────────────────────────
// email.controller.js — stratul "controller" pentru emailuri.
//
// Ce face, pe scurt: primește cererile HTTP din `email.routes.js`, le pasează
// serviciului `email.service.js` (acolo e toată logica reală), și împachetează
// rezultatul într-un răspuns JSON uniform `{ success: true, data: ... }`.
// Controllerul NU conține logică de business — doar citește ce a trimis userul
// (din `req.params` / `req.query`) și ce userId e logat (din `req.user._id`,
// pus de `auth.middleware.js`), apoi cheamă funcția potrivită din service.
//
// Orice eroare aruncată de service e trimisă către `next(error)`, care o
// predă lui `error.middleware.js` (transformă eroarea într-un JSON uniform).
//
// Detalii despre straturi: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    getEmailByIdForUser,
    getEmailRawByIdForUser,
    getEmailsForUser,
    getRiskBucketCountsForUser,
    getTopRiskySendersForUser,
    getTrendForUser,
} from '../services/email.service.js';

// GET /api/v1/emails/stats — statistici pentru dashboard: câte emailuri sunt
// în fiecare "găleată de risc" (riskBucket: safe / needs_review / quarantine
// / reviewed_safe / confirmed_phishing / unscanned), opțional filtrate pe
// interval de timp (days / from / to, citite din query string).
export const getEmailStats = async (req, res, next) => {
    try {
        const result = await getRiskBucketCountsForUser({
            userId: req.user._id,
            days: req.query.days,
            from: req.query.from,
            to: req.query.to,
        });

        res.status(200).json({
            success: true,
            data: result,
        });
    } catch (error) {
        next(error);
    }
};

// GET /api/v1/emails — lista de emailuri a userului logat, cu paginare,
// căutare text și filtre (verdict, riskBucket, cont de mail etc.).
// Toate detaliile filtrelor sunt validate și aplicate în `getEmailsForUser`.
export const getEmails = async (req, res, next) => {
    try {
        const result = await getEmailsForUser({
            userId: req.user._id,
            query: req.query,
        });

        res.status(200).json({
            success: true,
            data: result,
        });
    } catch (error) {
        next(error);
    }
};

// GET /api/v1/emails/:id — detaliile unui singur email (subiect, expeditor,
// corp, plus "starea" lui calculată: effectiveVerdict, riskBucket,
// reviewStatus, ultimul scan). `req.params.id` este id-ul emailului din URL.
export const getEmailById = async (req, res, next) => {
    try {
        const email = await getEmailByIdForUser({
            userId: req.user._id,
            emailId: req.params.id,
        });

        res.status(200).json({
            success: true,
            data: email,
        });
    } catch (error) {
        next(error);
    }
};

// GET /api/v1/emails/:id/raw — conținutul "brut" al emailului (ex. headerele
// MIME originale primite de la Gmail), util pentru depanare / inspecție.
export const getEmailRawById = async (req, res, next) => {
    try {
        const rawEmail = await getEmailRawByIdForUser({
            userId: req.user._id,
            emailId: req.params.id,
        });

        res.status(200).json({
            success: true,
            data: rawEmail,
        });
    } catch (error) {
        next(error);
    }
};

// GET /api/v1/emails/trend — evoluția în timp a numărului de emailuri pe
// verdict (ex. câte "safe" / "suspicious" / "likely_phishing" pe zi), pentru
// graficul de tendințe din dashboard. Interval opțional via from/to.
export const getEmailTrend = async (req, res, next) => {
    try {
        const trend = await getTrendForUser({
            userId: req.user._id,
            from: req.query.from,
            to: req.query.to,
        });
        res.status(200).json({ success: true, data: trend });
    } catch (error) {
        next(error);
    }
};

// GET /api/v1/emails/top-risky-senders — topul expeditorilor cu cele mai
// multe emailuri riscante, în ultimele `days` zile (implicit 30 dacă nu se
// trimite sau e invalid — `Number.parseInt(...) || 30`).
export const getTopRiskySenders = async (req, res, next) => {
    try {
        const senders = await getTopRiskySendersForUser({
            userId: req.user._id,
            days: Number.parseInt(req.query.days, 10) || 30,
            from: req.query.from,
            to: req.query.to,
        });
        res.status(200).json({ success: true, data: senders });
    } catch (error) {
        next(error);
    }
};
