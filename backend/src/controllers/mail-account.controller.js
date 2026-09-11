// ─────────────────────────────────────────────────────────────────────────────
// mail-account.controller.js — controller pentru conturile de mail (Gmail).
//
// Ce face, pe scurt: e stratul "subțire" dintre rute (mail-account.routes.js)
// și logica reală din mail-account.service.js. Fiecare funcție de mai jos:
// citește ce a trimis userul (req.user, req.params, req.body, req.query),
// apelează funcția corespunzătoare din service, și împachetează rezultatul
// într-un răspuns JSON ({ success, data/message }). NU conține logică de
// business — doar "leagă" cererea HTTP de service.
//
// Conține și fluxul OAuth Google (conectare cont Gmail):
// 1. startGoogleConnect  -> dă frontendului URL-ul de Google către care
//    trebuie redirecționat userul (ecranul "Permite acces Gmail").
// 2. handleGoogleCallback -> Google redirecționează aici după ce userul
//    aprobă/refuză; conectăm contul și redirecționăm userul înapoi spre
//    frontend (cu query params de succes/eroare), nu cu JSON.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    backfillGmailEmailsForUser,
    connectGoogleMailAccount,
    disconnectMailAccountForUser,
    getGoogleConnectUrl,
    getMailAccountsForUser,
    syncGmailEmailsForUser,
    updateMailAccountSettingsForUser,
} from '../services/mail-account.service.js';
import { sendPhishingAlertForNewEmails } from '../services/auto-sync.service.js';
import User from '../models/user.model.js';
import { FRONTEND_APP_URL } from '../config/env.js';

// Construiește un URL către pagina /dashboard din frontend, cu query params
// (de exemplu ?gmail=connected&account=... sau ?gmail=error&code=...).
// Folosit pentru a "raporta" userului rezultatul conectării Gmail, deoarece
// callback-ul OAuth e o redirecționare de browser, nu un apel API normal
// (frontendul nu poate citi direct un JSON aici).
const buildFrontendRedirectUrl = ({ params }) => {
    const redirectUrl = new URL('/dashboard', FRONTEND_APP_URL);

    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && String(value).length > 0) {
            redirectUrl.searchParams.set(key, String(value));
        }
    }

    return redirectUrl.toString();
};

// GET /mail-accounts — listează conturile de mail conectate de userul curent
// (de obicei doar contul Gmail), fără tokeni (vezi toPublicMailAccount).
export const getMailAccounts = async (req, res, next) => {
    try {
        const mailAccounts = await getMailAccountsForUser(req.user._id);

        res.status(200).json({
            success: true,
            data: mailAccounts,
        });
    } catch (error) {
        next(error);
    }
};

// GET /mail-accounts/google/start — pasul 1 din OAuth Google: returnează către
// frontend URL-ul către pagina de consimțământ Google, către care userul
// trebuie redirecționat din browser (acolo apasă "Permite acces la Gmail").
export const startGoogleConnect = async (req, res, next) => {
    try {
        const result = await getGoogleConnectUrl(req.user._id);

        res.status(200).json({
            success: true,
            data: result,
        });
    } catch (error) {
        next(error);
    }
};

// GET /mail-accounts/google/callback — pasul 2/3 din OAuth Google: Google
// redirecționează browserul userului aici, după ce acesta a aprobat (sau
// refuzat) accesul. Nu răspundem cu JSON, ci redirecționăm înapoi spre
// frontend (/dashboard), cu query params care arată dacă a mers ("connected")
// sau nu ("error"), ca frontendul să poată afișa un mesaj.
export const handleGoogleCallback = async (req, res, next) => {
    try {
        // connectGoogleMailAccount face toată munca: verifică "state"-ul (anti-CSRF),
        // schimbă code-ul pe tokeni Gmail și salvează contul în baza de date.
        const mailAccount = await connectGoogleMailAccount({
            code: req.query.code,
            state: req.query.state,
            googleError: req.query.error,
        });

        return res.redirect(
            302,
            buildFrontendRedirectUrl({
                params: {
                    gmail: 'connected',
                    account: mailAccount.accountEmail,
                },
            })
        );
    } catch (error) {
        // Dacă cererea avea cu adevărat parametri OAuth (a venit de la Google),
        // tratăm eroarea redirecționând userul spre frontend cu ?gmail=error,
        // în loc să-i arătăm o pagină de eroare JSON brută.
        if (req.query?.state || req.query?.code || req.query?.error) {
            return res.redirect(
                302,
                buildFrontendRedirectUrl({
                    params: {
                        gmail: 'error',
                        code: error.code || 'GMAIL_CONNECT_FAILED',
                    },
                })
            );
        }

        next(error);
    }
};

// DELETE /mail-accounts/:id — deconectează contul de mail al userului (șterge
// legătura cu Gmail; emailurile deja sincronizate rămân în baza de date).
export const disconnectMailAccount = async (req, res, next) => {
    try {
        const result = await disconnectMailAccountForUser({
            userId: req.user._id,
            mailAccountId: req.params.id,
        });

        res.status(200).json({
            success: true,
            message: result.message,
        });
    } catch (error) {
        next(error);
    }
};

// POST /mail-accounts/:id/sync — declanșează manual sincronizarea cu Gmail
// (butonul "Sync" din UI): descarcă emailurile noi, le salvează și le scanează.
export const syncMailAccount = async (req, res, next) => {
    try {
        const syncResult = await syncGmailEmailsForUser({
            userId: req.user._id,
            mailAccountId: req.params.id,
        });

        // După sincronizare, verificăm dacă printre emailurile noi sunt unele
        // periculoase și, dacă da, trimitem o alertă (email) userului.
        // Apelul e "fire-and-forget" (.catch fără await): nu blocăm răspunsul
        // către frontend cât timp se trimite alerta — userul vede rezultatul
        // sincronizării imediat, iar alerta se trimite în fundal.
        if (!syncResult.skipped) {
            const user = await User.findById(req.user._id).select('email name settings').lean();
            sendPhishingAlertForNewEmails({ userId: req.user._id, user, syncResult }).catch(
                (err) => console.error('[manual-sync] Failed to send phishing alert', err.message)
            );
        }

        res.status(200).json({
            success: true,
            message: syncResult.skipped
                ? 'Mail account sync is already running'
                : 'Mail account synced successfully',
            data: syncResult,
        });
    } catch (error) {
        next(error);
    }
};

export const backfillMailAccount = async (req, res, next) => {
    try {
        const result = await backfillGmailEmailsForUser({
            userId: req.user._id,
            mailAccountId: req.params.id,
        });

        res.status(200).json({
            success: true,
            message: result.skipped ? 'Mail account sync is already running' : 'Backfill started',
            data: result,
        });
    } catch (error) {
        next(error);
    }
};

// PATCH /mail-accounts/:id/settings — actualizează setările de sincronizare ale
// contului (în prezent doar syncMaxResults = câte emailuri se aduc la un sync).
export const updateMailAccountSettings = async (req, res, next) => {
    try {
        const mailAccount = await updateMailAccountSettingsForUser({
            userId: req.user._id,
            mailAccountId: req.params.id,
            syncMaxResults: req.body?.syncMaxResults,
        });

        res.status(200).json({
            success: true,
            message: 'Mail account settings updated successfully',
            data: mailAccount,
        });
    } catch (error) {
        next(error);
    }
};
