// ─────────────────────────────────────────────────────────────────────────────
// action.service.js — acțiunile manuale ale userului asupra unui email.
//
// Ce face, pe scurt: userul poate marca un email "sigur" (Mark safe) sau
// "phishing" (Mark phishing). Verdictul manual al userului are prioritate
// peste verdictul scanului automat ("user review overrides scan" — vezi
// email-state.service.js, secțiunea 5.4). Dacă userul marchează un email ca
// phishing, acest fișier încearcă și să mute mesajul în Spam pe Gmail
// (acțiune pe partea de provider, separată de acțiunea manuală).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';

import createError from '../common/errors/create-error.js';
import Email from '../models/email.model.js';
import { moveGmailMessageToSpam } from './mail-account.service.js';

// Cele două acțiuni manuale posibile, salvate ca șiruri de text pe documentul Email.
const ACTIONS = {
    markSafe: 'mark_safe',
    markPhishing: 'mark_phishing',
};

// Transformă documentul Email (din MongoDB) într-un obiect "public" — doar
// câmpurile relevante pentru frontend, legate de acțiunea manuală a userului
// și de acțiunea (eventuală) făcută pe Gmail.
const toPublicEmailAction = (email) => ({
    emailId: email._id,
    userVerdict: email.userVerdict,
    reviewedAt: email.reviewedAt,
    lastManualAction: email.lastManualAction,
    lastProviderAction: email.lastProviderAction || null,
    lastProviderActionStatus: email.lastProviderActionStatus || null,
    lastProviderActionAt: email.lastProviderActionAt || null,
    lastProviderActionError: email.lastProviderActionError || null,
});

// Wrapper comun pentru răspunsul final trimis spre controller: ce acțiune s-a
// făcut, starea emailului și (opțional) ce s-a întâmplat pe Gmail.
const toPublicActionResult = ({
    action,
    email = null,
    providerAction = null,
}) => ({
    action,
    email:
        email && Object.prototype.hasOwnProperty.call(email, 'emailId')
            ? email
            : email
              ? toPublicEmailAction(email)
              : null,
    providerAction,
});

// Verifică dacă emailId-ul are format valid de ObjectId Mongo, altfel 400.
const validateEmailId = (emailId) => {
    if (!mongoose.Types.ObjectId.isValid(emailId)) {
        throw createError('Invalid email id', 400, [], 'INVALID_EMAIL_ID');
    }
};

// Caută emailul după id, dar DOAR dacă apartine userului curent (userId).
// Așa ne asigurăm că un user nu poate marca/modifica emailurile altcuiva.
const findOwnedEmailById = async ({ userId, emailId }) => {
    validateEmailId(emailId);

    const email = await Email.findOne({
        _id: emailId,
        userId,
    });

    if (!email) {
        throw createError('Email not found', 404, [], 'EMAIL_NOT_FOUND');
    }

    return email;
};

// Salvează verdictul manual al userului (safe / phishing) pe email, împreună
// cu data la care a fost revizuit și ce acțiune s-a apăsat.
const updateManualReview = async ({ email, userVerdict, action }) => {
    email.userVerdict = userVerdict;
    email.reviewedAt = new Date();
    email.lastManualAction = action;

    await email.save();

    return toPublicEmailAction(email);
};

// Construiește un obiect "acțiune provider" pentru cazul în care mutarea în
// Spam pe Gmail a eșuat (de ex. token expirat, eroare de rețea).
const toProviderActionFailure = (error) => ({
    type: 'gmail_move_to_spam',
    status: 'failed',
    errorCode: error?.code || 'GMAIL_MOVE_TO_SPAM_FAILED',
    message: error?.message || 'Failed to move Gmail message to spam.',
});

// Salvează pe documentul Email rezultatul ultimei acțiuni făcute pe partea de
// provider (Gmail): tip, status (success/failed), când și — dacă a eșuat — eroarea.
const trackProviderAction = async ({ email, providerAction }) => {
    email.lastProviderAction = providerAction.type;
    email.lastProviderActionStatus = providerAction.status;
    email.lastProviderActionAt = new Date();
    email.lastProviderActionError =
        providerAction.status === 'success'
            ? null
            : {
                  code: providerAction.errorCode || null,
                  message: providerAction.message || null,
              };
    if (providerAction.type === 'gmail_move_to_spam' && providerAction.status === 'success') {
        email.inboxState = 'removed';
    }

    await email.save();

    return providerAction;
};

// Când userul marchează un email ca phishing, încercăm să mutăm mesajul și în
// Spam pe Gmail (acțiune reală pe contul userului, prin API-ul Gmail).
// Dacă apelul către Gmail eșuează, NU oprim acțiunea — doar înregistrăm eroarea
// (vezi toProviderActionFailure), astfel încât marcarea manuală să reușească
// chiar dacă Gmail e indisponibil.
const moveEmailToGmailSpamAfterManualPhishing = async ({ userId, email }) => {
    let providerAction;

    try {
        providerAction = await moveGmailMessageToSpam({ userId, email });
    } catch (error) {
        providerAction = toProviderActionFailure(error);
    }

    return trackProviderAction({ email, providerAction });
};

// Acțiune "Mark safe": userul confirmă manual că emailul e sigur. Acest
// verdict va avea prioritate peste verdictul automat al scanului.
export const markEmailSafeForUser = async ({ userId, emailId }) => {
    const email = await findOwnedEmailById({ userId, emailId });
    const emailAction = await updateManualReview({
        email,
        userVerdict: 'safe',
        action: ACTIONS.markSafe,
    });

    return toPublicActionResult({
        action: ACTIONS.markSafe,
        email: emailAction,
    });
};

// Acțiune "Mark phishing": userul marchează manual emailul ca phishing și,
// suplimentar, mesajul este mutat în Spam pe Gmail (acțiunea de mai sus).
export const markEmailPhishingForUser = async ({ userId, emailId }) => {
    const email = await findOwnedEmailById({ userId, emailId });
    const emailAction = await updateManualReview({
        email,
        userVerdict: 'phishing',
        action: ACTIONS.markPhishing,
    });

    const providerAction = await moveEmailToGmailSpamAfterManualPhishing({
        userId,
        email,
    });

    return toPublicActionResult({
        action: ACTIONS.markPhishing,
        email: {
            ...emailAction,
            lastProviderAction: email.lastProviderAction || null,
            lastProviderActionStatus: email.lastProviderActionStatus || null,
            lastProviderActionAt: email.lastProviderActionAt || null,
            lastProviderActionError: email.lastProviderActionError || null,
        },
        providerAction,
    });
};
