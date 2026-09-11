// ─────────────────────────────────────────────────────────────────────────────
// auto-sync.service.js — sincronizarea automată a tuturor conturilor Gmail.
//
// Ce face, pe scurt: pornit periodic de scheduler.service.js (cron, la fiecare
// SYNC_INTERVAL_MINUTES minute), parcurge TOATE conturile Gmail active din baza
// de date și, pentru fiecare, cere emailurile noi + rulează scanul automat
// (prin syncGmailEmailsForUser). Așa userul e protejat fără să deschidă
// aplicația ("conectează o dată și uită" — feedback coordonator).
//
// Tot aici: dacă după sync apar emailuri noi cu verdict "likely_phishing" și
// userul a activat alertele, se trimite un email de avertizare instant.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import MailAccount from '../models/mail-account.model.js';
import User from '../models/user.model.js';
import Scan from '../models/scan.model.js';
import Email from '../models/email.model.js';
import { syncGmailEmailsForUser } from './mail-account.service.js';
import { sendPhishingAlertEmail } from '../../extras/notifications/send-email.js';
import {
    GMAIL_POLL_INTERVAL_WITH_PUSH,
    isGmailPushConfigured,
} from '../config/env.js';

// Pentru o listă de id-uri de emailuri (de obicei emailuri NOU inserate la
// acest sync), găsește care dintre ele au scor "likely_phishing" și aduce
// datele necesare pentru emailul de alertă (subiect, expeditor, scor, reguli).
const findPhishingEmailsFromIds = async ({ userId, emailIds }) => {
    if (!emailIds || emailIds.length === 0) {
        return [];
    }

    const phishingScans = await Scan.find({
        userId,
        emailId: { $in: emailIds },
        verdict: 'likely_phishing',
    })
        .select('emailId score triggeredRules')
        .lean();

    if (phishingScans.length === 0) {
        return [];
    }

    const phishingEmailIds = phishingScans.map((scan) => scan.emailId);

    const scanByEmailId = new Map(
        phishingScans.map((scan) => [String(scan.emailId), scan])
    );

    const emails = await Email.find({ _id: { $in: phishingEmailIds }, userId })
        .select('subject from providerMessageId')
        .lean();

    return emails.map((email) => {
        const scan = scanByEmailId.get(String(email._id));
        return {
            ...email,
            score: scan?.score ?? null,
            triggeredRules: scan?.triggeredRules ?? [],
        };
    });
};

// Trimite emailul de alertă de phishing, dar doar dacă userul a activat
// alertele (alertsEnabled) și există efectiv emailuri de phishing de raportat.
// Eroarea de trimitere e doar logată — nu trebuie să strice tot sync-ul.
const sendAlertIfEnabled = async ({ user, phishingEmails }) => {
    if (!user.settings?.alertsEnabled || phishingEmails.length === 0) {
        return;
    }

    try {
        await sendPhishingAlertEmail({
            recipient: user.email,
            userName: user.name,
            emails: phishingEmails,
        });
    } catch (error) {
        console.error('[auto-sync] Failed to send phishing alert', {
            userId: String(user._id),
            error: error.message,
        });
    }
};

export const syncActiveGmailAccount = async ({ mailAccount }) => {
    const syncResult = await syncGmailEmailsForUser({
        userId: mailAccount.userId,
        mailAccountId: mailAccount._id,
    });
    const newEmails = syncResult.insertedCount || 0;
    let phishingAlerts = 0;

    if (newEmails > 0 && syncResult.insertedEmailIds?.length > 0) {
        const user = await User.findById(mailAccount.userId).select('email name settings').lean();
        if (user?.settings?.alertsEnabled) {
            const phishingEmails = await findPhishingEmailsFromIds({
                userId: mailAccount.userId,
                emailIds: syncResult.insertedEmailIds,
            });
            phishingAlerts = phishingEmails.length;
            await sendAlertIfEnabled({ user, phishingEmails });
        }
    }

    return { syncResult, newEmails, phishingAlerts };
};

export const shouldPollAccount = (mailAccount, now = Date.now(), {
    pushConfigured = isGmailPushConfigured(),
    intervalMinutes: configuredInterval = GMAIL_POLL_INTERVAL_WITH_PUSH,
} = {}) => {
    if (!pushConfigured || mailAccount.watchStatus !== 'active') return true;
    if (!mailAccount.watchExpiration || new Date(mailAccount.watchExpiration).getTime() <= now) return true;
    if (!mailAccount.lastSyncedAt) return true;

    const parsed = Number.parseInt(configuredInterval, 10);
    const intervalMinutes = Number.isInteger(parsed) && parsed > 0 ? parsed : 60;
    return now - new Date(mailAccount.lastSyncedAt).getTime() >= intervalMinutes * 60_000;
};

// Funcția principală, apelată de cron (scheduler.service.js) la fiecare
// SYNC_INTERVAL_MINUTES minute. Sincronizează pe rând TOATE conturile Gmail
// active, scanează emailurile noi și trimite alerte de phishing dacă e cazul.
// Erorile per-cont sunt prinse și numărate — un cont stricat nu blochează
// sincronizarea pentru restul userilor.
export const runAutoSyncForAllUsers = async () => {
    // Toate conturile Gmail conectate și active (userul nu le-a deconectat).
    const allActiveMailAccounts = await MailAccount.find({
        provider: 'gmail',
        status: 'active',
    }).lean();
    const activeMailAccounts = allActiveMailAccounts.filter((account) => shouldPollAccount(account));

    if (activeMailAccounts.length === 0) {
        console.log('[auto-sync] No active Gmail accounts found, skipping run');
        return { totalErrors: 0 };
    }

    console.log(`[auto-sync] Starting sync for ${activeMailAccounts.length} Gmail account(s)`);

    // Contoare globale pentru logul final de la sfârșitul rulării.
    let totalNewEmails = 0;
    let totalPhishingAlerts = 0;
    let totalErrors = 0;

    for (const mailAccount of activeMailAccounts) {
        try {
            const { syncResult, newEmails, phishingAlerts } = await syncActiveGmailAccount({ mailAccount });
            totalNewEmails += newEmails;
            totalPhishingAlerts += phishingAlerts;

            console.log('[auto-sync] Account synced', {
                userId: String(mailAccount.userId),
                accountEmail: mailAccount.accountEmail,
                insertedCount: syncResult.insertedCount,
                updatedCount: syncResult.updatedCount,
                scannedCount: syncResult.scanSummary?.scannedCount ?? 0,
            });
        } catch (error) {
            // Un cont cu eroare (ex: token expirat) NU oprește bucla — trecem
            // la următorul cont și raportăm eroarea în log.
            totalErrors += 1;
            console.error('[auto-sync] Sync failed for account', {
                userId: String(mailAccount.userId),
                mailAccountId: String(mailAccount._id),
                accountEmail: mailAccount.accountEmail,
                error: error.message,
            });
        }
    }

    console.log('[auto-sync] Run complete', {
        accounts: activeMailAccounts.length,
        newEmails: totalNewEmails,
        phishingAlerts: totalPhishingAlerts,
        errors: totalErrors,
    });
    return { totalErrors };
};

// Variantă folosită pentru un sync MANUAL (declanșat de user din UI, nu de
// cron): după sync, verifică emailurile noi inserate și trimite alertă de
// phishing dacă userul a activat opțiunea și au apărut emailuri riscante.
export const sendPhishingAlertForNewEmails = async ({ userId, user, syncResult }) => {
    if (!syncResult?.insertedEmailIds?.length) return;
    const phishingEmails = await findPhishingEmailsFromIds({
        userId,
        emailIds: syncResult.insertedEmailIds,
    });
    if (phishingEmails.length > 0) {
        await sendAlertIfEnabled({ user, phishingEmails });
    }
};
