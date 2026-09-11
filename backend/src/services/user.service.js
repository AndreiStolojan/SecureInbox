// ─────────────────────────────────────────────────────────────────────────────
// user.service.js — profilul userului: citire/actualizare date, setări (AI,
// notificări), și ștergerea contului (cu cascadă).
//
// Ce face, pe scurt: oferă funcțiile din spatele rutelor `/users/*` —
// listă useri (admin), profilul propriu ("me"), actualizare nume, setarea
// "aiEnabled" (dacă scanarea folosește și AI local prin Ollama), setările de
// notificări (alerte, digest zilnic și ora lui), și ștergerea completă a
// contului. La ștergere, se șterg și TOATE datele asociate userului din
// celelalte colecții (emailuri, scanări, conturi de mail, liste expeditori) —
// asta se numește "cascadă" (cascade).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import User from '../models/user.model.js';
import Email from '../models/email.model.js';
import Scan from '../models/scan.model.js';
import MailAccount from '../models/mail-account.model.js';
import SenderListEntry from '../models/sender-list.model.js';
import { toPublicUser } from './auth.service.js';
import { stopGmailWatchForAccount } from './mail-account.service.js';

// Listă cu toți userii (folosită de rute de admin) — fiecare e trecut prin
// toPublicUser ca să nu se scurgă date sensibile (ex. passwordHash).
export const getAllUsers = async () => {
    const users = await User.find();
    return users.map(toPublicUser);
};

// Caută un user după id (ex. pentru admin). Dacă nu există, aruncă 404.
export const getUserById = async (userId) => {
    const user = await User.findById(userId);

    if (!user) {
        const error = new Error('User not Found');
        error.statusCode = 404;
        throw error;
    }

    return toPublicUser(user);
};

// Profilul userului autentificat (răspunsul rutei GET /users/me).
// "authenticatedUserId" vine din token-ul JWT, pus pe req.user de middleware.
export const getCurrentUser = async (authenticatedUserId) => {
    const user = await User.findById(authenticatedUserId);

    if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
    }

    return toPublicUser(user);
};

// Actualizează datele de profil ale userului curent (acum doar "name").
export const updateCurrentUser = async (authenticatedUserId, payload) => {
    const user = await User.findById(authenticatedUserId);

    if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
    }

    // Object.hasOwn verifică dacă payload-ul conține efectiv câmpul "name"
    // (și nu doar că ar fi undefined) — așa nu ștergem numele din greșeală
    // dacă frontend-ul nu trimite acest câmp.
    if (Object.hasOwn(payload, 'name')) {
        user.name = payload.name;
    }

    await user.save();

    return toPublicUser(user);
};

// Activează/dezactivează folosirea AI-ului (Ollama) la scanarea emailurilor
// pentru acest user. Setarea e citită de scan.service.js.
export const updateCurrentUserAiSettings = async (authenticatedUserId, payload) => {
    const user = await User.findById(authenticatedUserId);

    if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
    }

    // Se păstrează restul setărilor existente (...user.settings.toObject())
    // și se suprascrie doar aiEnabled, convertit explicit la boolean.
    user.settings = {
        ...user.settings?.toObject?.(),
        aiEnabled: Boolean(payload.aiEnabled),
    };

    await user.save();

    return {
        aiEnabled: user.settings.aiEnabled,
    };
};

// Șterge definitiv contul userului curent, împreună cu toate datele lui din
// celelalte colecții (cascadă) — emailuri, scanări, conturi de mail conectate
// și listele de expeditori (allowlist/blocklist).
export const deleteCurrentUser = async (authenticatedUserId) => {
    const user = await User.findById(authenticatedUserId);

    if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
    }

    const mailAccounts = await MailAccount.find({ userId: user._id });
    const stopResults = await Promise.allSettled(
        mailAccounts.map((mailAccount) => stopGmailWatchForAccount({ mailAccount }))
    );
    stopResults.forEach((result, index) => {
        if (result.status === 'rejected') {
            console.warn('[gmail-watch] Failed to stop Watch before account deletion', {
                mailAccountId: String(mailAccounts[index]._id),
                error: result.reason?.message,
            });
        }
    });

    // Cascadă: toate colecțiile care țin date legate de acest user.
    // Promise.all rulează cele 4 ștergeri în paralel (mai rapid decât pe rând).
    await Promise.all([
        Scan.deleteMany({ userId: user._id }),
        Email.deleteMany({ userId: user._id }),
        MailAccount.deleteMany({ userId: user._id }),
        SenderListEntry.deleteMany({ userId: user._id }),
    ]);
    await User.deleteOne({ _id: user._id });

    return { deleted: true };
};

// Actualizează setările de notificări: alerte instant (alertsEnabled), digest
// zilnic (digestEnabled) și ora la care se trimite digest-ul (digestHour).
export const updateCurrentUserNotificationSettings = async (authenticatedUserId, payload) => {
    const user = await User.findById(authenticatedUserId);

    if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
    }

    const current = user.settings?.toObject?.() ?? {};

    // La fel ca mai sus: se modifică doar câmpurile prezente în payload,
    // restul setărilor (current) rămân neschimbate. Object.hasOwn evită
    // suprascrierea cu "undefined" dacă frontend-ul nu trimite un câmp.
    user.settings = {
        ...current,
        ...(Object.hasOwn(payload, 'alertsEnabled') && { alertsEnabled: Boolean(payload.alertsEnabled) }),
        ...(Object.hasOwn(payload, 'digestEnabled') && { digestEnabled: Boolean(payload.digestEnabled) }),
        ...(Object.hasOwn(payload, 'digestHour') && { digestHour: Number(payload.digestHour) }),
    };

    await user.save();

    return {
        alertsEnabled: user.settings.alertsEnabled,
        digestEnabled: user.settings.digestEnabled,
        digestHour: user.settings.digestHour,
    };
};
