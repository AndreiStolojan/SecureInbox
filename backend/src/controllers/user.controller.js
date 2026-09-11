// ─────────────────────────────────────────────────────────────────────────────
// user.controller.js — rutele pentru profilul userului, setări și ștergerea contului.
//
// Ce face, pe scurt: leagă rutele din `/users/*` de funcțiile din
// user.service.js. Controllerul nu conține logică de business — doar
// extrage datele din cerere (req), apelează serviciul corespunzător și
// trimite răspunsul HTTP (res) sau pasează eroarea către next(err) (care
// e prins de middleware-ul de erori).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    deleteCurrentUser,
    getAllUsers,
    getCurrentUser,
    getUserById,
    updateCurrentUser,
    updateCurrentUserAiSettings,
    updateCurrentUserNotificationSettings,
} from '../services/user.service.js';

// GET /users — listă cu toți userii. Doar pentru admin (vezi role.middleware.js).
export const getUsers = async (req, res, next) => {
    try {
        const users = await getAllUsers();

        res.status(200).json({ success: true, data: users });
    } catch (err) {
        next(err);
    }
};

// GET /users/:id — un user după id. Doar pentru admin.
export const getUser = async (req, res, next) => {
    try {
        const user = await getUserById(req.params.id);

        res.status(200).json({ success: true, data: user });
    } catch (err) {
        next(err);
    }
};

// GET /users/me — profilul userului autentificat curent.
// req.user._id vine din token-ul JWT (pus pe req de auth.middleware.js).
export const getMe = async (req, res, next) => {
    try {
        const user = await getCurrentUser(req.user._id);

        res.status(200).json({ success: true, data: user });
    } catch (err) {
        next(err);
    }
};

// PATCH /users/me — actualizează profilul userului curent (ex. numele).
export const updateMe = async (req, res, next) => {
    try {
        const user = await updateCurrentUser(req.user._id, req.body);

        res.status(200).json({ success: true, data: user });
    } catch (err) {
        next(err);
    }
};

// DELETE /users/me — șterge definitiv contul curent + toate datele lui
// (cascadă: emailuri, scanări, conturi de mail, liste de expeditori).
export const deleteMe = async (req, res, next) => {
    try {
        const result = await deleteCurrentUser(req.user._id);

        res.status(200).json({ success: true, message: 'Account deleted', data: result });
    } catch (err) {
        next(err);
    }
};

// PATCH /users/me/ai-settings — activează/dezactivează AI-ul local (Ollama)
// pentru scanarea emailurilor acestui user.
export const updateMeAiSettings = async (req, res, next) => {
    try {
        const aiSettings = await updateCurrentUserAiSettings(req.user._id, req.body);

        res.status(200).json({ success: true, data: aiSettings });
    } catch (err) {
        next(err);
    }
};

// PATCH /users/me/notification-settings — setări de notificări: alerte
// instant, digest zilnic și ora la care se trimite digest-ul.
export const updateMeNotificationSettings = async (req, res, next) => {
    try {
        const notificationSettings = await updateCurrentUserNotificationSettings(req.user._id, req.body);

        res.status(200).json({ success: true, data: notificationSettings });
    } catch (err) {
        next(err);
    }
};
