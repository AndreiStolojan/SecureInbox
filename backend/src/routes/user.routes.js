// ─────────────────────────────────────────────────────────────────────────────
// user.routes.js — definește rutele HTTP sub `/api/v1/users`.
//
// Ce face, pe scurt: pentru fiecare rută, leagă metoda HTTP + path-ul de
// un șir de funcții: middleware-uri (autentificare, validare, roluri) și,
// la final, controllerul care răspunde efectiv. Ordinea contează — fiecare
// middleware poate opri cererea înainte să ajungă la următorul.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

import { deleteMe, getMe, getUser, getUsers, updateMe, updateMeAiSettings, updateMeNotificationSettings } from '../controllers/user.controller.js';
import authorize from "../middlewares/auth.middleware.js";
import authorizeRoles from "../middlewares/role.middleware.js";
import validate from '../middlewares/validate.middleware.js';
import { updateAiSettingsSchema, updateMeSchema, updateNotificationSettingsSchema } from '../validations/user.validation.js';

const userRouter = Router();

// "me" = userul autentificat curent (identificat prin token JWT, nu prin id în URL).
userRouter.get('/me', authorize, getMe);
// Setări AI: validate(...) verifică body-ul cererii înainte să ajungă la controller.
userRouter.patch('/me/ai-settings', authorize, validate(updateAiSettingsSchema), updateMeAiSettings);
// Setări notificări (alerte, digest zilnic, ora digest-ului).
userRouter.patch('/me/notification-settings', authorize, validate(updateNotificationSettingsSchema), updateMeNotificationSettings);
// Actualizare profil (ex. nume).
userRouter.patch('/me', authorize, validate(updateMeSchema), updateMe);
// Ștergere cont (cu cascadă pe toate datele userului).
userRouter.delete('/me', authorize, deleteMe);
// Rute de admin: listă useri / un user după id. authorizeRoles('admin') blochează
// accesul dacă userul autentificat nu are rolul "admin".
userRouter.get('/', authorize, authorizeRoles('admin'), getUsers);
userRouter.get('/:id', authorize, authorizeRoles('admin'), getUser);

export default userRouter;
