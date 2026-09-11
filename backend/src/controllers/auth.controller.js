// ─────────────────────────────────────────────────────────────────────────────
// auth.controller.js — controllerul pentru autentificare (register / login).
//
// Ce face, pe scurt: este "subțire" intenționat — primește cererea HTTP, citește
// datele trimise de user (req.body, deja validate de validate.middleware.js),
// cheamă serviciul corespunzător din auth.service.js (acolo e toată logica) și
// împachetează rezultatul într-un răspuns JSON standard. NU conține logică de
// business.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { loginUser, registerUser } from '../services/auth.service.js';

// Înregistrare cont nou. Apelează registerUser (auth.service.js), care creează
// userul cu parola criptată și emite un token JWT.
export const register = async (req, res, next) => {
    try {
        const authResult = await registerUser(req.body);

        res.status(201).json({
            success: true,
            message: 'User successfully created',
            data: authResult,
        });
    } catch (err) {
        // Orice eroare (ex: email deja folosit) e trimisă către error.middleware,
        // care o transformă într-un JSON uniform de eroare.
        next(err);
    }
};

// Autentificare cont existent. Apelează loginUser (auth.service.js), care
// verifică parola și emite un token JWT nou.
export const login = async (req, res, next) => {
    try {
        const authResult = await loginUser(req.body);

        res.status(200).json({
            success: true,
            message: 'User successfully signed in',
            data: authResult,
        });
    } catch (err) {
        next(err);
    }
};

// Alias-uri (nume alternative) pentru aceleași funcții, folosite eventual de
// alte rute/teste care preferă denumirea "signUp"/"signIn".
export const signUp = register;
export const signIn = login;
