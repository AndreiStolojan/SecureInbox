// ─────────────────────────────────────────────────────────────────────────────
// auth.routes.js — rutele de autentificare: /register și /login.
//
// Ce face, pe scurt: leagă adresele URL (rutele) de funcțiile care le tratează,
// trecând cererea prin lanțul de middleware-uri înainte să ajungă la controller:
//   arcjetMiddleware  -> protecție anti-bot / rate limiting
//   validate(schema)  -> verifică req.body cu schema Joi (din validations/)
//   register / login  -> controllerul final (auth.controller.js)
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

import { login, register } from '../controllers/auth.controller.js';
import validate from '../middlewares/validate.middleware.js';
import { registerSchema, loginSchema } from '../validations/auth.validation.js';
import arcjetMiddleware from '../../extras/security/arcjet.middleware.js';

const authRouter = Router();

// POST /api/v1/auth/register — creare cont nou. Întâi arcjet (anti-bot), apoi
// validarea câmpurilor (name, email, password) cu registerSchema.
authRouter.post('/register', arcjetMiddleware, validate(registerSchema), register);
// POST /api/v1/auth/login — autentificare. Validarea câmpurilor (email, password)
// se face cu loginSchema.
authRouter.post('/login', arcjetMiddleware, validate(loginSchema), login);


export default authRouter;
