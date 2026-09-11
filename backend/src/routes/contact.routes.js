// ─────────────────────────────────────────────────────────────────────────────
// contact.routes.js — definește ruta HTTP sub `/api/v1/contact`.
//
// Ce face, pe scurt: o singură rută — trimiterea mesajului de contact.
// Pe lângă autentificare și validare, ruta este protejată și de Arcjet
// (vezi authorize și middleware-urile globale din app.js), care limitează
// numărul de cereri și blochează boții, ca formularul să nu fie folosit
// pentru spam.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

import { sendContactMessage } from '../controllers/contact.controller.js';
import authorize from '../middlewares/auth.middleware.js';
import validate from '../middlewares/validate.middleware.js';
import { contactMessageSchema } from '../validations/contact.validation.js';

const contactRouter = Router();

// validate(contactMessageSchema) verifică forma body-ului (subject + message)
// înainte ca cererea să ajungă la controller.
contactRouter.post('/message', authorize, validate(contactMessageSchema), sendContactMessage);

export default contactRouter;
