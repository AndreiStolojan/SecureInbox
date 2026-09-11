// ─────────────────────────────────────────────────────────────────────────────
// action.routes.js — rutele pentru acțiunile manuale ale userului asupra unui
// email (Mark safe / Mark phishing).
//
// Ce face, pe scurt: leagă cele două adrese (URL) de funcțiile din
// action.controller.js, montate sub /api/v1 (vezi app.js). Ambele rute trec
// prin: authorize (verifică tokenul JWT, pune userul pe req.user) și
// validateEmailActionParams (verifică că :id din URL e un id valid de email,
// folosind schema din validations/action.validation.js).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

import {
    markEmailPhishing,
    markEmailSafe,
} from '../controllers/action.controller.js';
import sendErrorResponse from '../common/http/send-error-response.js';
import authorize from '../middlewares/auth.middleware.js';
import { emailActionParamsSchema } from '../validations/action.validation.js';

const actionRouter = Router();

// Middleware de validare: verifică parametrul :id din URL (trebuie să fie un
// id valid de email) folosind schema Joi emailActionParamsSchema. Dacă nu e
// valid, răspunde direct cu 400 (Validation failed) și NU mai ajunge la
// controller. Dacă e valid, `value` (versiunea normalizată) înlocuiește
// req.params, iar cererea continuă spre controller.
const validateEmailActionParams = (req, res, next) => {
    const { error, value } = emailActionParamsSchema.validate(req.params, {
        abortEarly: false,
        stripUnknown: true,
    });

    if (error) {
        const messages = error.details.map((detail) => detail.message);

        return sendErrorResponse(res, 400, 'Validation failed', 'VALIDATION_ERROR', messages);
    }

    req.params = value;
    next();
};

// POST /emails/:id/mark-safe — marchează emailul ca sigur (verdict manual).
actionRouter.post('/emails/:id/mark-safe', authorize, validateEmailActionParams, markEmailSafe);
// POST /emails/:id/mark-phishing — marchează emailul ca phishing (verdict
// manual) și încearcă să mute mesajul în Spam pe Gmail.
actionRouter.post(
    '/emails/:id/mark-phishing',
    authorize,
    validateEmailActionParams,
    markEmailPhishing
);

export default actionRouter;
