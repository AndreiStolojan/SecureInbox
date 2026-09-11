// ─────────────────────────────────────────────────────────────────────────────
// action.controller.js — controller pentru acțiunile manuale ale userului
// asupra unui email (Mark safe / Mark phishing).
//
// Ce face, pe scurt: e stratul "subțire" dintre rute (action.routes.js) și
// logica din action.service.js. În loc să repete aceeași structură de două
// ori (Mark safe și Mark phishing au exact același "schelet": citește
// userId+emailId, apelează un service, răspunde cu JSON), folosim o singură
// "fabrică" de handlere — runAction — care primește serviciul concret și
// mesajul de succes, și produce funcția de controller.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    markEmailPhishingForUser,
    markEmailSafeForUser,
} from '../services/action.service.js';

// "Fabrică" de controllere: primește { service, successMessage } și returnează
// o funcție de controller Express (req, res, next). Evită duplicarea codului
// pentru markEmailSafe și markEmailPhishing, care au aceeași formă — diferă
// doar serviciul apelat și mesajul de succes.
const runAction = ({ service, successMessage }) => async (req, res, next) => {
    try {
        const result = await service({
            userId: req.user._id,
            emailId: req.params.id,
        });

        res.status(200).json({
            success: true,
            message: successMessage,
            data: result,
        });
    } catch (error) {
        next(error);
    }
};

// POST /emails/:id/mark-safe — userul confirmă manual că emailul e sigur.
export const markEmailSafe = runAction({
    service: markEmailSafeForUser,
    successMessage: 'Email marked as safe',
});

// POST /emails/:id/mark-phishing — userul marchează manual emailul ca phishing
// (serviciul încearcă și să mute mesajul în Spam pe Gmail).
export const markEmailPhishing = runAction({
    service: markEmailPhishingForUser,
    successMessage: 'Email marked as phishing',
});
