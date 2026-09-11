// ─────────────────────────────────────────────────────────────────────────────
// validate.middleware.js — middleware GENERIC de validare a datelor primite în
// cerere (req.body), folosind o schemă Joi.
//
// Ce face, pe scurt: e o "fabrică" de middleware-uri — primește o schemă Joi
// (definită în backend/src/validations/*.js) și returnează un middleware care
// verifică req.body cu acea schemă. Dacă datele nu respectă schema (câmpuri
// lipsă, tip greșit etc.), cererea e respinsă cu status 400 și lista de erori,
// fără să mai ajungă la controller. Dacă sunt valide, req.body e înlocuit cu
// versiunea "curățată" (value) și cererea continuă.
//
// Folosit pe orice rută care primește date de la user, de ex.:
//   authRouter.post('/register', validate(registerSchema), register);
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import sendErrorResponse from '../common/http/send-error-response.js';

// validate este o funcție care, dată o schemă Joi, returnează middleware-ul
// efectiv (req, res, next) => {...}. Acest tipar se numește "middleware factory"
// (fabrică de middleware), pentru că permite reutilizarea aceleiași logici de
// validare cu scheme diferite pe rute diferite.
const validate = (schema) => {
    return (req, res, next) => {
        // schema.validate verifică req.body fără să se opună la prima eroare
        // (abortEarly: false -> colectează TOATE erorile, nu doar prima) și
        // elimină câmpurile care nu sunt definite în schemă (stripUnknown).
        const { error, value } = schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true,
        });

        if (error) {
            // Transformăm lista de erori Joi într-o listă simplă de mesaje text,
            // ca să fie ușor de afișat în frontend.
            const messages = error.details.map((detail) => detail.message);

            return sendErrorResponse(res, 400, 'Validation failed', 'VALIDATION_ERROR', messages);
        }

        // Înlocuim req.body cu varianta validată/curățată (value), pentru ca
        // restul lanțului (controller, service) să primească date "sigure".
        req.body = value;
        next();
    };
};

export default validate;
