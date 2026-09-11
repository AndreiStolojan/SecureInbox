// ─────────────────────────────────────────────────────────────────────────────
// error.middleware.js — handler-ul CENTRAL de erori al backend-ului.
//
// Ce face, pe scurt: e ultimul "filtru" din lanțul de middleware-uri (înregistrat
// ultimul în app.js). Orice eroare aruncată în servicii/controllere (cu
// createError sau prin next(error)) ajunge aici, indiferent de unde a venit, și
// e transformată într-un singur format JSON uniform:
//   { success: false, statusCode, message, code?, errors? }
// Așa, frontend-ul tratează toate erorile la fel, fără cazuri speciale.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

// Express recunoaște un middleware ca fiind "de erori" doar dacă are EXACT 4
// parametri (err, req, res, next). "next" nu e folosit aici, dar trebuie păstrat
// în semnătura funcției, altfel Express nu îl mai tratează ca handler de erori.
// eslint-disable-next-line no-unused-vars
const errorMiddleware = (err, req, res, next) => {
    // Valori implicite, dacă eroarea nu specifică altceva (createError de obicei
    // le setează pe toate).
    let statusCode = err.statusCode || 500;
    let message = err.message || 'Server Error';
    let errors = err.errors || [];
    let code = err.code || null;

    // CastError = Mongoose nu a putut converti un id (ex: id invalid în URL) ->
    // tratăm ca "resursă inexistentă".
    if (err.name === 'CastError') {
        statusCode = 404;
        message = 'Resource not found';
        code = 'RESOURCE_NOT_FOUND';
    }

    // Codul 11000 = eroare de duplicat la nivel de MongoDB (ex: încercare de a
    // crea un user cu un email care există deja, dacă există index unic).
    if (err.code === 11000) {
        statusCode = 409;
        message = 'Duplicate field value entered';
        code = 'DUPLICATE_FIELD';
    }

    // ValidationError = eroare de validare ridicată direct de Mongoose (nu de
    // Joi, care e tratat în validate.middleware.js). Extragem mesajele din
    // fiecare câmp invalid.
    if (err.name === 'ValidationError') {
        statusCode = 400;
        message = 'Validation failed';
        errors = Object.values(err.errors).map((value) => value.message);
        code = 'VALIDATION_ERROR';
    }

    // Forma de bază a răspunsului trimis către frontend.
    const payload = {
        success: false,
        statusCode,
        message,
    };

    // Codul (ex: "VALIDATION_ERROR") e adăugat doar dacă există — frontend-ul îl
    // folosește pentru a alege un mesaj specific de afișat userului.
    if (code) {
        payload.code = code;
    }

    // Lista detaliată de erori (ex: mesaje Joi/Mongoose) e adăugată doar dacă
    // există cel puțin una.
    if (errors.length > 0) {
        payload.errors = errors;
    }

    // În afara producției, logăm în consolă orice eroare de server (5xx), ca să
    // fie vizibilă în timpul dezvoltării/testării.
    if (process.env.NODE_ENV !== 'production' && statusCode >= 500) {
        console.error('[error]', err);
    }

    res.status(statusCode).json(payload);
};

export default errorMiddleware;
