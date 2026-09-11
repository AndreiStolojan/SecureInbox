// ─────────────────────────────────────────────────────────────────────────────
// mail-account.routes.js — rutele pentru conturile de mail (conectare Gmail,
// sincronizare, setări, deconectare).
//
// Ce face, pe scurt: leagă fiecare adresă (URL) + metodă HTTP de funcția din
// mail-account.controller.js care o tratează, montate sub /api/v1/mail-accounts
// (vezi app.js). `authorize` = middleware care verifică tokenul JWT din header-ul
// Authorization și pune userul curent pe req.user — fără el, cererea e respinsă
// cu 401 (Unauthorized).
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';
import {
    backfillMailAccount,
    disconnectMailAccount,
    getMailAccounts,
    handleGoogleCallback,
    startGoogleConnect,
    syncMailAccount,
    updateMailAccountSettings,
} from '../controllers/mail-account.controller.js';
import authorize from '../middlewares/auth.middleware.js';

const mailAccountRouter = Router();

// Pasul 1 din OAuth Google: userul trebuie autentificat (authorize) ca să
// inițieze conectarea contului său Gmail.
mailAccountRouter.get('/google/start', authorize, startGoogleConnect);
// Pasul 2/3 din OAuth Google: callback apelat DIRECT de Google (browser
// redirect), de aceea NU are middleware authorize — userul e identificat
// prin JWT-ul "state" trimis la pasul 1, verificat în service.
mailAccountRouter.get('/google/callback', handleGoogleCallback);
// Listează conturile de mail conectate de userul curent.
mailAccountRouter.get('/', authorize, getMailAccounts);
// Actualizează setările de sincronizare (ex: syncMaxResults) ale unui cont.
mailAccountRouter.patch('/:id/settings', authorize, updateMailAccountSettings);
// Declanșează manual sincronizarea cu Gmail pentru un cont.
mailAccountRouter.post('/:id/sync', authorize, syncMailAccount);
mailAccountRouter.post('/:id/backfill', authorize, backfillMailAccount);
// Deconectează (șterge) un cont de mail al userului.
mailAccountRouter.delete('/:id', authorize, disconnectMailAccount);

export default mailAccountRouter;
