// ─────────────────────────────────────────────────────────────────────────────
// meta.controller.js — endpoint de "status" pentru userul curent.
//
// Ce face, pe scurt: leagă ruta GET /meta/status de meta.service.js, care
// adună rapid câteva numere (counts) și steaguri (flags) despre contul
// userului (ex. câte emailuri/scanări are, dacă are Gmail conectat, dacă AI-ul
// e activat). Frontend-ul folosește aceste informații pentru a decide ce
// să arate userului.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import { getStatusForUser } from '../services/meta.service.js';

// GET /meta/status — returnează statusul userului autentificat curent
// (counts + flags), folosit de frontend pentru un mic "tablou de bord".
export const getMetaStatus = async (req, res, next) => {
    try {
        const status = await getStatusForUser(req.user._id);

        res.status(200).json({
            success: true,
            data: status,
        });
    } catch (error) {
        next(error);
    }
};
