// ─────────────────────────────────────────────────────────────────────────────
// sender-list.controller.js — controllerul pentru listele de expeditori ale userului
// (allowlist = "de încredere" / blocklist = "blocat").
//
// Ce face, pe scurt: primește cererile HTTP pentru listarea, adăugarea și
// ștergerea regulilor de expeditor/domeniu ale userului logat și apelează
// sender-list.service.js pentru logica reală. Nu face calcule el însuși —
// doar "traduce" cererea/răspunsul HTTP.
//
// Aceste reguli sunt folosite de scan.service.js la scanare, pentru a ajusta
// scorul de risc (vezi sender-list.service.js pentru detalii).
//
// Endpoint-uri (vezi sender-list.routes.js):
//   GET    /sender-lists[?withMatchCounts=1]
//   POST   /sender-lists
//   DELETE /sender-lists/:id
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import {
    addSenderListEntry,
    getSenderListEntries,
    removeSenderListEntry,
} from '../services/sender-list.service.js';

// GET /sender-lists
// Returnează toate regulile (allow + block) ale userului logat. Dacă query
// param-ul withMatchCounts=1 e prezent, fiecare regulă include și câte
// emailuri din inbox se potrivesc cu ea (util pentru afișare în UI, ex.
// "acest domeniu blocat are 12 emailuri").
export const listSenderListEntries = async (req, res, next) => {
    try {
        const entries = await getSenderListEntries({
            userId: req.user._id,
            withMatchCounts: req.query.withMatchCounts === '1',
        });

        res.status(200).json({
            success: true,
            data: { entries },
        });
    } catch (error) {
        next(error);
    }
};

// POST /sender-lists
// Adaugă o regulă nouă (allow sau block) pe un sender (adresă exactă) sau pe
// un domeniu. Dacă regula există deja, nu se mai creează una identică — se
// returnează cea existentă cu status 200 (în loc de 201 "creat"). Serviciul
// verifică și conflictele (ex. același sender pe ambele liste, sau conflict
// încrucișat sender/domeniu) și aruncă eroare 409 LIST_CONFLICT.
export const createSenderListEntry = async (req, res, next) => {
    try {
        const { listType, kind, value } = req.body;
        const { entry, created } = await addSenderListEntry({
            userId: req.user._id,
            listType,
            kind,
            value,
        });

        // created = true -> 201 (resursă nouă); created = false -> 200 (exista deja).
        res.status(created ? 201 : 200).json({
            success: true,
            message: created ? 'List entry added' : 'List entry already exists',
            data: { entry },
        });
    } catch (error) {
        next(error);
    }
};

// DELETE /sender-lists/:id
// Șterge o regulă a userului după id-ul ei (validat ca ObjectId Mongo de
// middleware-ul de validare din rute, înainte să ajungă aici).
export const deleteSenderListEntry = async (req, res, next) => {
    try {
        const entry = await removeSenderListEntry({
            userId: req.user._id,
            entryId: req.params.id,
        });

        res.status(200).json({
            success: true,
            message: 'List entry removed',
            data: { entry },
        });
    } catch (error) {
        next(error);
    }
};
