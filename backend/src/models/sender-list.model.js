// ─────────────────────────────────────────────────────────────────────────────
// sender-list.model.js — modelul Mongoose pentru o intrare în lista
// allowlist/blocklist a userului.
//
// Ce face, pe scurt: definește forma unui document din colecția
// "senderlistentries". Un document = o regulă personală a userului de tipul
// "am încredere în acest expeditor/domeniu" (allow) sau "blochează acest
// expeditor/domeniu" (block). Folosit de scan.service.js (prin
// sender-list.service.js) ca semnal în calculul scorului de risc.
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';

const senderListEntrySchema = new mongoose.Schema(
    {
        // ── Cui îi apartine regula ─────────────────────────────────────────
        // "ref" + ObjectId = referință (legătură) către documentul User,
        // ca o cheie externă (foreign key). "index: true" = MongoDB ține o
        // structură de căutare rapidă pe acest câmp.
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
            index: true,
        },

        // ── Ce fel de regulă este ──────────────────────────────────────────
        // listType: "allow" (permite/încredere) sau "block" (blochează).
        // kind: regula se aplică unui expeditor exact ("sender", ex.
        // "cineva@exemplu.com") sau unui domeniu întreg ("domain", ex.
        // "exemplu.com"). "enum" = lista valorilor permise.
        listType: {
            type: String,
            enum: ['allow', 'block'],
            required: true,
        },
        kind: {
            type: String,
            enum: ['sender', 'domain'],
            required: true,
        },

        // Valoarea efectivă (adresa de email sau domeniul) la care se aplică
        // regula. Salvată cu litere mici, fără spații, ca să se compare
        // consistent indiferent cum a fost scrisă.
        value: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
        },
    },
    {
        // timestamps: true => Mongoose adaugă automat createdAt și updatedAt.
        timestamps: true,
    }
);

// ── Index unic + regulă de excludere mutuală ───────────────────────────────
// O intrare per (user, kind, value): un expeditor sau domeniu are exact o
// singură intrare, al cărei listType e fie "allow", fie "block" — nu poate fi
// simultan pe ambele liste. Un index unic = MongoDB garantează că nu pot
// exista două documente cu aceeași combinație de (userId, kind, value).
senderListEntrySchema.index({ userId: 1, kind: 1, value: 1 }, { unique: true });

const SenderListEntry = mongoose.model('SenderListEntry', senderListEntrySchema);

export default SenderListEntry;
