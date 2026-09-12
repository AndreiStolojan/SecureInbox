// ─────────────────────────────────────────────────────────────────────────────
// mail-account.model.js — modelul Mongoose pentru un CONT GMAIL conectat.
//
// Ce face, pe scurt: definește forma unui document din colecția
// "mailaccounts". Un document = un cont Gmail pe care un user l-a conectat
// prin OAuth (vezi GET /api/v1/mail-accounts/google/start). Ține adresa de
// email, tokenii OAuth (CRIPTAȚI înainte de salvare), starea conexiunii și
// setările de sincronizare.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';

const mailAccountSchema = new mongoose.Schema(
    {
        // ── Cui îi apartine contul ────────────────────────────────────────
        // "ref" + ObjectId = referință (legătură) către documentul User
        // corespunzător, ca o cheie externă (foreign key).
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
        },

        // ── Identitatea contului conectat ─────────────────────────────────
        // "enum" = lista valorilor permise; momentan doar Gmail e suportat.
        provider: {
            type: String,
            enum: ['gmail'],
            required: true,
            default: 'gmail',
        },
        accountEmail: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
        },

        // Starea conexiunii: activă, revocată de user (acces retras din
        // contul Google) sau în eroare (ex. tokenul nu mai poate fi reînnoit).
        status: {
            type: String,
            enum: ['active', 'revoked', 'error'],
            default: 'active',
        },

        // ── Tokenii OAuth (criptați) ───────────────────────────────────────
        // accessToken / refreshToken = "biletele" cu care backend-ul cere date
        // de la Gmail în numele userului. Sunt CRIPTATE înainte de a fi
        // salvate în baza de date (nu se ține nimic în clar). accessToken
        // expiră periodic; refreshToken e folosit ca să se obțină unul nou,
        // iar tokenExpiryDate ține minte până când e valid accessToken-ul curent.
        accessToken: {
            type: String,
            required: true,
        },
        refreshToken: {
            type: String,
            default: null,
        },
        tokenExpiryDate: {
            type: Date,
            default: null,
        },

        // ── Sincronizare ───────────────────────────────────────────────────
        // lastSyncedAt = când a avut loc ultima sincronizare cu Gmail.
        // syncMaxResults = câte emailuri se aduc la o sincronizare (limitat
        // între 1 și 50, și trebuie să fie un număr întreg).
        lastSyncedAt: {
            type: Date,
            default: null,
        },
        lastHistoryId: {
            type: String,
            default: null,
        },
        lastFullSyncAt: {
            type: Date,
            default: null,
        },
        syncState: {
            type: String,
            enum: ['never_synced', 'backfilling', 'incremental', 'resync_required'],
            default: 'never_synced',
        },
        backfillPageToken: {
            type: String,
            default: null,
        },
        backfillCompletedAt: {
            type: Date,
            default: null,
        },
        syncLock: {
            type: new mongoose.Schema(
                {
                    lockedAt: { type: Date, required: true },
                    lockedBy: { type: String, required: true },
                },
                { _id: false }
            ),
            default: null,
        },
        // Watch metadata never advances the authoritative T3 sync cursor.
        watchExpiration: { type: Date, default: null },
        watchRegisteredAt: { type: Date, default: null },
        watchHistoryId: { type: String, default: null },
        watchStatus: {
            type: String,
            enum: ['active', 'expired', 'failed', 'disabled'],
            default: 'disabled',
        },
        watchFailureCount: { type: Number, min: 0, default: 0 },
        lastPushNotificationAt: { type: Date, default: null },
        syncMaxResults: {
            type: Number,
            default: 10,
            min: [1, 'syncMaxResults must be at least 1'],
            max: [50, 'syncMaxResults must be at most 50'],
            validate: {
                validator: Number.isInteger,
                message: 'syncMaxResults must be an integer',
            },
        },
    },
    {
        // timestamps: true => Mongoose adaugă automat createdAt și updatedAt.
        timestamps: true,
    }
);

// Index UNIC pe (userId, provider): un user poate avea cel mult un cont
// conectat per furnizor (momentan doar Gmail). Un index = o structură
// suplimentară pe care MongoDB o ține pentru căutări rapide și, aici, pentru
// a împiedica intrări duplicate.
mailAccountSchema.index({ userId: 1, provider: 1 }, { unique: true });
mailAccountSchema.index({ accountEmail: 1, provider: 1, status: 1 });

const MailAccount = mongoose.model('MailAccount', mailAccountSchema);

export default MailAccount;
