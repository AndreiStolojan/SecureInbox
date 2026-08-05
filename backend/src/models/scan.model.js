// ─────────────────────────────────────────────────────────────────────────────
// scan.model.js — modelul Mongoose pentru rezultatul unei SCANĂRI de email.
//
// Ce face, pe scurt: definește forma unui document din colecția "scans".
// Un document = rezultatul unei scanări produse de scan.service.js: scorul
// (total + împărțit pe reguli/AI), verdictul, regulile declanșate, semnalele
// și explicația AI. Pattern: "un singur scan curent per email" — la fiecare
// rescanare, scorul vechi se înlocuiește (index unic userId + emailId, vezi
// mai jos).
//
// Detalii: docs/EXPLICATIE_BACKEND.md §3 și §4 (motorul de scanare,
// CURRENT_SCAN_ENGINE_VERSION din scan.service.js).
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';

// Sub-schemă (schemă "îmbricată", folosită ca tip pentru un câmp din schema
// principală) pentru o regulă de scor care s-a declanșat la scanare: numele
// regulii, câte puncte a adăugat și detalii suplimentare. "_id: false" =
// MongoDB nu mai creează un id separat pentru acest sub-document.
const triggeredRuleSchema = new mongoose.Schema(
    {
        rule: {
            type: String,
            required: true,
            trim: true,
        },
        points: {
            type: Number,
            required: true,
        },
        details: {
            type: String,
            default: '',
            trim: true,
        },
    },
    {
        _id: false,
    }
);

// Sub-schemă pentru detaliile potrivirii cu allowlist/blocklist-ul userului:
// din ce listă vine ("allow"/"block"), pe ce tip de valoare s-a potrivit
// ("sender" = adresă exactă, "domain" = domeniu) și valoarea efectivă.
const senderListMatchSchema = new mongoose.Schema(
    {
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
        value: {
            type: String,
            required: true,
            trim: true,
            lowercase: true,
        },
    },
    { _id: false }
);

const scanSchema = new mongoose.Schema(
    {
        // ── Legături către alte colecții ──────────────────────────────────
        // "ref" + ObjectId = referință (legătură) către documentul respectiv,
        // ca o cheie externă (foreign key). "index: true" = MongoDB ține o
        // structură de căutare rapidă pe acest câmp.
        emailId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Email',
            required: true,
            index: true,
        },
        userId: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true,
            index: true,
        },

        // ── Scoruri ────────────────────────────────────────────────────────
        // score = scorul final (reguli + AI, limitat la maximul din
        // scoring.config.js). ruleScore = doar partea din reguli fixe.
        // aiScore = doar partea calculată din semnalele AI (Ollama).
        score: {
            type: Number,
            required: true,
            min: 0,
        },
        ruleScore: {
            type: Number,
            required: true,
            min: 0,
            default: 0,
        },
        aiScore: {
            type: Number,
            required: true,
            min: 0,
            default: 0,
        },

        // ── Verdict și explicații ─────────────────────────────────────────
        // verdict = traducerea scorului într-o categorie de risc, conform
        // pragurilor din scoring.config.js. "enum" = lista valorilor permise.
        verdict: {
            type: String,
            enum: ['safe', 'suspicious', 'likely_phishing'],
            required: true,
        },
        // reasons = lista de motive afișate userului (text simplu, pentru UI).
        reasons: {
            type: [String],
            default: [],
        },
        // triggeredRules = lista detaliată a regulilor de scor declanșate
        // (vezi sub-schema triggeredRuleSchema de mai sus).
        triggeredRules: {
            type: [triggeredRuleSchema],
            default: [],
        },

        // ── Verificare brand (expeditor oficial) ──────────────────────────
        // senderVerifiedBrand = true când emailul a venit de pe un domeniu
        // oficial, controlat de brand (vezi brand-verification.service.js).
        // Acest semnal alimentează stratul de "modificatori de context" pentru
        // expeditori verificați și afișează un badge de "expeditor verificat"
        // în interfață. verifiedBrandName = numele brandului detectat.
        senderVerifiedBrand: {
            type: Boolean,
            default: false,
        },
        verifiedBrandName: {
            type: String,
            default: null,
            trim: true,
        },

        // ── Potrivire cu lista personală a userului ───────────────────────
        // Se completează când expeditorul s-a potrivit cu allowlist-ul sau
        // blocklist-ul userului în momentul scanării (vezi
        // sender-list.service.js). Înregistrează CE intrare a decis rezultatul
        // (vezi sub-schema senderListMatchSchema de mai sus).
        senderListMatch: {
            type: senderListMatchSchema,
            default: null,
        },

        // ── Metadate despre scanare ────────────────────────────────────────
        // scanSource = ce a declanșat scanarea: manual (butonul "Scan again")
        // sau sync (automat, la sincronizare). engineVersion = versiunea
        // motorului de scanare folosită (ex. "rules-ai-v7"), ca să se știe
        // dacă o scanare veche trebuie refăcută cu un motor mai nou.
        scanSource: {
            type: String,
            enum: ['manual', 'sync'],
            default: 'manual',
        },
        engineVersion: {
            type: String,
            default: null,
            trim: true,
        },
        // Amprenta dovezilor de autentificare folosite la scorare. Dacă Gmail,
        // DKIM/ARC sau DMARC se schimbă la sync, scanarea curentă este refăcută.
        authResultsFingerprint: {
            type: String,
            default: null,
            trim: true,
        },
        threatIntelConfigFingerprint: {
            type: String,
            default: null,
            trim: true,
        },
        attachmentConfigFingerprint: {
            type: String,
            default: null,
            trim: true,
        },
        // Amprenta rezultatului de verificare a atașamentelor folosit la
        // scorare. Este doar SHA-256 al semnalelor normalizate, fără datele
        // atașamentului sau hashuri de fișier.
        attachmentAnalysisFingerprint: {
            type: String,
            default: null,
            trim: true,
        },
        // Rezultatul fiecărui provider (success/error/skipped), păstrat pentru
        // observabilitate fără a schimba forma răspunsului public al API-ului.
        providerMeta: {
            type: mongoose.Schema.Types.Mixed,
            default: [],
        },

        // ── Date AI (Ollama), formă liberă ─────────────────────────────────
        // "Mixed" = poate fi orice tip de date (obiect, listă etc.), Mongoose
        // nu îi validează structura — folosit pentru rezultate AI a căror
        // formă variază. aiSignals = semnalele brute returnate de modelul AI.
        // aiExplanation = explicația în limbaj natural generată de AI.
        // aiExplanationMeta = metadate despre explicație (ex. ce model a
        // generat-o, cât a durat).
        aiSignals: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },
        aiExplanation: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },
        aiExplanationMeta: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },

        // Momentul exact al scanării (poate diferi puțin de createdAt/updatedAt
        // dacă scanarea e reprocesată).
        scannedAt: {
            type: Date,
            default: Date.now,
            required: true,
        },
    },
    {
        // timestamps: true => Mongoose adaugă automat createdAt și updatedAt.
        timestamps: true,
    }
);

// Index UNIC pe (userId, emailId): garantează un singur document "scan" per
// email per user — pattern "un singur scan curent". La rescanare, acest
// document se actualizează (upsert), nu se creează altul nou. Un index = o
// structură suplimentară pe care MongoDB o ține pentru căutări rapide și,
// aici, pentru a împiedica duplicate.
scanSchema.index({ userId: 1, emailId: 1 }, { unique: true });

const Scan = mongoose.model('Scan', scanSchema);

export default Scan;
