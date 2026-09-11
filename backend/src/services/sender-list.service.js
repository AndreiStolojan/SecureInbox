// ─────────────────────────────────────────────────────────────────────────────
// sender-list.service.js — al doilea strat de context peste motorul de reguli:
// listele de expeditori ale userului (allowlist / blocklist).
//
// Ce face, pe scurt: gestionează listele personale ale fiecărui user — "am
// încredere în acest expeditor/domeniu" (allow = trusted) sau "blochez acest
// expeditor/domeniu" (block = blocked). La scanare, scan.service.js întreabă
// acest fișier "se potrivește emailul cu vreo regulă a userului?" și ajustează
// scorul în consecință:
//   - Allowlist ("de încredere") -> semnalele CONTEXTUALE (urgență, multe
//     linkuri etc.) sunt reduse, dar semnalele CRITICE (parolă cerută,
//     atașamente periculoase, link către IP, credențiale, punycode) rămân la
//     greutate plină. Deci "de încredere" nu înseamnă "mereu sigur".
//   - Blocklist ("blocat") -> se adaugă fix punctajul USER_BLOCKLIST_RULE_POINTS
//     (= pragul de likely_phishing), deci verdictul likely_phishing e garantat.
//     Userul a decis explicit, nu mai e o euristică ce poate greși.
//
// Regulile de potrivire (vezi getSenderListContextForEmail / matchSenderListEntries):
//   - O regulă pe ADRESĂ EXACTĂ are mereu prioritate față de o regulă pe DOMENIU
//     (criteriul mai specific câștigă). Ex: boss@firma.com e "trusted" chiar
//     dacă firma.com e "blocked".
//   - Regulile pe domeniu se potrivesc "suffix-aware" (ca la verificarea de
//     brand): o regulă pentru paypal.com se potrivește cu mail.paypal.com, dar
//     NU cu evil-paypal.com.
//   - Excludere mutuală: aceeași valoare (sender/domeniu) nu poate fi simultan pe
//     allow și pe block — garantat de indexul unic (userId, kind, value) din
//     model + verificarea de conflict din addSenderListEntry (eroare 409 cu
//     codul LIST_CONFLICT).
//   - Conflict încrucișat (cross-kind): dacă un sender e pe o listă și domeniul
//     lui e pe lista opusă (sau invers), userul ar avea o regulă "moartă" fără
//     să-și dea seama — așa că respingem operația cu 409 LIST_CONFLICT, cu mesaj
//     explicativ (vezi findOppositeCoverageConflict).
//
// Detalii: docs/detection-engine.md.
// ─────────────────────────────────────────────────────────────────────────────

import mongoose from 'mongoose';
import { mapWithConcurrency } from '../common/async/map-with-concurrency.js';

import createError from '../common/errors/create-error.js';
import SenderListEntry from '../models/sender-list.model.js';
import Email from '../models/email.model.js';
// Aceiași pași de aggregation folosiți de lista de emailuri și de numărătorile
// din dashboard — importați (nu copiați), ca defalcarea pe categorii de aici să
// nu poată "devia" de la restul aplicației.
import {
    buildLatestScanLookupStages,
    buildEmailStateStages,
} from './email.service.js';

// Normalizează o adresă de expeditor: dacă valoarea e de forma
// `Nume Afișat <adresa@exemplu.com>`, extrage doar adresa dintre `< >`, apoi
// elimină spațiile și pune totul cu litere mici. Așa comparăm mereu adrese
// "curate", indiferent cum apar ele în antetul From al emailului.
export const normalizeSenderAddress = (value) => {
    const raw = String(value || '').trim();
    const openingBracket = raw.indexOf('<');
    const closingBracket = raw.indexOf('>', openingBracket + 1);
    const address =
        openingBracket >= 0 && closingBracket > openingBracket + 1
            ? raw.slice(openingBracket + 1, closingBracket)
            : raw;

    return address.trim().toLowerCase();
};

// Normalizează un domeniu pentru listă: litere mici, fără spații, fără
// prefixul "www." și fără punctul final (la fel ca în brand-verification.service.js).
export const normalizeListDomain = (value) =>
    String(value || '')
        .trim()
        .toLowerCase()
        .replace(/^www\./, '')
        .replace(/\.$/, '');

// Alege normalizarea corectă în funcție de tipul regulii: "sender" (adresă
// exactă) sau "domain" (domeniu întreg).
const normalizeValue = (kind, value) =>
    kind === 'sender' ? normalizeSenderAddress(value) : normalizeListDomain(value);

// Comparație "suffix-aware" pentru domenii: domeniul expeditorului se
// potrivește cu regula de listă dacă e identic sau e subdomeniu al ei
// (ex: domeniul din regulă "paypal.com" se potrivește cu "mail.paypal.com").
const domainMatches = (senderDomain, listedDomain) =>
    senderDomain === listedDomain || senderDomain.endsWith(`.${listedDomain}`);

// Etichete folosite în mesajele de eroare arătate userului ("trusted" / "blocked").
const LIST_TYPE_LABELS = {
    allow: 'trusted',
    block: 'blocked',
};

// Transformă un document din baza de date într-o formă "publică", sigură de
// trimis către frontend (fără câmpuri interne ale Mongoose).
const toPublicEntry = (entry) => ({
    id: entry._id,
    listType: entry.listType,
    kind: entry.kind,
    value: entry.value,
    createdAt: entry.createdAt,
});

// Scapă caracterele speciale dintr-un șir, ca să poată fi folosit în siguranță
// într-o expresie regulată (regex) construită dinamic.
const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Toate categoriile posibile de risc, pornite de la 0 — la fel ca în
// getRiskBucketCountsForUser: răspunsul are mereu toate cheile, deci frontend-ul
// nu trebuie să verifice dacă o categorie există înainte să o afișeze.
const emptyBucketCounts = () => ({
    safe: 0,
    needs_review: 0,
    quarantine: 0,
    reviewed_safe: 0,
    confirmed_phishing: 0,
    unscanned: 0,
});

/*
 * Filtrul de potrivire al unei reguli, folosit ca prim pas ($match) al
 * aggregation-ului. Regulile de tip "sender" verifică adresa din antetul From
 * brut; regulile de tip "domain" verifică domeniul expeditorului suffix-aware
 * (aceeași logică ca la potrivirea folosită în scanare) — exact aceleași două
 * expresii regulate ca înainte, ca numărul afișat să nu se schimbe.
 */
const buildEntryMatch = ({ userId, entry }) => {
    if (entry.kind === 'sender') {
        return {
            userId,
            from: { $regex: escapeRegex(entry.value), $options: 'i' },
        };
    }

    return {
        userId,
        senderDomain: { $regex: `(^|\\.)${escapeRegex(entry.value)}$`, $options: 'i' },
    };
};

/*
 * Câte emailuri sincronizate sunt acoperite de o regulă, în acest moment — și
 * cum se împart ele pe categorii de risc.
 *
 * `riskBucket` NU e stocat pe documentul de email: se derivă din ultimul scan +
 * decizia manuală a userului. De aceea nu se poate face un simplu
 * countDocuments pe categorii, ci un aggregation cu aceiași pași ca la lista de
 * emailuri (lookup pe cel mai recent scan -> câmpurile de stare -> grupare
 * după riskBucket). Totalul se calculează din sumele grupurilor, ca să rămână
 * mereu egal cu suma defalcării (un total dintr-o a doua interogare ar putea
 * să difere dacă se sincronizează emailuri între cele două).
 */
const countMatchingEmails = async ({ userId, entry }) => {
    const results = await Email.aggregate([
        { $match: buildEntryMatch({ userId, entry }) },
        ...buildLatestScanLookupStages(),
        ...buildEmailStateStages(),
        { $group: { _id: '$riskBucket', count: { $sum: 1 } } },
    ]);

    const byBucket = emptyBucketCounts();
    let total = 0;

    for (const row of results) {
        if (Object.hasOwn(byBucket, row._id)) {
            byBucket[row._id] = row.count;
        }
        total += row.count;
    }

    return { total, byBucket };
};

// Returnează toate regulile (allow + block) ale userului, cele mai recente
// primele. Dacă `withMatchCounts` e true, pentru fiecare regulă calculează și
// câte emailuri existente se potrivesc cu ea (`matchedEmails`, ca înainte) plus
// defalcarea lor pe categorii de risc (`matchedByBucket`), folosită în UI.
export const getSenderListEntries = async ({ userId, withMatchCounts = false }) => {
    const entries = await SenderListEntry.find({ userId }).sort({ createdAt: -1 });

    if (!withMatchCounts) {
        return entries.map(toPublicEntry);
    }

    // Aggregation-ul nu trece prin schema Mongoose, deci nu face conversia
    // automată string -> ObjectId; o facem explicit aici, o singură dată.
    const userObjectId = new mongoose.Types.ObjectId(String(userId));

    // At most four count queries per request; preserve rule order and reject failures.
    return mapWithConcurrency(entries, 4, async (entry) => {
        const { total, byBucket } = await countMatchingEmails({
            userId: userObjectId,
            entry,
        });

        return {
            ...toPublicEntry(entry),
            matchedEmails: total,
            matchedByBucket: byBucket,
        };
    });
};

// Extrage domeniul dintr-o adresă de email (partea după "@"), normalizat.
// Ex: "boss@company.com" -> "company.com". Dacă nu există "@", returnează "".
const senderAddressDomain = (address) => {
    const atIndex = address.lastIndexOf('@');

    return atIndex === -1 ? '' : normalizeListDomain(address.slice(atIndex + 1));
};

/*
 * Verificare de conflict încrucișat (cross-kind): o regulă pe expeditor exact și
 * o regulă pe domeniu care îl acoperă NU pot avea tipuri opuse. Ex: dacă userul
 * are "block boss@x.com" și ar adăuga "trust x.com" (sau invers), una dintre
 * cele două reguli ar deveni "moartă" — precedența (sender > domain) ar alege
 * un câștigător, dar userul nu și-ar da seama de ce. De aceea respingem
 * contradicția din start, cu un mesaj clar care explică ce trebuie șters mai întâi.
 */
const findOppositeCoverageConflict = async ({ userId, listType, kind, value }) => {
    // Tipul opus al listei: dacă adăugăm pe "allow", verificăm conflicte cu "block"
    // (și invers).
    const oppositeType = listType === 'allow' ? 'block' : 'allow';

    if (kind === 'sender') {
        // Cazul 1: adăugăm o regulă pe ADRESĂ. Verificăm dacă domeniul acelei
        // adrese e deja pe lista opusă.
        const domain = senderAddressDomain(value);

        if (!domain) {
            return null;
        }

        const domainEntries = await SenderListEntry.find({
            userId,
            kind: 'domain',
            listType: oppositeType,
        });
        const covering = domainEntries.find((entry) => domainMatches(domain, entry.value));

        return covering
            ? `This sender's domain (${covering.value}) is already on the ${LIST_TYPE_LABELS[oppositeType]} list. Remove the domain rule first.`
            : null;
    }

    // Cazul 2: adăugăm o regulă pe DOMENIU. Verificăm dacă există adrese exacte
    // (sender) deja pe lista opusă, ale căror domenii sunt acoperite de acest domeniu.
    const senderEntries = await SenderListEntry.find({
        userId,
        kind: 'sender',
        listType: oppositeType,
    });
    const covered = senderEntries.filter((entry) =>
        domainMatches(senderAddressDomain(entry.value), value)
    );

    if (covered.length === 0) {
        return null;
    }

    // Construim mesajul de eroare, cu gramatică corectă pentru singular/plural
    // (1 expeditor afectat vs. mai mulți).
    const sample = covered[0].value;
    const others = covered.length - 1;

    return `${covered.length === 1 ? `The sender ${sample}` : `${sample}${others > 0 ? ` and ${others} other sender${others > 1 ? 's' : ''}` : ''}`} from this domain ${covered.length === 1 ? 'is' : 'are'} already on the ${LIST_TYPE_LABELS[oppositeType]} list. Remove ${covered.length === 1 ? 'that rule' : 'those rules'} first.`;
};

// Adaugă o regulă nouă (allow/block, sender/domain) pentru userul curent.
// Pași: normalizează valoarea -> verifică dacă există deja exact aceeași regulă
// (idempotent, dacă e identică) -> verifică dacă există un conflict cu lista
// opusă pe același criteriu -> verifică conflicte încrucișate (sender vs domain)
// -> salvează în baza de date.
export const addSenderListEntry = async ({ userId, listType, kind, value }) => {
    const normalizedValue = normalizeValue(kind, value);

    if (!normalizedValue) {
        throw createError('A value is required', 400, [], 'INVALID_LIST_VALUE');
    }

    const existing = await SenderListEntry.findOne({ userId, kind, value: normalizedValue });

    if (existing) {
        // Aceeași regulă, același tip de listă -> nu mai e nimic de făcut, dar
        // nu e o eroare (idempotent).
        if (existing.listType === listType) {
            return { entry: toPublicEntry(existing), created: false };
        }

        // Aceeași valoare (sender/domeniu), dar deja pe lista OPUSĂ -> conflict
        // direct, trebuie ștearsă mai întâi.
        throw createError(
            `This ${kind} is already on the ${LIST_TYPE_LABELS[existing.listType]} list. Remove it from there first.`,
            409,
            [],
            'LIST_CONFLICT'
        );
    }

    // Verificăm conflictele încrucișate (sender acoperit de un domeniu opus, sau
    // domeniu care acoperă un sender opus).
    const coverageConflict = await findOppositeCoverageConflict({
        userId,
        listType,
        kind,
        value: normalizedValue,
    });

    if (coverageConflict) {
        throw createError(coverageConflict, 409, [], 'LIST_CONFLICT');
    }

    try {
        const entry = await SenderListEntry.create({
            userId,
            listType,
            kind,
            value: normalizedValue,
        });

        return { entry: toPublicEntry(entry), created: true };
    } catch (error) {
        // Cursă pe indexul unic: două cereri simultane care adaugă aceeași regulă
        // în același timp — una ajunge prima, cealaltă primește eroarea de
        // duplicat de la MongoDB (codul 11000). O transformăm tot într-un
        // LIST_CONFLICT, ca să fie tratată uniform de frontend.
        if (error?.code === 11000) {
            throw createError(
                `This ${kind} is already on a list.`,
                409,
                [],
                'LIST_CONFLICT'
            );
        }

        throw error;
    }
};

// Șterge o regulă a userului, identificată după id. Verifică mai întâi că id-ul
// e un ObjectId Mongo valid (altfel query-ul ar arunca o eroare neclară), apoi
// se asigură că regula aparține userului (userId în filtru) — un user nu poate
// șterge regulile altui user.
export const removeSenderListEntry = async ({ userId, entryId }) => {
    if (!mongoose.Types.ObjectId.isValid(String(entryId))) {
        throw createError('Invalid list entry id', 400, [], 'INVALID_LIST_ENTRY_ID');
    }

    const deleted = await SenderListEntry.findOneAndDelete({ _id: entryId, userId });

    if (!deleted) {
        throw createError('List entry not found', 404, [], 'LIST_ENTRY_NOT_FOUND');
    }

    return toPublicEntry(deleted);
};

// Rezultatul standard "nicio regulă nu se aplică acestui email" — folosit ca
// valoare implicită de context pentru scoring.
const buildEmptyListContext = () => ({
    senderAllowlisted: false,
    senderBlocklisted: false,
    listMatch: null,
});

/*
 * Funcția "pură" de potrivire, separată de interogarea bazei de date, ca să
 * poată fi testată unitar (fără MongoDB) și folosită de motorul de scanare.
 * Precedență: o regulă pe adresă exactă (sender) câștigă în fața unei reguli
 * pe domeniu (suffix-aware) — criteriul mai specific are întâietate.
 */
export const matchSenderListEntries = ({ entries = [], senderAddress, senderDomain }) => {
    const address = normalizeSenderAddress(senderAddress);
    const domain = normalizeListDomain(senderDomain);

    // Caz 1: există o regulă pe adresa EXACTĂ a expeditorului?
    const senderEntry = address
        ? entries.find((entry) => entry.kind === 'sender' && entry.value === address)
        : null;
    // Caz 2: există o regulă pe domeniul expeditorului (suffix-aware)?
    const domainEntry = domain
        ? entries.find((entry) => entry.kind === 'domain' && domainMatches(domain, entry.value))
        : null;
    // Adresa exactă are prioritate față de domeniu.
    const match = senderEntry || domainEntry || null;

    if (!match) {
        return buildEmptyListContext();
    }

    // Returnăm contextul folosit de scan.service.js pentru a ajusta scorul:
    // dacă regula e "allow" -> senderAllowlisted true; dacă e "block" ->
    // senderBlocklisted true. listMatch ajută la explicația afișată userului.
    return {
        senderAllowlisted: match.listType === 'allow',
        senderBlocklisted: match.listType === 'block',
        listMatch: {
            listType: match.listType,
            kind: match.kind,
            value: match.value,
        },
    };
};

// Punctul de intrare folosit de motorul de scanare: pentru un email dat,
// încarcă toate regulile userului din baza de date și calculează contextul de
// listă (allowlist/blocklist) pentru acel email. Dacă nu avem nicio informație
// despre expeditor, returnăm direct contextul "gol", fără să interogăm baza de date.
export const getSenderListContextForEmail = async ({ userId, senderAddress, senderDomain }) => {
    if (!senderAddress && !senderDomain) {
        return buildEmptyListContext();
    }

    const entries = await SenderListEntry.find({ userId });

    return matchSenderListEntries({ entries, senderAddress, senderDomain });
};
