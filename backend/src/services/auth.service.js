// ─────────────────────────────────────────────────────────────────────────────
// auth.service.js — autentificare: înregistrare, login și emiterea token-ului JWT.
//
// Ce face, pe scurt: la ÎNREGISTRARE creează un user nou cu parola CRIPTATĂ
// (nu se ține parola "în clar" în baza de date), iar la LOGIN verifică parola
// introdusă față de cea criptată. În ambele cazuri, dacă totul e OK, emite un
// JWT (un "bilet de acces" semnat) pe care frontend-ul îl trimite apoi la fiecare
// cerere în antetul "Authorization: Bearer <token>". Nu există logout pe backend —
// frontend-ul pur și simplu șterge token-ul.
//
// Detalii: docs/architecture.md.
// ─────────────────────────────────────────────────────────────────────────────

import bcrypt from 'bcryptjs'; // bibliotecă pentru criptarea (hash-uirea) parolelor
import jwt from 'jsonwebtoken'; // bibliotecă pentru generarea/verificarea token-urilor JWT

import createError from '../common/errors/create-error.js';
import { JWT_EXPIRES_IN, JWT_SECRET } from '../config/env.js';
import User from '../models/user.model.js';

// Transformă un document User (din MongoDB) într-un obiect "public", sigur de
// trimis către frontend — fără parolă (passwordHash) sau alte câmpuri interne.
export const toPublicUser = (user) => ({
    _id: user._id,
    name: user.name,
    email: user.email,
    role: user.role,
    settings: {
        aiEnabled: Boolean(user.settings?.aiEnabled),
        alertsEnabled: Boolean(user.settings?.alertsEnabled),
    },
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
});

// Forma comună a răspunsului trimis la register/login: token-ul JWT + datele
// publice ale userului.
const buildAuthResponse = (user, token) => ({
    token,
    user: toPublicUser(user),
});

// Generează un JWT care conține id-ul userului, semnat cu JWT_SECRET (cheia
// secretă din .env) și valid un timp limitat (JWT_EXPIRES_IN).
const signToken = (userId) => jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

// Înregistrare cont nou.
export const registerUser = async ({ name, email, password }) => {
    const existingUser = await User.findOne({ email });

    // Nu permitem două conturi cu același email.
    if (existingUser) {
        throw createError('User already exists', 409, [], 'USER_ALREADY_EXISTS');
    }

    // "salt" = un șir aleator adăugat parolei înainte de hash, ca să nu se poată
    // ghici parolele identice din hash-uri identice. bcrypt face hash-ul: o
    // transformare ireversibilă — din hash nu se mai poate reface parola.
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Se salvează doar parola criptată (passwordHash), niciodată parola brută.
    const createdUser = await User.create({ name, email, passwordHash: hashedPassword, role: 'user' });

    const token = signToken(createdUser._id);

    return buildAuthResponse(createdUser, token);
};

// Autentificare cont existent.
export const loginUser = async ({ email, password }) => {
    // passwordHash e exclus implicit din interogări (vezi modelul User);
    // .select('+passwordHash') îl include explicit aici, ca să-l putem compara.
    const user = await User.findOne({ email }).select('+passwordHash');

    if (!user) {
        throw createError('Invalid email or password', 401, [], 'INVALID_CREDENTIALS');
    }

    // bcrypt.compare hash-uiește parola introdusă cu același salt și compară
    // rezultatul cu passwordHash din baza de date.
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

    if (!isPasswordValid) {
        throw createError('Invalid password', 401, [], 'INVALID_CREDENTIALS');
    }

    const token = signToken(user._id);

    return buildAuthResponse(user, token);
};
