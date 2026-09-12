import crypto from 'node:crypto';

import UrlReputation from '../../models/url-reputation.model.js';

const MIN_TTL_MS = 60 * 1000;
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const ALLOWED_SOURCES = new Set(['web_risk', 'urlhaus', 'rdap', 'redirect']);
const ALLOWED_SUBJECT_TYPES = new Set(['url', 'domain']);
const ALLOWED_STATUSES = new Set([
    'malicious',
    'clean',
    'found',
    'not_found',
    'unavailable',
    'blocked',
    'resolved',
]);

const toPlainObject = async (query) => {
    if (query && typeof query.lean === 'function') return query.lean();
    return query;
};

const requireEnum = (value, allowed, label) => {
    if (!allowed.has(value)) throw new TypeError(`Invalid reputation cache ${label}`);
    return value;
};

const requireSubject = (value) => {
    if (typeof value !== 'string' || value.length === 0 || value.length > 8192) {
        throw new TypeError('Invalid reputation cache subject');
    }
    return value;
};

const requireDate = (value) => {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) throw new TypeError('Invalid reputation cache clock');
    return date;
};

export const clampReputationCacheTtlMs = (value) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) return MIN_TTL_MS;
    return Math.min(MAX_TTL_MS, Math.max(MIN_TTL_MS, Math.round(parsed)));
};

export const hashReputationSubject = (subject) =>
    crypto.createHash('sha256').update(requireSubject(subject)).digest('hex');

const sanitizeValue = (value = {}) => ({
    status: requireEnum(value.status, ALLOWED_STATUSES, 'status'),
    threatTypes: [...new Set((value.threatTypes || []).filter(
        (item) => typeof item === 'string' && /^[A-Z0-9_-]{1,64}$/.test(item)
    ))].slice(0, 8),
    registeredAt: value.registeredAt ? requireDate(value.registeredAt) : null,
    targetHash:
        typeof value.targetHash === 'string' && /^[a-f0-9]{64}$/.test(value.targetHash)
            ? value.targetHash
            : null,
    hopCount: Number.isInteger(value.hopCount)
        ? Math.min(Math.max(value.hopCount, 0), 5)
        : null,
});

export const createReputationCacheService = ({
    model = UrlReputation,
    now = () => new Date(),
} = {}) => {
    const getByHash = async ({ source, keyHash }) => {
        requireEnum(source, ALLOWED_SOURCES, 'source');
        if (typeof keyHash !== 'string' || !/^[a-f0-9]{64}$/.test(keyHash)) {
            throw new TypeError('Invalid reputation cache key hash');
        }
        const currentTime = requireDate(now());
        return toPlainObject(model.findOne({ source, keyHash, expiresAt: { $gt: currentTime } }));
    };

    const get = ({ source, subject }) =>
        getByHash({ source, keyHash: hashReputationSubject(subject) });

    const setByHash = async ({ source, subjectType, keyHash, value, ttlMs }) => {
        requireEnum(source, ALLOWED_SOURCES, 'source');
        requireEnum(subjectType, ALLOWED_SUBJECT_TYPES, 'subject type');
        if (typeof keyHash !== 'string' || !/^[a-f0-9]{64}$/.test(keyHash)) {
            throw new TypeError('Invalid reputation cache key hash');
        }
        const fetchedAt = requireDate(now());
        const expiresAt = new Date(fetchedAt.getTime() + clampReputationCacheTtlMs(ttlMs));
        const safeValue = sanitizeValue(value);

        return model.findOneAndUpdate(
            { source, keyHash },
            {
                $set: {
                    source,
                    subjectType,
                    keyHash,
                    ...safeValue,
                    fetchedAt,
                    expiresAt,
                },
            },
            { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
        );
    };

    const set = ({ source, subjectType, subject, value, ttlMs }) =>
        setByHash({
            source,
            subjectType,
            keyHash: hashReputationSubject(subject),
            value,
            ttlMs,
        });

    return { get, getByHash, set, setByHash };
};
