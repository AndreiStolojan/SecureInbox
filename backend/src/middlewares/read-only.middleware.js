import { APP_READ_ONLY } from '../config/env.js';
import sendErrorResponse from '../common/http/send-error-response.js';

// Explicitly reviewed database reads. New routes are denied until reviewed here.
const readPaths = [
    /^\/api\/v1\/(health|ready)\/?$/,
    /^\/api\/v1\/users\/me\/?$/,
    /^\/api\/v1\/mail-accounts\/?$/,
    /^\/api\/v1\/meta\/status\/?$/,
    /^\/api\/v1\/sender-lists\/?$/,
    /^\/api\/v1\/reports\/monthly-summary\/?$/,
    /^\/api\/v1\/emails(?:\/(?:stats|trend|top-risky-senders|[a-f\d]{24}(?:\/raw)?))?\/?$/i,
    /^\/api\/v1\/scans\/emails\/[a-f\d]{24}\/latest\/?$/i,
];

// Login checks the existing password and signs a local token without writing data.
// GET alone is insufficient: OAuth callbacks can mutate data and contact Google.
const readOnlyMiddleware = (req, res, next) => {
    if (!APP_READ_ONLY) return next();
    const login = req.method === 'POST' && /^\/api\/v1\/auth\/login\/?$/.test(req.path);
    const read = ['GET', 'HEAD'].includes(req.method) && readPaths.some((path) => path.test(req.path));
    if (login || read) return next();
    return sendErrorResponse(res, 403, 'This local session is read-only.', 'READ_ONLY_MODE');
};

export default readOnlyMiddleware;
