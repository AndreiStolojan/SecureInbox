import { ARCJET_KEY, APP_READ_ONLY } from '../../src/config/env.js';
import aj from './arcjet.config.js';

const arcjetMiddleware = async (req, res, next) => {
    if (APP_READ_ONLY || !ARCJET_KEY || !aj) return next();
    try {
        const decision = await aj.protect(req, { requested: 1 });

        if (decision.isDenied()) {
            if (decision.reason.isRateLimit()) {
                return res.status(429).json({ error: 'Too many requests' });
            }

            if (decision.reason.isBot()) {
                return res.status(403).json({ error: 'Bot detected' });
            }

            return res.status(403).json({ error: 'Access denied' });
        }

        next();
    } catch (error) {
        next(error);
    }
};

export default arcjetMiddleware;
