import arcjet, { detectBot, shield, tokenBucket } from '@arcjet/node';

import { ARCJET_KEY, APP_READ_ONLY } from '../../src/config/env.js';

const aj = !APP_READ_ONLY && ARCJET_KEY
    ? arcjet({
        key: ARCJET_KEY,
        characteristics: ['ip.src'],
        rules: [
            shield({ mode: 'LIVE' }),
            detectBot({
                mode: 'LIVE',
                allow: [
                    'CATEGORY:SEARCH_ENGINE',
                ],
            }),
            tokenBucket({
                mode: 'LIVE',
                refillRate: 5,
                interval: 10,
                capacity: 10,
            }),
        ],
    })
    : null;

export default aj;
