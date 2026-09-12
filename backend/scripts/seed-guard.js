// Require an explicit opt-in and a development database before writing demo data.
export const assertDevelopmentSeed = (env = process.env) => {
    const database = new URL(env.DB_URI).pathname.slice(1);
    if (env.APP_READ_ONLY === 'true' || env.NODE_ENV !== 'development' || env.SEED_DEMO !== 'true'
        || !/(?:_|-)(?:dev|test)$/.test(database)) {
        throw new Error('Demo seed requires development, SEED_DEMO=true and a database ending in _dev, -dev, _test or -test.');
    }
};
