import bcrypt from 'bcryptjs';

import { ADMIN_EMAIL, ADMIN_NAME, ADMIN_PASSWORD, APP_READ_ONLY } from '../src/config/env.js';
import connectToDatabase from '../src/database/mongodb.js';
import User from '../src/models/user.model.js';

const bootstrapAdmin = async () => {
    if (APP_READ_ONLY) throw new Error('Admin bootstrap is disabled in read-only mode.');
    if (!ADMIN_NAME || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
        throw new Error(
            'Missing admin bootstrap config. Set ADMIN_NAME, ADMIN_EMAIL and ADMIN_PASSWORD in your env file.'
        );
    }

    await connectToDatabase();

    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);

    const adminUser = await User.findOneAndUpdate(
        { email: ADMIN_EMAIL.toLowerCase() },
        {
            name: ADMIN_NAME,
            email: ADMIN_EMAIL.toLowerCase(),
            passwordHash,
            role: 'admin',
        },
        {
            returnDocument: 'after',
            upsert: true,
            runValidators: true,
            setDefaultsOnInsert: true,
        }
    );

    console.log(`Admin bootstrap completed for ${adminUser.email}`);
};

bootstrapAdmin()
    .then(() => {
        process.exit(0);
    })
    .catch((error) => {
        console.error('Admin bootstrap failed:', error.message);
        process.exit(1);
    });
