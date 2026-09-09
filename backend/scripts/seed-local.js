import { spawnSync } from 'node:child_process';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';

import '../src/config/env.js';
import { assertDevelopmentSeed } from './seed-guard.js';

assertDevelopmentSeed();

const {
    DB_URI,
    DEMO_USER_EMAIL = 'demo@secureinbox.test',
    DEMO_USER_NAME = 'Demo User',
    DEMO_USER_PASSWORD,
} = process.env;

if (!DB_URI || !DEMO_USER_PASSWORD) {
    throw new Error('DB_URI and DEMO_USER_PASSWORD are required for the local seed.');
}

const User = (await import('../src/models/user.model.js')).default;
const Email = (await import('../src/models/email.model.js')).default;
const { scanEmailWithRules } = await import('../src/services/scan.service.js');

await mongoose.connect(DB_URI);

const passwordHash = await bcrypt.hash(DEMO_USER_PASSWORD, 10);
const user = await User.findOneAndUpdate(
    { email: DEMO_USER_EMAIL.toLowerCase() },
    {
        $set: {
            name: DEMO_USER_NAME,
            passwordHash,
            role: 'user',
            'settings.aiEnabled': false,
            'settings.alertsEnabled': false,
            'settings.digestEnabled': false,
        },
    },
    {
        upsert: true,
        returnDocument: 'after',
        runValidators: true,
        setDefaultsOnInsert: true,
    }
);

await mongoose.disconnect();

const seedResult = spawnSync(
    process.execPath,
    ['scripts/seed-demo-inbox.js', DEMO_USER_EMAIL],
    { cwd: process.cwd(), env: process.env, stdio: 'inherit' }
);

if (seedResult.status !== 0) {
    throw new Error('Demo email seed failed.');
}

await mongoose.connect(DB_URI);
const demoEmails = await Email.find({
    userId: user._id,
    providerMessageId: { $regex: '^demo-' },
}).select('_id');

for (const email of demoEmails) {
    await scanEmailWithRules({
        emailId: email._id,
        userId: user._id,
        scanSource: 'manual',
    });
}

console.log(`Local demo ready: ${DEMO_USER_EMAIL} (${demoEmails.length} emails scanned).`);
await mongoose.disconnect();
