/*
 * Seed a set of crafted demo emails into a SecureInbox account, for the live
 * coordinator demo. The emails cover every detection scenario in the
 * presentation script (docs/PRESENTATION_SCRIPT.md).
 *
 * Usage:
 *   node scripts/seed-demo-inbox.js <account-email>          # insert demo emails
 *   node scripts/seed-demo-inbox.js <account-email> --clean  # remove them again
 *
 * All demo emails carry a providerMessageId starting with "demo-", so --clean
 * removes exactly what this script created and nothing else. They are local DB
 * documents only — they never touch the real Gmail account, and "Mark phishing"
 * on them will simply report the Gmail move as failed (expected).
 */
import '../src/config/env.js';
import { assertDevelopmentSeed } from './seed-guard.js';
import mongoose from 'mongoose';

assertDevelopmentSeed();

const [, , accountEmail, flag] = process.argv;

if (!accountEmail) {
    console.error('Usage: node scripts/seed-demo-inbox.js <account-email> [--clean]');
    process.exit(1);
}

await mongoose.connect(process.env.DB_URI);

const User = (await import('../src/models/user.model.js')).default;
const Email = (await import('../src/models/email.model.js')).default;
const Scan = (await import('../src/models/scan.model.js')).default;

const user = await User.findOne({ email: accountEmail.toLowerCase() });

if (!user) {
    console.error(`No user found for ${accountEmail}`);
    await mongoose.disconnect();
    process.exit(1);
}

if (flag === '--clean') {
    const demoEmails = await Email.find({
        userId: user._id,
        providerMessageId: { $regex: '^demo-' },
    }).select('_id');
    const ids = demoEmails.map((e) => e._id);
    const scans = await Scan.deleteMany({ userId: user._id, emailId: { $in: ids } });
    const emails = await Email.deleteMany({ _id: { $in: ids } });
    console.log(`Removed ${emails.deletedCount} demo emails and ${scans.deletedCount} scans.`);
    await mongoose.disconnect();
    process.exit(0);
}

const accountId = new mongoose.Types.ObjectId();
const hoursAgo = (h) => new Date(Date.now() - h * 3600 * 1000);

const DEMO_EMAILS = [
    // 1. Classic credential phishing — urgency + shortened link + reply-to split.
    {
        providerMessageId: 'demo-phish-credentials',
        subject: 'Your account will be suspended in 24 hours — verify now',
        from: 'PayPal Security <security@paypal-account-verify.com>',
        displayName: 'PayPal Security',
        senderDomain: 'paypal-account-verify.com',
        replyTo: 'support-team@collector-mail.ru',
        replyToDomain: 'collector-mail.ru',
        snippet: 'URGENT: We detected unusual activity. Verify your password now…',
        textBody:
            'URGENT: We detected unusual activity on your account.\n\nYour account will be SUSPENDED in 24 hours unless you verify your identity.\n\nClick here to verify your password now: http://bit.ly/3xVerify\n\nPayPal Security Team',
        links: ['http://bit.ly/3xVerify'],
        linkDomains: ['bit.ly'],
        linkCount: 1,
        hasShortenedUrl: true,
        receivedAt: hoursAgo(2),
    },
    // 2. Malware delivery — dangerous attachment + IP link.
    {
        providerMessageId: 'demo-phish-attachment',
        subject: 'Invoice #38271 — payment overdue',
        from: 'Accounting <billing@invoice-portal-eu.net>',
        displayName: 'Accounting',
        senderDomain: 'invoice-portal-eu.net',
        snippet: 'Please find the overdue invoice attached. Download immediately…',
        textBody:
            'Dear customer,\n\nYour payment is overdue. Please open the attached invoice and pay immediately to avoid penalties.\n\nIf the attachment does not open, download it here: http://185.220.101.4/invoice.exe',
        links: ['http://185.220.101.4/invoice.exe'],
        linkDomains: ['185.220.101.4'],
        linkCount: 1,
        suspiciousLinkPatterns: ['ip_address_link'],
        attachmentExtensions: ['exe'],
        receivedAt: hoursAgo(8),
    },
    // 3. Lookalike delivery scam — punycode + urgency.
    {
        providerMessageId: 'demo-phish-delivery',
        subject: 'Your package is on hold — customs fee required',
        from: 'DHL Express <tracking@dhl-express-track.net>',
        displayName: 'DHL Express',
        senderDomain: 'dhl-express-track.net',
        snippet: 'A small customs fee of 2.99 EUR is required to release your package…',
        textBody:
            'Your package DHL-29381 could not be delivered.\n\nA customs fee of 2.99 EUR is required. Pay within 48 hours or the package will be returned.\n\nPay here: http://xn--dhl-tracking-9db.com/pay',
        links: ['http://xn--dhl-tracking-9db.com/pay'],
        linkDomains: ['xn--dhl-tracking-9db.com'],
        linkCount: 1,
        suspiciousLinkPatterns: ['punycode_domain'],
        receivedAt: hoursAgo(20),
    },
    // 4. Legitimate brand newsletter — looks "phishy" to naive filters (many links,
    //    ESP reply-to) but comes from the real domain → verified-brand layer.
    {
        providerMessageId: 'demo-legit-brand',
        subject: 'Your weekly digest from LinkedIn',
        from: 'LinkedIn <messages-noreply@linkedin.com>',
        displayName: 'LinkedIn',
        senderDomain: 'linkedin.com',
        replyTo: 'bounce@e.linkedin.com',
        replyToDomain: 'e.linkedin.com',
        snippet: 'You appeared in 9 searches this week. See who is looking…',
        textBody:
            'You appeared in 9 searches this week.\n\nSee your profile views: https://www.linkedin.com/me/profile-views\nNew jobs for you: https://www.linkedin.com/jobs\nPeople you may know: https://www.linkedin.com/mynetwork\nSign in to see more: https://www.linkedin.com/login\nManage notifications: https://www.linkedin.com/settings\nUnsubscribe: https://www.linkedin.com/unsubscribe\nHelp center: https://www.linkedin.com/help',
        links: [
            'https://www.linkedin.com/me/profile-views',
            'https://www.linkedin.com/jobs',
            'https://www.linkedin.com/mynetwork',
            'https://www.linkedin.com/login',
            'https://www.linkedin.com/settings',
            'https://www.linkedin.com/unsubscribe',
            'https://www.linkedin.com/help',
        ],
        linkDomains: ['linkedin.com'],
        linkCount: 7,
        receivedAt: hoursAgo(30),
    },
    // 5. Ordinary clean email — baseline "safe".
    {
        providerMessageId: 'demo-legit-plain',
        subject: 'Notite curs joi',
        from: 'Mihai Popescu <mihai.popescu@stud.fils.ro>',
        displayName: 'Mihai Popescu',
        senderDomain: 'stud.fils.ro',
        snippet: 'Salut! Ti-am trimis notitele de la cursul de joi…',
        textBody:
            'Salut!\n\nTi-am trimis notitele de la cursul de joi. Spune-mi daca lipseste ceva.\n\nMihai',
        linkCount: 0,
        receivedAt: hoursAgo(4),
    },
    // 6. Newsletter from an unknown company — lands "suspicious" (reply-to split +
    //    many links). The trust-rule demo: add the domain to Trusted, rescan → safe.
    {
        providerMessageId: 'demo-newsletter-unknown',
        subject: 'Oferte saptamanale — reduceri de vara',
        from: 'EMag Deals <newsletter@deals-emag-marketing.com>',
        displayName: 'EMag Deals',
        senderDomain: 'deals-emag-marketing.com',
        replyTo: 'campaigns@mailgun-esp.net',
        replyToDomain: 'mailgun-esp.net',
        snippet: 'Reduceri de pana la 50% saptamana aceasta…',
        textBody:
            'Reduceri de vara!\n\nTelefoane: https://deals-emag-marketing.com/tel\nLaptopuri: https://deals-emag-marketing.com/laptop\nElectrocasnice: https://deals-emag-marketing.com/casa\nGaming: https://deals-emag-marketing.com/gaming\nFashion: https://deals-emag-marketing.com/fashion\nDezabonare: https://deals-emag-marketing.com/unsub',
        links: [
            'https://deals-emag-marketing.com/tel',
            'https://deals-emag-marketing.com/laptop',
            'https://deals-emag-marketing.com/casa',
            'https://deals-emag-marketing.com/gaming',
            'https://deals-emag-marketing.com/fashion',
            'https://deals-emag-marketing.com/unsub',
        ],
        linkDomains: ['deals-emag-marketing.com'],
        linkCount: 6,
        receivedAt: hoursAgo(12),
    },
];

let inserted = 0;

for (const demo of DEMO_EMAILS) {
    await Email.findOneAndUpdate(
        { userId: user._id, providerMessageId: demo.providerMessageId },
        {
            userId: user._id,
            mailAccountId: accountId,
            provider: 'gmail',
            syncSource: 'gmail_manual_sync',
            ...demo,
        },
        { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
    );
    inserted += 1;
}

console.log(`Seeded ${inserted} demo emails for ${accountEmail}.`);
console.log('They are unscanned — open each one and press "Scan again", or run a sync.');
console.log('Remove them later with: node scripts/seed-demo-inbox.js ' + accountEmail + ' --clean');

await mongoose.disconnect();
