// Returnează numărul de conturi, emailuri și scanări pentru utilizatorul curent,
// conexiunea Gmail și opțiunile AI globale și personale. Vezi docs/architecture.md.

import { isAiSemanticGloballyEnabled } from '../config/env.js';
import Email from '../models/email.model.js';
import MailAccount from '../models/mail-account.model.js';
import Scan from '../models/scan.model.js';
import User from '../models/user.model.js';

// Calculează statusul pentru userul dat: numere (counts) + steaguri (flags).
export const getStatusForUser = async (userId) => {
    const [mailAccountsCount, emailsCount, scansCount, activeGmailAccount, user] = await Promise.all([
        MailAccount.countDocuments({ userId }),
        Email.countDocuments({ userId }),
        Scan.countDocuments({ userId }),
        // Proiectează doar _id; răspunsul public convertește rezultatul în boolean.
        MailAccount.exists({ userId, provider: 'gmail', status: 'active' }),
        User.findById(userId).select('settings.aiEnabled'),
    ]);

    return {
        status: 'ok',
        scope: 'user',
        counts: {
            mailAccountsCount,
            emailsCount,
            scansCount,
        },
        flags: {
            hasGmailConnected: Boolean(activeGmailAccount),
            aiSemanticEnabled: isAiSemanticGloballyEnabled(),
            aiEnabled: Boolean(user?.settings?.aiEnabled),
        },
        generatedAt: new Date().toISOString(),
    };
};
