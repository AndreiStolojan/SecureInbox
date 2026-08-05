import assert from 'node:assert/strict';
import test from 'node:test';

import Email from '../../src/models/email.model.js';
import Scan from '../../src/models/scan.model.js';
import { getEmailByIdForUser } from '../../src/services/email.service.js';

test('email details expose attachment analysis without Gmail locators, hashes, or bytes', async () => {
    const originalFindEmail = Email.findOne;
    const originalFindScan = Scan.findOne;
    const originalCountDocuments = Email.countDocuments;
    const email = {
        _id: '507f1f77bcf86cd799439011',
        userId: '507f1f77bcf86cd799439012',
        attachments: [{
            attachmentId: 'gmail-private-locator',
            filename: 'invoice.docx',
            declaredMimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size: 42,
            bytes: Buffer.from('must-not-leak'),
        }],
        attachmentAnalysis: {
            status: 'evaluated',
            reason: 'completed',
            evaluatedAt: new Date('2026-08-04T12:00:00.000Z'),
            hash: 'must-not-leak',
            items: [{
                attachmentIndex: 0,
                status: 'evaluated',
                reason: 'unsupported_archive_type',
                detectedMimeType: 'application/x-dosexec',
                detectedExtension: 'exe',
                findings: ['attachment_type_mismatch_dangerous'],
                attachmentId: 'must-not-leak',
                sha256: 'must-not-leak',
                data: Buffer.from('must-not-leak'),
            }],
        },
    };

    try {
        Email.findOne = () => ({ lean: async () => email });
        Scan.findOne = () => ({
            sort: () => ({
                select: () => ({ lean: async () => null }),
            }),
        });
        Email.countDocuments = async () => 0;

        const result = await getEmailByIdForUser({
            userId: email.userId,
            emailId: email._id,
            attachmentAnalysisEnabled: true,
        });

        assert.deepEqual(result.attachments, [{
            filename: 'invoice.docx',
            declaredMimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size: 42,
        }]);
        assert.deepEqual(result.attachmentAnalysis, {
            status: 'evaluated',
            reason: 'completed',
            evaluatedAt: new Date('2026-08-04T12:00:00.000Z'),
            items: [{
                attachmentIndex: 0,
                status: 'evaluated',
                reason: 'unsupported_archive_type',
                detectedMimeType: 'application/x-dosexec',
                detectedExtension: 'exe',
                findings: ['attachment_type_mismatch_dangerous'],
            }],
        });
        assert.doesNotMatch(JSON.stringify(result), /gmail-private-locator|must-not-leak/);
    } finally {
        Email.findOne = originalFindEmail;
        Scan.findOne = originalFindScan;
        Email.countDocuments = originalCountDocuments;
    }
});

test('email details hide persisted attachment findings while rollback is enabled', async () => {
    const originalFindEmail = Email.findOne;
    const originalFindScan = Scan.findOne;
    const originalCountDocuments = Email.countDocuments;
    const email = {
        _id: '507f1f77bcf86cd799439011',
        userId: '507f1f77bcf86cd799439012',
        attachments: [{ filename: 'invoice.exe', size: 42 }],
        attachmentAnalysis: {
            status: 'evaluated',
            items: [{
                attachmentIndex: 0,
                status: 'evaluated',
                findings: ['attachment_known_malware_hash'],
            }],
        },
    };

    try {
        Email.findOne = () => ({ lean: async () => email });
        Scan.findOne = () => ({
            sort: () => ({ select: () => ({ lean: async () => null }) }),
        });
        Email.countDocuments = async () => 0;

        const result = await getEmailByIdForUser({
            userId: email.userId,
            emailId: email._id,
            attachmentAnalysisEnabled: false,
        });

        assert.deepEqual(result.attachments, []);
        assert.equal(result.attachmentAnalysis, null);
        assert.doesNotMatch(JSON.stringify(result), /known_malware|invoice\.exe/u);
    } finally {
        Email.findOne = originalFindEmail;
        Scan.findOne = originalFindScan;
        Email.countDocuments = originalCountDocuments;
    }
});
