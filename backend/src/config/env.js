import { config } from 'dotenv';

const nodeEnv = process.env.NODE_ENV || 'development';
const resolvedEnvFilePath = `.env.${nodeEnv}.local`;

config({ path: resolvedEnvFilePath });

const requiredEnvVars = ['PORT', 'DB_URI', 'JWT_SECRET', 'JWT_EXPIRES_IN', 'MAIL_TOKEN_ENCRYPTION_KEY'];
const requiredInProduction = [
    'GOOGLE_CLIENT_ID',
    'GOOGLE_CLIENT_SECRET',
    'GOOGLE_REDIRECT_URI',
    'FRONTEND_APP_URL',
    'EMAIL_FROM',
    'EMAIL_PASSWORD',
];
const requiredGmailPushEnvVars = [
    'GOOGLE_CLOUD_PROJECT_ID',
    'GMAIL_PUBSUB_TOPIC',
    'GMAIL_PUSH_AUDIENCE',
    'GMAIL_PUSH_SERVICE_ACCOUNT_EMAIL',
];
const missingProductionEnvVars = nodeEnv === 'production'
    ? requiredInProduction.filter((envName) => !process.env[envName])
    : [];
const missingEnvVars = requiredEnvVars.filter((envName) => !process.env[envName]);
const gmailPushEnabled = ['true', '1', 'yes', 'on'].includes(
    String(process.env.GMAIL_PUSH_ENABLED || '').trim().toLowerCase()
);

if (missingProductionEnvVars.length > 0) {
    throw new Error(
        `Missing required production env vars: ${missingProductionEnvVars.join(', ')}`
    );
}

if (missingEnvVars.length > 0) {
    throw new Error(
        `Missing required env vars in ${resolvedEnvFilePath}: ${missingEnvVars.join(', ')}`
    );
}

// Gmail Push is deliberately optional: local installs keep using polling when
// no Push variables are present. A partial configuration is unsafe, though:
// Gmail Watch would be created while the webhook could not authenticate Pub/Sub.
const missingGmailPushEnvVars = gmailPushEnabled
    ? requiredGmailPushEnvVars.filter((envName) => !process.env[envName])
    : [];

if (missingGmailPushEnvVars.length > 0) {
    throw new Error(
        `Gmail Push is enabled but missing: ${missingGmailPushEnvVars.join(', ')}`
    );
}

if (
    gmailPushEnabled &&
    process.env.GMAIL_PUBSUB_TOPIC &&
    !/^projects\/[^/]+\/topics\/[^/]+$/.test(process.env.GMAIL_PUBSUB_TOPIC)
) {
    throw new Error('GMAIL_PUBSUB_TOPIC must use projects/<project>/topics/<topic> format');
}

if (
    gmailPushEnabled &&
    process.env.GMAIL_PUBSUB_TOPIC.split('/')[1] !== process.env.GOOGLE_CLOUD_PROJECT_ID
) {
    throw new Error('GMAIL_PUBSUB_TOPIC must belong to GOOGLE_CLOUD_PROJECT_ID');
}

export const {
    PORT,
    NODE_ENV,
    DB_URI,
    JWT_EXPIRES_IN,
    JWT_SECRET,
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    ARCJET_ENV,
    ARCJET_KEY,
    EMAIL_FROM,
    EMAIL_PASSWORD,
    ADMIN_NAME,
    ADMIN_EMAIL,
    ADMIN_PASSWORD,
    MAIL_TOKEN_ENCRYPTION_KEY,
    AI_SEMANTIC_ENABLED,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_TIMEOUT_MS,
    OLLAMA_PROMPT_VERSION,
    SCAN_CONCURRENCY,
    SYNC_INTERVAL_MINUTES,
    GMAIL_PUSH_ENABLED,
    GOOGLE_CLOUD_PROJECT_ID,
    GMAIL_PUBSUB_TOPIC,
    GMAIL_PUSH_AUDIENCE,
    GMAIL_PUSH_SERVICE_ACCOUNT_EMAIL,
    GMAIL_POLL_INTERVAL_WITH_PUSH,
} = process.env;

export const FRONTEND_APP_URL = process.env.FRONTEND_APP_URL || 'http://localhost:5173';
export const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || EMAIL_FROM || '';
// Threat intelligence stays opt-in. Source keys are intentionally not startup
// requirements: each external source can be unavailable independently.
export const THREAT_INTEL_ENABLED = process.env.THREAT_INTEL_ENABLED || 'false';
export const WEB_RISK_API_KEY = process.env.WEB_RISK_API_KEY || '';
export const URLHAUS_AUTH_KEY = process.env.URLHAUS_AUTH_KEY || '';
// Services own range validation so bad optional values cannot prevent startup.
export const THREAT_INTEL_MAX_URLS_PER_EMAIL =
    process.env.THREAT_INTEL_MAX_URLS_PER_EMAIL || '5';
export const THREAT_INTEL_TIMEOUT_MS = process.env.THREAT_INTEL_TIMEOUT_MS || '10000';
// Attachment byte inspection is opt-in so existing/local Gmail syncs never start
// downloading files until the operator explicitly enables the feature.
export const ATTACHMENT_ANALYSIS_ENABLED =
    process.env.ATTACHMENT_ANALYSIS_ENABLED || 'false';
export const ATTACHMENT_MAX_BYTES = process.env.ATTACHMENT_MAX_BYTES || '10485760';
export const ATTACHMENT_MAX_TOTAL_BYTES =
    process.env.ATTACHMENT_MAX_TOTAL_BYTES || '26214400';
export const ATTACHMENT_MAX_COUNT = process.env.ATTACHMENT_MAX_COUNT || '10';
export const ATTACHMENT_ANALYSIS_CONCURRENCY =
    process.env.ATTACHMENT_ANALYSIS_CONCURRENCY || '3';
export const ATTACHMENT_ANALYSIS_TIMEOUT_MS =
    process.env.ATTACHMENT_ANALYSIS_TIMEOUT_MS || '15000';
export const MALWAREBAZAAR_AUTH_KEY = process.env.MALWAREBAZAAR_AUTH_KEY || '';

export const isTruthyEnvValue = (value) =>
    typeof value === 'string' &&
    ['true', '1', 'yes', 'on'].includes(value.trim().toLowerCase());

export const isAiSemanticGloballyEnabled = () =>
    isTruthyEnvValue(AI_SEMANTIC_ENABLED);

export const isGmailPushConfigured = () =>
    gmailPushEnabled && missingGmailPushEnvVars.length === 0;

export const isThreatIntelEnabled = () =>
    isTruthyEnvValue(THREAT_INTEL_ENABLED);

export const isAttachmentAnalysisEnabled = () =>
    isTruthyEnvValue(ATTACHMENT_ANALYSIS_ENABLED);
