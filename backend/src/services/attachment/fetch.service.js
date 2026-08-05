import { GMAIL_MESSAGE_DETAILS_BASE_URL } from '../../config/google-oauth.js';

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
const RESPONSE_OVERHEAD_BYTES = 4 * 1024;
const MAX_GMAIL_ID_LENGTH = 1_024;

const invalidAttachmentError = (message, code) => {
    const error = new Error(message);
    error.code = code;
    return error;
};

const isGmailIdentifier = (value) =>
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= MAX_GMAIL_ID_LENGTH &&
    /^[A-Za-z0-9_-]+$/.test(value);

const asBoundedByteCount = (value, code) => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw invalidAttachmentError('Attachment size is invalid', code);
    }

    return value;
};

const maxBase64UrlLength = (byteCount) => Math.ceil(byteCount / 3) * 4;

const decodeAttachmentData = ({ data, declaredSize, maxBytes }) => {
    if (
        typeof data !== 'string' ||
        data.length > maxBase64UrlLength(declaredSize) ||
        data.replace(/=+$/, '').length % 4 === 1 ||
        !/^[A-Za-z0-9_-]*={0,2}$/.test(data)
    ) {
        throw invalidAttachmentError(
            'Gmail returned invalid attachment data',
            'GMAIL_ATTACHMENT_DATA_INVALID'
        );
    }

    const bytes = Buffer.from(data, 'base64url');
    if (bytes.length > maxBytes) {
        throw invalidAttachmentError(
            'Gmail attachment exceeds the allowed size',
            'GMAIL_ATTACHMENT_TOO_LARGE'
        );
    }
    if (bytes.length !== declaredSize) {
        throw invalidAttachmentError(
            'Gmail attachment size does not match its declared size',
            'GMAIL_ATTACHMENT_SIZE_MISMATCH'
        );
    }

    return bytes;
};

export const createGmailAttachmentFetchService = ({
    request,
    baseUrl = GMAIL_MESSAGE_DETAILS_BASE_URL,
    defaultMaxBytes = DEFAULT_MAX_BYTES,
} = {}) => {
    if (typeof request !== 'function') {
        throw new TypeError('Gmail attachment fetch requires an injected requester');
    }

    const configuredMaxBytes = asBoundedByteCount(
        defaultMaxBytes,
        'GMAIL_ATTACHMENT_MAX_BYTES_INVALID'
    );
    if (configuredMaxBytes === 0) {
        throw new RangeError('Gmail attachment maximum size must be positive');
    }

    const fetchAttachment = async ({
        mailAccount,
        messageId,
        attachmentId,
        declaredSize,
        maxBytes = configuredMaxBytes,
        timeoutMs,
        signal,
    } = {}) => {
        if (!isGmailIdentifier(messageId)) {
            throw invalidAttachmentError(
                'Gmail message id is invalid',
                'GMAIL_MESSAGE_ID_INVALID'
            );
        }
        if (!isGmailIdentifier(attachmentId)) {
            throw invalidAttachmentError(
                'Gmail attachment id is invalid',
                'GMAIL_ATTACHMENT_ID_INVALID'
            );
        }

        const allowedBytes = asBoundedByteCount(
            maxBytes,
            'GMAIL_ATTACHMENT_MAX_BYTES_INVALID'
        );
        if (allowedBytes === 0) {
            throw new RangeError('Gmail attachment maximum size must be positive');
        }

        const expectedBytes = asBoundedByteCount(
            declaredSize,
            'GMAIL_ATTACHMENT_DECLARED_SIZE_INVALID'
        );
        if (expectedBytes > allowedBytes) {
            throw invalidAttachmentError(
                'Gmail attachment exceeds the allowed size',
                'GMAIL_ATTACHMENT_TOO_LARGE'
            );
        }

        const url = `${baseUrl}/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}`;
        const payload = await request({
            mailAccount,
            url,
            fallbackMessage: 'Failed to fetch Gmail attachment',
            errorCode: 'GMAIL_ATTACHMENT_FETCH_FAILED',
            unreachableCode: 'GMAIL_ATTACHMENT_FETCH_UNREACHABLE',
            timeoutMs,
            signal,
            maxResponseBytes: maxBase64UrlLength(expectedBytes) + RESPONSE_OVERHEAD_BYTES,
        });

        if (payload?.size !== expectedBytes) {
            throw invalidAttachmentError(
                'Gmail attachment response size does not match its declared size',
                'GMAIL_ATTACHMENT_SIZE_MISMATCH'
            );
        }

        return decodeAttachmentData({
            data: payload.data,
            declaredSize: expectedBytes,
            maxBytes: allowedBytes,
        });
    };

    return Object.freeze({ fetchAttachment });
};
