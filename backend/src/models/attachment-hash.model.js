import mongoose from 'mongoose';

const attachmentHashSchema = new mongoose.Schema(
    {
        sha256: {
            type: String,
            required: true,
            unique: true,
            match: /^[a-f0-9]{64}$/,
        },
        verdict: {
            type: String,
            required: true,
            enum: ['malicious', 'unknown'],
        },
        fetchedAt: { type: Date, required: true },
        expiresAt: { type: Date, required: true },
    },
    { timestamps: true, collection: 'attachmenthashes' }
);

attachmentHashSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model('AttachmentHash', attachmentHashSchema);
