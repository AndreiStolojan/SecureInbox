import app from './app.js';
import mongoose from 'mongoose';
import { PORT, APP_READ_ONLY } from './config/env.js';
import connectToDatabase from './database/mongodb.js';
import { startSchedulers } from './services/scheduler.service.js';
import {
    drainGmailPushQueue,
    stopGmailPushQueue,
} from './services/gmail-push-runtime.service.js';

const startServer = async () => {
    try {
        await connectToDatabase();
        const schedulers = startSchedulers();

        const host = APP_READ_ONLY ? '127.0.0.1' : process.env.APP_HOST || '127.0.0.1';
        const server = app.listen(PORT, host, () => {
            console.log(`running api on http://${host}:${PORT}`);
        });

        const shutdown = (signal) => {
            console.log(`${signal} received; shutting down gracefully`);
            schedulers.stop();
            stopGmailPushQueue();

            server.close(async () => {
                try {
                    await drainGmailPushQueue();
                    await mongoose.disconnect();
                } finally {
                    process.exit(0);
                }
            });

            setTimeout(() => process.exit(1), 10000).unref();
        };

        process.once('SIGTERM', () => shutdown('SIGTERM'));
        process.once('SIGINT', () => shutdown('SIGINT'));
    } catch (error) {
        console.error('Failed to start server:', error.message);
        process.exit(1);
    }
};

startServer();
