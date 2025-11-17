"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DelayNode = exports.DebugNode = exports.EmailNode = void 0;
const zod_1 = require("zod");
const logger_1 = require("../utils/logger");
class EmailNode {
    type = 'email';
    name = 'Send Email';
    description = 'Send emails via SMTP';
    category = 'Communication';
    icon = '📧';
    version = '1.0.0';
    inputs = zod_1.z.object({
        to: zod_1.z.string().describe('Recipient email address'),
        subject: zod_1.z.string().describe('Email subject'),
        body: zod_1.z.string().describe('Email body content'),
        from: zod_1.z.string().optional().describe('Sender email address'),
        cc: zod_1.z.string().optional().describe('CC email address'),
        bcc: zod_1.z.string().optional().describe('BCC email address'),
        attachments: zod_1.z.array(zod_1.z.object({
            filename: zod_1.z.string(),
            content: zod_1.z.string(),
            contentType: zod_1.z.string().optional(),
        })).optional().describe('Email attachments'),
    });
    outputs = zod_1.z.object({
        messageId: zod_1.z.string().describe('Email message ID'),
        status: zod_1.z.string().describe('Email send status'),
        sentAt: zod_1.z.string().describe('Timestamp when email was sent'),
    });
    config = zod_1.z.object({
        smtpHost: zod_1.z.string().describe('SMTP server hostname'),
        smtpPort: zod_1.z.number().default(587).describe('SMTP server port'),
        smtpSecure: zod_1.z.boolean().default(false).describe('Use SSL/TLS encryption'),
        smtpUser: zod_1.z.string().describe('SMTP username'),
        smtpPassword: zod_1.z.string().describe('SMTP password'),
        fromName: zod_1.z.string().default('AutoFlow').describe('Sender display name'),
    });
    async execute(context) {
        const startTime = Date.now();
        const logs = [];
        try {
            const { to, subject, body, from, cc, bcc, attachments } = context.inputs;
            logger_1.logger.info('Executing email send', {
                executionId: context.executionId,
                nodeId: context.nodeId,
                to,
                subject
            });
            if (!to) {
                throw new Error('Recipient email address is required');
            }
            if (!subject) {
                throw new Error('Email subject is required');
            }
            if (!body) {
                throw new Error('Email body is required');
            }
            logs.push({
                level: 'info',
                message: `Preparing to send email to ${to}`,
                timestamp: new Date(),
                data: { to, subject, hasAttachments: !!attachments },
            });
            // In a real implementation, you would use a library like nodemailer
            // For now, we'll simulate the email sending
            const smtpConfig = context.config;
            logs.push({
                level: 'debug',
                message: 'Connecting to SMTP server',
                timestamp: new Date(),
                data: { host: smtpConfig.smtpHost, port: smtpConfig.smtpPort },
            });
            // Simulate SMTP connection and email sending
            await new Promise(resolve => setTimeout(resolve, 1000));
            logs.push({
                level: 'info',
                message: 'Email sent successfully',
                timestamp: new Date(),
            });
            const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            logger_1.logger.info('Email sent successfully', {
                executionId: context.executionId,
                nodeId: context.nodeId,
                to,
                subject,
                messageId
            });
            return {
                success: true,
                outputs: {
                    messageId,
                    status: 'sent',
                    sentAt: new Date().toISOString(),
                },
                executionTimeMs: Date.now() - startTime,
                logs,
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            logs.push({
                level: 'error',
                message: `Failed to send email: ${errorMessage}`,
                timestamp: new Date(),
                error,
            });
            logger_1.logger.error('Email send failed', {
                error,
                executionId: context.executionId,
                nodeId: context.nodeId
            });
            return {
                success: false,
                outputs: {
                    messageId: null,
                    status: 'failed',
                    sentAt: null,
                },
                error: errorMessage,
                executionTimeMs: Date.now() - startTime,
                logs,
            };
        }
    }
    validate(config) {
        const { smtpHost, smtpPort, smtpUser, smtpPassword } = config;
        if (!smtpHost || !smtpPort || !smtpUser || !smtpPassword) {
            return false;
        }
        if (smtpPort < 1 || smtpPort > 65535) {
            return false;
        }
        return true;
    }
}
exports.EmailNode = EmailNode;
class DebugNode {
    type = 'debug';
    name = 'Debug';
    description = 'Log data for debugging purposes';
    category = 'Development';
    icon = '🐛';
    version = '1.0.0';
    inputs = zod_1.z.object({
        message: zod_1.z.string().optional().describe('Custom debug message'),
        data: zod_1.z.record(zod_1.z.any()).optional().describe('Data to log'),
        logLevel: zod_1.z.enum(['debug', 'info', 'warn', 'error']).default('info').describe('Log level'),
    });
    outputs = zod_1.z.object({
        logged: zod_1.z.boolean().describe('Whether data was logged successfully'),
        loggedData: zod_1.z.record(zod_1.z.any()).describe('The data that was logged'),
        timestamp: zod_1.z.string().describe('Timestamp when data was logged'),
    });
    config = zod_1.z.object({
        includeTimestamp: zod_1.z.boolean().default(true).describe('Include timestamp in logs'),
        includeExecutionId: zod_1.z.boolean().default(true).describe('Include execution ID in logs'),
    });
    async execute(context) {
        const startTime = Date.now();
        const logs = [];
        const { message, data, logLevel } = context.inputs;
        try {
            const debugData = {
                message: message || 'Debug node executed',
                data: data || context.previousResults,
                ...(context.config.includeTimestamp && { timestamp: new Date().toISOString() }),
                ...(context.config.includeExecutionId && { executionId: context.executionId }),
                nodeId: context.nodeId,
            };
            // Log based on the specified level
            const logMessage = debugData.message;
            const logData = { ...debugData, nodeId: context.nodeId };
            switch (logLevel) {
                case 'debug':
                    logger_1.logger.debug(logMessage, logData);
                    break;
                case 'info':
                    logger_1.logger.info(logMessage, logData);
                    break;
                case 'warn':
                    logger_1.logger.warn(logMessage, logData);
                    break;
                case 'error':
                    logger_1.logger.error(logMessage, logData);
                    break;
            }
            logs.push({
                level: logLevel,
                message: logMessage,
                timestamp: new Date(),
                data: debugData,
            });
            logger_1.logger.info('Debug node executed', {
                executionId: context.executionId,
                nodeId: context.nodeId,
                logLevel
            });
            return {
                success: true,
                outputs: {
                    logged: true,
                    loggedData: debugData,
                    timestamp: new Date().toISOString(),
                },
                executionTimeMs: Date.now() - startTime,
                logs,
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            logs.push({
                level: 'error',
                message: `Debug node failed: ${errorMessage}`,
                timestamp: new Date(),
                error,
            });
            logger_1.logger.error('Debug node failed', {
                error,
                executionId: context.executionId,
                nodeId: context.nodeId
            });
            return {
                success: false,
                outputs: {
                    logged: false,
                    loggedData: {},
                    timestamp: null,
                },
                error: errorMessage,
                executionTimeMs: Date.now() - startTime,
                logs,
            };
        }
    }
    validate(config) {
        return true; // Debug node doesn't require validation
    }
}
exports.DebugNode = DebugNode;
class DelayNode {
    type = 'delay';
    name = 'Delay';
    description = 'Wait for a specified duration before proceeding';
    category = 'Control';
    icon = '⏰';
    version = '1.0.0';
    inputs = zod_1.z.object({
        duration: zod_1.z.number().describe('Delay duration in milliseconds'),
        unit: zod_1.z.enum(['ms', 's', 'm', 'h']).default('ms').describe('Time unit'),
    });
    outputs = zod_1.z.object({
        delayCompleted: zod_1.z.boolean().describe('Whether delay was completed'),
        startTime: zod_1.z.string().describe('Delay start timestamp'),
        endTime: zod_1.z.string().describe('Delay end timestamp'),
        actualDuration: zod_1.z.number().describe('Actual delay duration in milliseconds'),
    });
    config = zod_1.z.object({
        maxDuration: zod_1.z.number().default(300000).describe('Maximum allowed delay in ms (5 minutes)'),
        allowInfinite: zod_1.z.boolean().default(false).describe('Allow delays longer than max duration'),
    });
    async execute(context) {
        const startTime = Date.now();
        const logs = [];
        try {
            const { duration, unit } = context.inputs;
            if (!duration || duration <= 0) {
                throw new Error('Delay duration must be greater than 0');
            }
            // Convert duration to milliseconds
            let delayMs = duration;
            switch (unit) {
                case 's':
                    delayMs = duration * 1000;
                    break;
                case 'm':
                    delayMs = duration * 60 * 1000;
                    break;
                case 'h':
                    delayMs = duration * 60 * 60 * 1000;
                    break;
            }
            // Check if delay exceeds maximum allowed duration
            if (!context.config.allowInfinite && delayMs > context.config.maxDuration) {
                throw new Error(`Delay duration ${delayMs}ms exceeds maximum allowed ${context.config.maxDuration}ms`);
            }
            const startTimestamp = new Date().toISOString();
            logger_1.logger.info('Starting delay', {
                executionId: context.executionId,
                nodeId: context.nodeId,
                duration: delayMs,
                unit
            });
            logs.push({
                level: 'info',
                message: `Starting delay for ${duration}${unit}`,
                timestamp: new Date(),
                data: { delayMs, unit, startTimestamp },
            });
            // Wait for the specified duration
            await new Promise(resolve => setTimeout(resolve, delayMs));
            const endTimestamp = new Date().toISOString();
            const actualDuration = Date.now() - startTime;
            logs.push({
                level: 'info',
                message: 'Delay completed',
                timestamp: new Date(),
                data: { actualDuration },
            });
            logger_1.logger.info('Delay completed', {
                executionId: context.executionId,
                nodeId: context.nodeId,
                requestedDuration: delayMs,
                actualDuration
            });
            return {
                success: true,
                outputs: {
                    delayCompleted: true,
                    startTime: startTimestamp,
                    endTime: endTimestamp,
                    actualDuration,
                },
                executionTimeMs: actualDuration,
                logs,
            };
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            logs.push({
                level: 'error',
                message: `Delay failed: ${errorMessage}`,
                timestamp: new Date(),
                error,
            });
            logger_1.logger.error('Delay failed', {
                error,
                executionId: context.executionId,
                nodeId: context.nodeId
            });
            return {
                success: false,
                outputs: {
                    delayCompleted: false,
                    startTime: null,
                    endTime: null,
                    actualDuration: Date.now() - startTime,
                },
                error: errorMessage,
                executionTimeMs: Date.now() - startTime,
                logs,
            };
        }
    }
    validate(config) {
        const { maxDuration, allowInfinite } = config;
        if (maxDuration <= 0) {
            return false;
        }
        return true;
    }
}
exports.DelayNode = DelayNode;
//# sourceMappingURL=EmailNode.js.map