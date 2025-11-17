import { z } from 'zod';
import { NodeExecutionContext, NodeExecutionResult, NodeDefinition } from '../services/execution';
import { logger } from '../utils/logger';

export class EmailNode implements NodeDefinition {
  type = 'email';
  name = 'Send Email';
  description = 'Send emails via SMTP';
  category = 'Communication';
  icon = '📧';
  version = '1.0.0';

  inputs = z.object({
    to: z.string().email().max(254).describe('Recipient email address'),
    subject: z.string().min(1).max(998).describe('Email subject'),
    body: z.string().min(1).max(1000000).describe('Email body content'),
    from: z.string().email().max(254).optional().describe('Sender email address'),
    cc: z.string().email().max(254).optional().describe('CC email address'),
    bcc: z.string().email().max(254).optional().describe('BCC email address'),
    attachments: z.array(z.object({
      filename: z.string().min(1).max(255),
      content: z.string().max(10000000), // 10MB max per attachment
      contentType: z.string().max(100).optional(),
    })).max(10).optional().describe('Email attachments'),
  });

  outputs = z.object({
    messageId: z.string().describe('Email message ID'),
    status: z.string().describe('Email send status'),
    sentAt: z.string().describe('Timestamp when email was sent'),
  });

  config = z.object({
    smtpHost: z.string().describe('SMTP server hostname'),
    smtpPort: z.number().default(587).describe('SMTP server port'),
    smtpSecure: z.boolean().default(false).describe('Use SSL/TLS encryption'),
    smtpUser: z.string().describe('SMTP username'),
    smtpPassword: z.string().describe('SMTP password'),
    fromName: z.string().default('AutoFlow').describe('Sender display name'),
  });

  async execute(context: NodeExecutionContext): Promise<NodeExecutionResult> {
    const startTime = Date.now();
    const logs: Array<any> = [];

    try {
      const { to, subject, body, from, cc, bcc, attachments } = context.inputs;
      
      logger.info('Executing email send', { 
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

      logger.info('Email sent successfully', { 
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
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logs.push({
        level: 'error',
        message: `Failed to send email: ${errorMessage}`,
        timestamp: new Date(),
        error,
      });

      logger.error('Email send failed', { 
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

  validate(config: any): boolean {
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

export class DebugNode implements NodeDefinition {
  type = 'debug';
  name = 'Debug';
  description = 'Log data for debugging purposes';
  category = 'Development';
  icon = '🐛';
  version = '1.0.0';

  inputs = z.object({
    message: z.string().optional().describe('Custom debug message'),
    data: z.record(z.any()).optional().describe('Data to log'),
    logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info').describe('Log level'),
  });

  outputs = z.object({
    logged: z.boolean().describe('Whether data was logged successfully'),
    loggedData: z.record(z.any()).describe('The data that was logged'),
    timestamp: z.string().describe('Timestamp when data was logged'),
  });

  config = z.object({
    includeTimestamp: z.boolean().default(true).describe('Include timestamp in logs'),
    includeExecutionId: z.boolean().default(true).describe('Include execution ID in logs'),
  });

  async execute(context: NodeExecutionContext): Promise<NodeExecutionResult> {
    const startTime = Date.now();
    const logs: Array<any> = [];
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
          logger.debug(logMessage, logData);
          break;
        case 'info':
          logger.info(logMessage, logData);
          break;
        case 'warn':
          logger.warn(logMessage, logData);
          break;
        case 'error':
          logger.error(logMessage, logData);
          break;
      }

      logs.push({
        level: logLevel,
        message: logMessage,
        timestamp: new Date(),
        data: debugData,
      });

      logger.info('Debug node executed', { 
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
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logs.push({
        level: 'error',
        message: `Debug node failed: ${errorMessage}`,
        timestamp: new Date(),
        error,
      });

      logger.error('Debug node failed', { 
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

  validate(config: any): boolean {
    return true; // Debug node doesn't require validation
  }
}

export class DelayNode implements NodeDefinition {
  type = 'delay';
  name = 'Delay';
  description = 'Wait for a specified duration before proceeding';
  category = 'Control';
  icon = '⏰';
  version = '1.0.0';

  inputs = z.object({
    duration: z.number().describe('Delay duration in milliseconds'),
    unit: z.enum(['ms', 's', 'm', 'h']).default('ms').describe('Time unit'),
  });

  outputs = z.object({
    delayCompleted: z.boolean().describe('Whether delay was completed'),
    startTime: z.string().describe('Delay start timestamp'),
    endTime: z.string().describe('Delay end timestamp'),
    actualDuration: z.number().describe('Actual delay duration in milliseconds'),
  });

  config = z.object({
    maxDuration: z.number().default(300000).describe('Maximum allowed delay in ms (5 minutes)'),
    allowInfinite: z.boolean().default(false).describe('Allow delays longer than max duration'),
  });

  async execute(context: NodeExecutionContext): Promise<NodeExecutionResult> {
    const startTime = Date.now();
    const logs: Array<any> = [];

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
      
      logger.info('Starting delay', { 
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

      logger.info('Delay completed', { 
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
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logs.push({
        level: 'error',
        message: `Delay failed: ${errorMessage}`,
        timestamp: new Date(),
        error,
      });

      logger.error('Delay failed', { 
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

  validate(config: any): boolean {
    const { maxDuration, allowInfinite } = config;
    
    if (maxDuration <= 0) {
      return false;
    }
    
    return true;
  }
}