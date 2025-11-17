import { z } from 'zod';
import { NodeExecutionContext, NodeExecutionResult, NodeDefinition } from '../services/execution';
import { logger } from '../utils/logger';

export class TriggerNode implements NodeDefinition {
  type = 'trigger';
  name = 'Trigger';
  description = 'Starting point for workflow execution';
  category = 'Core';
  icon = '🚀';
  version = '1.0.0';

  inputs = z.object({});

  outputs = z.object({
    triggerData: z.record(z.any()).describe('Data that triggered the workflow'),
    timestamp: z.string().describe('ISO timestamp when workflow started'),
    executionId: z.string().describe('Unique execution ID'),
  });

  config = z.object({
    eventType: z.string().optional().describe('Type of event that triggered this workflow'),
    webhookUrl: z.string().optional().describe('Custom webhook URL for external triggers'),
  });

  async execute(context: NodeExecutionContext): Promise<NodeExecutionResult> {
    const startTime = Date.now();
    const logs: Array<any> = [];

    try {
      logger.info('Executing trigger node', { 
        executionId: context.executionId,
        nodeId: context.nodeId 
      });

      logs.push({
        level: 'info',
        message: 'Trigger node executed successfully',
        timestamp: new Date(),
      });

      const outputs = {
        triggerData: context.inputs,
        timestamp: new Date().toISOString(),
        executionId: context.executionId,
        eventType: context.config.eventType || 'manual',
      };

      logger.info('Trigger node completed', { 
        executionId: context.executionId,
        nodeId: context.nodeId,
        duration: Date.now() - startTime 
      });

      return {
        success: true,
        outputs,
        executionTimeMs: Date.now() - startTime,
        logs,
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logs.push({
        level: 'error',
        message: `Trigger node failed: ${errorMessage}`,
        timestamp: new Date(),
        error,
      });

      logger.error('Trigger node failed', { 
        error, 
        executionId: context.executionId,
        nodeId: context.nodeId 
      });

      return {
        success: false,
        outputs: {},
        error: errorMessage,
        executionTimeMs: Date.now() - startTime,
        logs,
      };
    }
  }

  validate(config: any): boolean {
    return true; // Trigger node doesn't require validation
  }
}