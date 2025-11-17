import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { Queue } from 'bullmq';
import { db } from '@/database/connection';
import { logger } from '@/utils/logger';
import { queueConfig } from '@/config/environment';
import { workflowService } from './workflow';
import Redis from 'ioredis';

// Redis connection for queue
const redisConfig = {
  host: 'localhost',
  port: 6379,
  ...(process.env.REDIS_PASSWORD && { password: process.env.REDIS_PASSWORD }),
};

const redis = new Redis(redisConfig);

// Create queue
export const executionQueue = new Queue('workflow-execution', {
  connection: redis,
});

// Node execution schemas
export const NodeExecutionContextSchema = z.object({
  workflowId: z.string(),
  executionId: z.string(),
  nodeId: z.string(),
  inputs: z.record(z.any()).default({}),
  config: z.record(z.any()).default({}),
  previousResults: z.record(z.any()).default({}),
  webhooks: z.object({
    baseUrl: z.string(),
    executionId: z.string(),
    nodeId: z.string(),
  }).optional(),
});

export const NodeExecutionResultSchema = z.object({
  success: z.boolean(),
  outputs: z.record(z.any()).default({}),
  error: z.string().optional(),
  executionTimeMs: z.number(),
  logs: z.array(z.object({
    level: z.enum(['debug', 'info', 'warn', 'error']),
    message: z.string(),
    timestamp: z.date(),
    data: z.record(z.any()).optional(),
  })).default([]),
});

export interface NodeExecutionContext {
  workflowId: string;
  executionId: string;
  nodeId: string;
  inputs: Record<string, any>;
  config: Record<string, any>;
  previousResults: Record<string, any>;
  webhooks?: {
    baseUrl: string;
    executionId: string;
    nodeId: string;
  };
}

export interface NodeExecutionResult {
  success: boolean;
  outputs: Record<string, any>;
  error?: string;
  executionTimeMs: number;
  logs: Array<{
    level: 'debug' | 'info' | 'warn' | 'error';
    message: string;
    timestamp: Date;
    data?: Record<string, any>;
  }>;
}

// Node registry interface
export interface NodeDefinition {
  type: string;
  name: string;
  description: string;
  category: string;
  icon: string;
  version: string;
  inputs: z.ZodTypeAny;
  outputs: z.ZodTypeAny;
  config: z.ZodTypeAny;
  execute: (context: NodeExecutionContext) => Promise<NodeExecutionResult>;
  validate?: (config: any) => boolean;
}

export class NodeRegistry {
  private nodes = new Map<string, NodeDefinition>();

  register(node: NodeDefinition): void {
    if (this.nodes.has(node.type)) {
      throw new Error(`Node type '${node.type}' is already registered`);
    }
    
    this.nodes.set(node.type, node);
    logger.info(`Registered node type: ${node.type}`, { nodeType: node.type, version: node.version });
  }

  get(type: string): NodeDefinition | undefined {
    return this.nodes.get(type);
  }

  getAll(): NodeDefinition[] {
    return Array.from(this.nodes.values());
  }

  getByCategory(category: string): NodeDefinition[] {
    return Array.from(this.nodes.values()).filter(node => node.category === category);
  }

  has(type: string): boolean {
    return this.nodes.has(type);
  }
}

export const nodeRegistry = new NodeRegistry();

// Built-in node implementations
import { TriggerNode } from '../nodes/TriggerNode';
import { HTTPNode } from '../nodes/HTTPNode';
import { EmailNode, DebugNode, DelayNode } from '../nodes/EmailNode';

// Register built-in nodes
nodeRegistry.register(new TriggerNode());
nodeRegistry.register(new HTTPNode());
nodeRegistry.register(new EmailNode());
nodeRegistry.register(new DebugNode());
nodeRegistry.register(new DelayNode());

export class ExecutionService {
  async enqueueExecution(workflowId: string, triggerData: Record<string, any>, userId: string): Promise<string> {
    try {
      // Verify workflow exists and user has access
      const workflow = await workflowService.getWorkflowById(workflowId, userId);
      if (!workflow) {
        throw new Error('Workflow not found or access denied');
      }

      // Create execution record
      const executionId = uuidv4();
      const now = new Date();
      
      await db
        .insertInto('executions')
        .values({
          id: executionId,
          workflow_id: workflowId,
          trigger_data: triggerData,
          status: 'queued',
          created_at: now,
          updated_at: now,
        })
        .execute();

      // Enqueue job
      await executionQueue.add(
        'execute-workflow',
        {
          executionId,
          workflowId,
          triggerData,
          userId,
        },
        {
          attempts: queueConfig.attempts,
          backoff: {
            type: 'exponential',
            delay: queueConfig.backoffDelay,
          },
          removeOnComplete: 100,
          removeOnFail: 50,
        }
      );

      logger.info('Workflow execution enqueued', { executionId, workflowId, userId });

      return executionId;
    } catch (error) {
      logger.error('Failed to enqueue workflow execution', { error, workflowId, userId });
      throw error;
    }
  }

  async getExecution(executionId: string, userId?: string): Promise<any> {
    try {
      const execution = await db
        .selectFrom('executions')
        .selectAll()
        .where('id', '=', executionId)
        .executeTakeFirst();

      if (!execution) {
        throw new Error('Execution not found');
      }

      // Check access permissions if userId provided
      if (userId) {
        const workflow = await workflowService.getWorkflowById(execution.workflow_id, userId);
        if (!workflow) {
          throw new Error('Access denied');
        }
      }

      return {
        id: execution.id,
        workflowId: execution.workflow_id,
        triggerData: execution.trigger_data,
        status: execution.status,
        startedAt: execution.started_at,
        completedAt: execution.completed_at,
        errorMessage: execution.error_message,
        executionTimeMs: execution.execution_time_ms,
        nodeExecutions: execution.node_executions,
        createdAt: execution.created_at,
        updatedAt: execution.updated_at,
      };
    } catch (error) {
      logger.error('Failed to get execution', { error, executionId });
      throw error;
    }
  }

  async getExecutions(
    workflowId?: string,
    userId?: string,
    options: {
      status?: string;
      page?: number;
      limit?: number;
      startDate?: Date;
      endDate?: Date;
    } = {}
  ): Promise<any> {
    try {
      const { status, page = 1, limit = 10, startDate, endDate } = options;
      const offset = (page - 1) * limit;

      let query = db
        .selectFrom('executions')
        .select([
          'id',
          'workflow_id',
          'status',
          'started_at',
          'completed_at',
          'execution_time_ms',
          'error_message',
          'created_at',
          'updated_at',
        ]);

      if (workflowId) {
        query = query.where('workflow_id', '=', workflowId);
      }

      if (status) {
        query = query.where('status', '=', status);
      }

      if (startDate) {
        query = query.where('created_at', '>=', startDate);
      }

      if (endDate) {
        query = query.where('created_at', '<=', endDate);
      }

      // Get total count
      const countQuery = query.select(({ fn }) => fn.countAll().as('count'));
      const totalResult = await countQuery.executeTakeFirst();
      const total = parseInt(totalResult?.count as string) || 0;

      // Apply pagination and ordering
      const executions = await query
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset)
        .execute();

      const totalPages = Math.ceil(total / limit);

      return {
        executions: executions.map(e => ({
          id: e.id,
          workflowId: e.workflow_id,
          status: e.status,
          startedAt: e.started_at,
          completedAt: e.completed_at,
          executionTimeMs: e.execution_time_ms,
          errorMessage: e.error_message,
          createdAt: e.created_at,
          updatedAt: e.updated_at,
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error('Failed to get executions', { error, options });
      throw error;
    }
  }

  async retryExecution(executionId: string, userId: string): Promise<string> {
    try {
      const execution = await this.getExecution(executionId, userId);
      if (!execution) {
        throw new Error('Execution not found');
      }

      // Only allow retry of failed executions
      if (execution.status !== 'failed') {
        throw new Error('Only failed executions can be retried');
      }

      // Create new execution with same trigger data
      return await this.enqueueExecution(execution.workflowId, execution.triggerData, userId);
    } catch (error) {
      logger.error('Failed to retry execution', { error, executionId, userId });
      throw error;
    }
  }

  async cancelExecution(executionId: string, userId: string): Promise<void> {
    try {
      const execution = await this.getExecution(executionId, userId);
      if (!execution) {
        throw new Error('Execution not found');
      }

      // Only allow cancel of queued or running executions
      if (!['queued', 'running'].includes(execution.status)) {
        throw new Error('Only queued or running executions can be cancelled');
      }

      // Update status to cancelled
      await db
        .updateTable('executions')
        .set({
          status: 'cancelled',
          completed_at: new Date(),
          updated_at: new Date(),
        })
        .where('id', '=', executionId)
        .execute();

      // Remove from queue if still queued
      try {
        const jobs = await executionQueue.getJob(executionId);
        if (jobs && jobs.finished) {
          // Job already completed, can't remove
        } else {
          await executionQueue.remove(executionId);
        }
      } catch (queueError) {
        logger.warn('Failed to remove job from queue', { executionId, error: queueError });
      }

      logger.info('Execution cancelled', { executionId, userId });
    } catch (error) {
      logger.error('Failed to cancel execution', { error, executionId, userId });
      throw error;
    }
  }
}

export const executionService = new ExecutionService();