import { Worker, Job } from 'bullmq';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/database/connection';
import { logger } from '@/utils/logger';
import { nodeRegistry, NodeExecutionContext } from '@/services/execution';
import { workflowService } from '@/services/workflow';
import Redis from 'ioredis';
import os from 'os';

// Redis connection for worker
const redisConfig = {
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD || undefined,
  lazyConnect: true,
  maxRetriesPerRequest: 3,
  retryDelayOnFailover: 100,
  enableReadyCheck: true,
  connectionTimeout: 5000,
  commandTimeout: 5000,
};

const redis = new Redis(redisConfig);

// Create worker with CPU-based concurrency
const cpuCount = os.cpus().length;
const workerConcurrency = Math.max(1, Math.min(cpuCount, 4)); // Max 4 workers

export const executionWorker = new Worker(
  'workflow-execution',
  async (job: Job) => {
    const { executionId, workflowId, triggerData, userId } = job.data;
    
    const startTime = Date.now();
    
    try {
      logger.info('Starting workflow execution', { 
        executionId, 
        workflowId, 
        userId,
        jobId: job.id
      });

      // Update execution status to running
      await db
        .updateTable('executions')
        .set({
          status: 'running',
          started_at: new Date(),
          updated_at: new Date(),
        })
        .where('id', '=', executionId)
        .execute();

      // Get workflow
      const workflow = await workflowService.getWorkflowById(workflowId, userId);
      if (!workflow) {
        throw new Error('Workflow not found');
      }

      const { nodes, edges } = workflow.graph;
      const nodeResults: Record<string, any> = {};
      const nodeLogs: any[] = [];

      // Find trigger nodes
      const triggerNodes = nodes.filter(node => node.type === 'trigger');
      
      if (triggerNodes.length === 0) {
        throw new Error('No trigger node found in workflow');
      }

      // Execute each trigger node (in parallel)
      for (const triggerNode of triggerNodes) {
        await executeNode(triggerNode, workflow, executionId, triggerData, nodeResults, nodeLogs);
      }

      // Execute remaining nodes based on graph traversal
      const remainingNodes = nodes.filter(node => node.type !== 'trigger');
      
      for (const node of remainingNodes) {
        // Check if all input connections are satisfied
        const incomingEdges = edges.filter(edge => edge.target === node.id);
        const canExecute = incomingEdges.every(edge => 
          nodeResults[edge.source]?.success === true
        );

        if (canExecute) {
          await executeNode(node, workflow, executionId, triggerData, nodeResults, nodeLogs);
        }
      }

      const executionTime = Date.now() - startTime;
      
      // Update execution as completed
      await db
        .updateTable('executions')
        .set({
          status: 'completed',
          completed_at: new Date(),
          execution_time_ms: executionTime,
          node_executions: nodeResults,
          updated_at: new Date(),
        })
        .where('id', '=', executionId)
        .execute();

      // Update workflow execution metrics
      await db
        .updateTable('workflows')
        .set({
          execution_count: (workflow.executionCount || 0) + 1,
          last_executed_at: new Date(),
          avg_execution_time_ms: workflow.avgExecutionTimeMs 
            ? Math.round((workflow.avgExecutionTimeMs + executionTime) / 2)
            : executionTime,
        })
        .where('id', '=', workflowId)
        .execute();

      logger.info('Workflow execution completed', {
        executionId,
        workflowId,
        userId,
        executionTime,
        completedNodes: Object.keys(nodeResults).length
      });

      return {
        executionId,
        status: 'completed',
        executionTime,
        nodeResults
      };

    } catch (error) {
      const executionTime = Date.now() - startTime;
      
      // Update execution as failed
      await db
        .updateTable('executions')
        .set({
          status: 'failed',
          completed_at: new Date(),
          execution_time_ms: executionTime,
          error_message: error instanceof Error ? error.message : 'Unknown error',
          updated_at: new Date(),
        })
        .where('id', '=', executionId)
        .execute();

      logger.error('Workflow execution failed', {
        executionId,
        workflowId,
        userId,
        error,
        executionTime
      });

      throw error;
    }
  },
  {
    connection: redis,
    concurrency: workerConcurrency,
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 50 },
    limiter: {
      max: 1000, // Max jobs per duration
      duration: 60000, // Per minute
    },
  }
);

// Execute a single node
async function executeNode(
  node: any,
  workflow: any,
  executionId: string,
  triggerData: any,
  nodeResults: Record<string, any>,
  nodeLogs: any[]
): Promise<void> {
  const startTime = Date.now();
  
  logger.info('Executing node', {
    executionId,
    workflowId: workflow.id,
    nodeId: node.id,
    nodeType: node.type
  });

  try {
    // Get node definition from registry
    const nodeDefinition = nodeRegistry.get(node.type);
    if (!nodeDefinition) {
      throw new Error(`Node type '${node.type}' not found in registry`);
    }

    // Build execution context
    const context: NodeExecutionContext = {
      workflowId: workflow.id,
      executionId,
      nodeId: node.id,
      inputs: node.data.inputs || {},
      config: node.data.config || {},
      previousResults: nodeResults,
    };

    // Execute node
    const result = await nodeDefinition.execute(context);
    
    // Store result
    nodeResults[node.id] = {
      success: result.success,
      outputs: result.outputs,
      error: result.error,
      executionTimeMs: result.executionTimeMs,
      logs: result.logs,
    };

    // Add to global node logs
    nodeLogs.push(...result.logs);

    const logLevel = result.success ? 'info' : 'error';
    logger.info(`Node ${result.success ? 'completed' : 'failed'}`, {
      executionId,
      nodeId: node.id,
      nodeType: node.type,
      duration: result.executionTimeMs,
      success: result.success
    });

    if (!result.success && result.error) {
      logger.error('Node execution failed', {
        executionId,
        nodeId: node.id,
        nodeType: node.type,
        error: result.error
      });
    }

  } catch (error) {
    const executionTime = Date.now() - startTime;
    
    // Store error result
    nodeResults[node.id] = {
      success: false,
      outputs: {},
      error: error instanceof Error ? error.message : 'Unknown error',
      executionTimeMs: executionTime,
      logs: [
        {
          level: 'error',
          message: `Node execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          timestamp: new Date(),
          error
        }
      ],
    };

    logger.error('Node execution failed', {
      executionId,
      nodeId: node.id,
      nodeType: node.type,
      error,
      executionTime
    });

    throw error;
  }
}

// Worker event handlers
executionWorker.on('completed', (job: Job) => {
  logger.info('Job completed', {
    jobId: job.id,
    jobType: job.name,
    executionId: job.data.executionId
  });
});

executionWorker.on('failed', (job: Job | undefined, error: Error) => {
  logger.error('Job failed', {
    jobId: job?.id,
    jobType: job?.name,
    executionId: job?.data.executionId,
    error: error.message,
    stack: error.stack
  });
});

executionWorker.on('progress', (job: Job, progress: number | object) => {
  logger.debug('Job progress', {
    jobId: job.id,
    executionId: job.data.executionId,
    progress
  });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, shutting down execution worker...');
  await executionWorker.close();
  await redis.quit();
  process.exit(0);
});

process.on('SIGINT', async () => {
  logger.info('Received SIGINT, shutting down execution worker...');
  await executionWorker.close();
  await redis.quit();
  process.exit(0);
});

export default executionWorker;