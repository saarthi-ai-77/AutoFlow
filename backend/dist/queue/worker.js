"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.executionWorker = void 0;
const bullmq_1 = require("bullmq");
const connection_1 = require("@/database/connection");
const logger_1 = require("@/utils/logger");
const execution_1 = require("@/services/execution");
const workflow_1 = require("@/services/workflow");
const ioredis_1 = __importDefault(require("ioredis"));
const os_1 = __importDefault(require("os"));
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
const redis = new ioredis_1.default(redisConfig);
// Create worker with CPU-based concurrency
const cpuCount = os_1.default.cpus().length;
const workerConcurrency = Math.max(1, Math.min(cpuCount, 4)); // Max 4 workers
exports.executionWorker = new bullmq_1.Worker('workflow-execution', async (job) => {
    const { executionId, workflowId, triggerData, userId } = job.data;
    const startTime = Date.now();
    try {
        logger_1.logger.info('Starting workflow execution', {
            executionId,
            workflowId,
            userId,
            jobId: job.id
        });
        // Update execution status to running
        await connection_1.db
            .updateTable('executions')
            .set({
            status: 'running',
            started_at: new Date(),
            updated_at: new Date(),
        })
            .where('id', '=', executionId)
            .execute();
        // Get workflow
        const workflow = await workflow_1.workflowService.getWorkflowById(workflowId, userId);
        if (!workflow) {
            throw new Error('Workflow not found');
        }
        const { nodes, edges } = workflow.graph;
        const nodeResults = {};
        const nodeLogs = [];
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
            const canExecute = incomingEdges.every(edge => nodeResults[edge.source]?.success === true);
            if (canExecute) {
                await executeNode(node, workflow, executionId, triggerData, nodeResults, nodeLogs);
            }
        }
        const executionTime = Date.now() - startTime;
        // Update execution as completed
        await connection_1.db
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
        await connection_1.db
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
        logger_1.logger.info('Workflow execution completed', {
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
    }
    catch (error) {
        const executionTime = Date.now() - startTime;
        // Update execution as failed
        await connection_1.db
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
        logger_1.logger.error('Workflow execution failed', {
            executionId,
            workflowId,
            userId,
            error,
            executionTime
        });
        throw error;
    }
}, {
    connection: redis,
    concurrency: workerConcurrency,
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 50 },
    limiter: {
        max: 1000, // Max jobs per duration
        duration: 60000, // Per minute
    },
});
// Execute a single node
async function executeNode(node, workflow, executionId, triggerData, nodeResults, nodeLogs) {
    const startTime = Date.now();
    logger_1.logger.info('Executing node', {
        executionId,
        workflowId: workflow.id,
        nodeId: node.id,
        nodeType: node.type
    });
    try {
        // Get node definition from registry
        const nodeDefinition = execution_1.nodeRegistry.get(node.type);
        if (!nodeDefinition) {
            throw new Error(`Node type '${node.type}' not found in registry`);
        }
        // Build execution context
        const context = {
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
        logger_1.logger.info(`Node ${result.success ? 'completed' : 'failed'}`, {
            executionId,
            nodeId: node.id,
            nodeType: node.type,
            duration: result.executionTimeMs,
            success: result.success
        });
        if (!result.success && result.error) {
            logger_1.logger.error('Node execution failed', {
                executionId,
                nodeId: node.id,
                nodeType: node.type,
                error: result.error
            });
        }
    }
    catch (error) {
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
        logger_1.logger.error('Node execution failed', {
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
exports.executionWorker.on('completed', (job) => {
    logger_1.logger.info('Job completed', {
        jobId: job.id,
        jobType: job.name,
        executionId: job.data.executionId
    });
});
exports.executionWorker.on('failed', (job, error) => {
    logger_1.logger.error('Job failed', {
        jobId: job?.id,
        jobType: job?.name,
        executionId: job?.data.executionId,
        error: error.message,
        stack: error.stack
    });
});
exports.executionWorker.on('progress', (job, progress) => {
    logger_1.logger.debug('Job progress', {
        jobId: job.id,
        executionId: job.data.executionId,
        progress
    });
});
// Graceful shutdown
process.on('SIGTERM', async () => {
    logger_1.logger.info('Received SIGTERM, shutting down execution worker...');
    await exports.executionWorker.close();
    await redis.quit();
    process.exit(0);
});
process.on('SIGINT', async () => {
    logger_1.logger.info('Received SIGINT, shutting down execution worker...');
    await exports.executionWorker.close();
    await redis.quit();
    process.exit(0);
});
exports.default = exports.executionWorker;
//# sourceMappingURL=worker.js.map