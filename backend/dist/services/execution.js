"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.executionService = exports.ExecutionService = exports.nodeRegistry = exports.NodeRegistry = exports.NodeExecutionResultSchema = exports.NodeExecutionContextSchema = exports.executionQueue = void 0;
const zod_1 = require("zod");
const uuid_1 = require("uuid");
const bullmq_1 = require("bullmq");
const connection_1 = require("@/database/connection");
const logger_1 = require("@/utils/logger");
const environment_1 = require("@/config/environment");
const workflow_1 = require("./workflow");
const ioredis_1 = __importDefault(require("ioredis"));
// Redis connection for queue
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
// Create queue
exports.executionQueue = new bullmq_1.Queue('workflow-execution', {
    connection: redis,
});
// Node execution schemas
exports.NodeExecutionContextSchema = zod_1.z.object({
    workflowId: zod_1.z.string(),
    executionId: zod_1.z.string(),
    nodeId: zod_1.z.string(),
    inputs: zod_1.z.record(zod_1.z.any()).default({}),
    config: zod_1.z.record(zod_1.z.any()).default({}),
    previousResults: zod_1.z.record(zod_1.z.any()).default({}),
    webhooks: zod_1.z.object({
        baseUrl: zod_1.z.string(),
        executionId: zod_1.z.string(),
        nodeId: zod_1.z.string(),
    }).optional(),
});
exports.NodeExecutionResultSchema = zod_1.z.object({
    success: zod_1.z.boolean(),
    outputs: zod_1.z.record(zod_1.z.any()).default({}),
    error: zod_1.z.string().optional(),
    executionTimeMs: zod_1.z.number(),
    logs: zod_1.z.array(zod_1.z.object({
        level: zod_1.z.enum(['debug', 'info', 'warn', 'error']),
        message: zod_1.z.string(),
        timestamp: zod_1.z.date(),
        data: zod_1.z.record(zod_1.z.any()).optional(),
    })).default([]),
});
class NodeRegistry {
    nodes = new Map();
    register(node) {
        if (this.nodes.has(node.type)) {
            throw new Error(`Node type '${node.type}' is already registered`);
        }
        this.nodes.set(node.type, node);
        logger_1.logger.info(`Registered node type: ${node.type}`, { nodeType: node.type, version: node.version });
    }
    get(type) {
        return this.nodes.get(type);
    }
    getAll() {
        return Array.from(this.nodes.values());
    }
    getByCategory(category) {
        return Array.from(this.nodes.values()).filter(node => node.category === category);
    }
    has(type) {
        return this.nodes.has(type);
    }
}
exports.NodeRegistry = NodeRegistry;
exports.nodeRegistry = new NodeRegistry();
// Built-in node implementations
const TriggerNode_1 = require("../nodes/TriggerNode");
const HTTPNode_1 = require("../nodes/HTTPNode");
const EmailNode_1 = require("../nodes/EmailNode");
// Register built-in nodes
exports.nodeRegistry.register(new TriggerNode_1.TriggerNode());
exports.nodeRegistry.register(new HTTPNode_1.HTTPNode());
exports.nodeRegistry.register(new EmailNode_1.EmailNode());
exports.nodeRegistry.register(new EmailNode_1.DebugNode());
exports.nodeRegistry.register(new EmailNode_1.DelayNode());
class ExecutionService {
    async enqueueExecution(workflowId, triggerData, userId) {
        try {
            // Verify workflow exists and user has access
            const workflow = await workflow_1.workflowService.getWorkflowById(workflowId, userId);
            if (!workflow) {
                throw new Error('Workflow not found or access denied');
            }
            // Create execution record
            const executionId = (0, uuid_1.v4)();
            const now = new Date();
            await connection_1.db
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
            await exports.executionQueue.add('execute-workflow', {
                executionId,
                workflowId,
                triggerData,
                userId,
            }, {
                attempts: environment_1.queueConfig.attempts,
                backoff: {
                    type: 'exponential',
                    delay: environment_1.queueConfig.backoffDelay,
                },
                removeOnComplete: 100,
                removeOnFail: 50,
            });
            logger_1.logger.info('Workflow execution enqueued', { executionId, workflowId, userId });
            return executionId;
        }
        catch (error) {
            logger_1.logger.error('Failed to enqueue workflow execution', { error, workflowId, userId });
            throw error;
        }
    }
    async getExecution(executionId, userId) {
        try {
            const execution = await connection_1.db
                .selectFrom('executions')
                .selectAll()
                .where('id', '=', executionId)
                .executeTakeFirst();
            if (!execution) {
                throw new Error('Execution not found');
            }
            // Check access permissions if userId provided
            if (userId) {
                const workflow = await workflow_1.workflowService.getWorkflowById(execution.workflow_id, userId);
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
        }
        catch (error) {
            logger_1.logger.error('Failed to get execution', { error, executionId });
            throw error;
        }
    }
    async getExecutions(workflowId, userId, options = {}) {
        try {
            const { status, page = 1, limit = 10, startDate, endDate, cursor } = options;
            const offset = (page - 1) * limit;
            // Use JOIN to filter by user access and get workflow info in single query
            let query = connection_1.db
                .selectFrom('executions')
                .innerJoin('workflows', 'workflows.id', 'executions.workflow_id')
                .select([
                'executions.id',
                'executions.workflow_id',
                'executions.status',
                'executions.started_at',
                'executions.completed_at',
                'executions.execution_time_ms',
                'executions.error_message',
                'executions.created_at',
                'executions.updated_at',
                'workflows.name as workflow_name',
                'workflows.owner_id',
                'workflows.is_public',
            ])
                .where('workflows.is_active', '=', true);
            // Filter by user access: owner or public
            if (userId) {
                query = query.where((eb) => eb.or([
                    eb('workflows.owner_id', '=', userId),
                    eb('workflows.is_public', '=', true)
                ]));
            }
            else {
                // If no userId, only show public workflows
                query = query.where('workflows.is_public', '=', true);
            }
            if (workflowId) {
                query = query.where('executions.workflow_id', '=', workflowId);
            }
            if (status) {
                query = query.where('executions.status', '=', status);
            }
            if (startDate) {
                query = query.where('executions.created_at', '>=', startDate);
            }
            if (endDate) {
                query = query.where('executions.created_at', '<=', endDate);
            }
            // Cursor-based pagination
            if (cursor) {
                const cursorDate = new Date(cursor);
                query = query.where('executions.created_at', '<', cursorDate);
            }
            // Get total count (for backward compatibility, but expensive for large datasets)
            let total = 0;
            if (!cursor) {
                const countQuery = query.select(({ fn }) => fn.countAll().as('count'));
                const totalResult = await countQuery.executeTakeFirst();
                total = parseInt(totalResult?.count) || 0;
            }
            // Apply ordering and pagination
            const executions = await query
                .orderBy('executions.created_at', 'desc')
                .limit(limit)
                .execute();
            // For cursor pagination, next cursor is the last item's created_at
            const nextCursor = executions.length === limit ? executions[executions.length - 1].created_at.toISOString() : null;
            return {
                executions: executions.map(e => ({
                    id: e.id,
                    workflowId: e.workflow_id,
                    workflowName: e.workflow_name,
                    status: e.status,
                    startedAt: e.started_at,
                    completedAt: e.completed_at,
                    executionTimeMs: e.execution_time_ms,
                    errorMessage: e.error_message,
                    createdAt: e.created_at,
                    updatedAt: e.updated_at,
                })),
                pagination: cursor ? {
                    cursor: nextCursor,
                    hasNext: !!nextCursor,
                    limit,
                } : {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                    hasNext: page < Math.ceil(total / limit),
                    hasPrev: page > 1,
                },
            };
        }
        catch (error) {
            logger_1.logger.error('Failed to get executions', { error, options });
            throw error;
        }
    }
    async retryExecution(executionId, userId) {
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
        }
        catch (error) {
            logger_1.logger.error('Failed to retry execution', { error, executionId, userId });
            throw error;
        }
    }
    async cancelExecution(executionId, userId) {
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
            await connection_1.db
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
                const jobs = await exports.executionQueue.getJob(executionId);
                if (jobs && jobs.finished) {
                    // Job already completed, can't remove
                }
                else {
                    await exports.executionQueue.remove(executionId);
                }
            }
            catch (queueError) {
                logger_1.logger.warn('Failed to remove job from queue', { executionId, error: queueError });
            }
            logger_1.logger.info('Execution cancelled', { executionId, userId });
        }
        catch (error) {
            logger_1.logger.error('Failed to cancel execution', { error, executionId, userId });
            throw error;
        }
    }
}
exports.ExecutionService = ExecutionService;
exports.executionService = new ExecutionService();
//# sourceMappingURL=execution.js.map