"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TriggerNode = void 0;
const zod_1 = require("zod");
const logger_1 = require("../utils/logger");
class TriggerNode {
    type = 'trigger';
    name = 'Trigger';
    description = 'Starting point for workflow execution';
    category = 'Core';
    icon = '🚀';
    version = '1.0.0';
    inputs = zod_1.z.object({});
    outputs = zod_1.z.object({
        triggerData: zod_1.z.record(zod_1.z.any()).describe('Data that triggered the workflow'),
        timestamp: zod_1.z.string().describe('ISO timestamp when workflow started'),
        executionId: zod_1.z.string().describe('Unique execution ID'),
    });
    config = zod_1.z.object({
        eventType: zod_1.z.string().optional().describe('Type of event that triggered this workflow'),
        webhookUrl: zod_1.z.string().optional().describe('Custom webhook URL for external triggers'),
    });
    async execute(context) {
        const startTime = Date.now();
        const logs = [];
        try {
            logger_1.logger.info('Executing trigger node', {
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
            logger_1.logger.info('Trigger node completed', {
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
        }
        catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'Unknown error';
            logs.push({
                level: 'error',
                message: `Trigger node failed: ${errorMessage}`,
                timestamp: new Date(),
                error,
            });
            logger_1.logger.error('Trigger node failed', {
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
    validate(config) {
        return true; // Trigger node doesn't require validation
    }
}
exports.TriggerNode = TriggerNode;
//# sourceMappingURL=TriggerNode.js.map