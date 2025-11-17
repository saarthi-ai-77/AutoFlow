"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.workflowRoutes = void 0;
const express_1 = require("express");
const workflow_1 = require("@/services/workflow");
const execution_1 = require("@/services/execution");
const auth_1 = require("@/api/middleware/auth");
const zod_1 = require("zod");
const logger_1 = require("@/utils/logger");
const router = (0, express_1.Router)();
exports.workflowRoutes = router;
// All workflow routes require authentication
router.use(auth_1.authenticate);
// Get all workflows
router.get('/', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const search = req.query.search;
        const tags = req.query.tags ? req.query.tags.split(',') : undefined;
        const isPublic = req.query.isPublic ? req.query.isPublic === 'true' : undefined;
        const result = await workflow_1.workflowService.getWorkflows(req.user?.userId, {
            page,
            limit,
            search,
            tags,
            isPublic,
        });
        res.json({
            message: 'Workflows retrieved successfully',
            data: result,
        });
        logger_1.logger.debug('Workflows retrieved', {
            userId: req.user?.userId,
            page,
            limit,
            count: result.workflows.length
        });
    }
    catch (error) {
        logger_1.logger.error('Get workflows failed', { error, userId: req.user?.userId, query: req.query });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Create workflow
router.post('/', async (req, res) => {
    try {
        const validatedData = workflow_1.CreateWorkflowSchema.parse(req.body);
        const workflow = await workflow_1.workflowService.createWorkflow(req.user?.userId, validatedData);
        res.status(201).json({
            message: 'Workflow created successfully',
            data: { workflow },
        });
        logger_1.logger.info('Workflow created', {
            userId: req.user?.userId,
            workflowId: workflow.id,
            name: workflow.name
        });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.errors,
            });
        }
        logger_1.logger.error('Create workflow failed', { error, userId: req.user?.userId, body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Get workflow by ID
router.get('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const workflow = await workflow_1.workflowService.getWorkflowById(id, req.user?.userId);
        if (!workflow) {
            return res.status(404).json({
                error: 'Workflow not found',
                code: 'WORKFLOW_NOT_FOUND',
            });
        }
        res.json({
            message: 'Workflow retrieved successfully',
            data: { workflow },
        });
        logger_1.logger.debug('Workflow retrieved', {
            userId: req.user?.userId,
            workflowId: id
        });
    }
    catch (error) {
        if (error instanceof Error && error.message.includes('Access denied')) {
            return res.status(403).json({
                error: 'Access denied',
                code: 'ACCESS_DENIED',
            });
        }
        logger_1.logger.error('Get workflow failed', { error, userId: req.user?.userId, workflowId: req.params.id });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Update workflow
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const validatedData = workflow_1.UpdateWorkflowSchema.parse(req.body);
        const workflow = await workflow_1.workflowService.updateWorkflow(id, req.user?.userId, validatedData);
        res.json({
            message: 'Workflow updated successfully',
            data: { workflow },
        });
        logger_1.logger.info('Workflow updated', {
            userId: req.user?.userId,
            workflowId: id,
            version: workflow.version
        });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.errors,
            });
        }
        if (error instanceof Error) {
            if (error.message.includes('not found')) {
                return res.status(404).json({
                    error: 'Workflow not found',
                    code: 'WORKFLOW_NOT_FOUND',
                });
            }
            if (error.message.includes('Access denied')) {
                return res.status(403).json({
                    error: 'Access denied',
                    code: 'ACCESS_DENIED',
                });
            }
        }
        logger_1.logger.error('Update workflow failed', { error, userId: req.user?.userId, workflowId: req.params.id, body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Delete workflow
router.delete('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        await workflow_1.workflowService.deleteWorkflow(id, req.user?.userId);
        res.json({
            message: 'Workflow deleted successfully',
        });
        logger_1.logger.info('Workflow deleted', {
            userId: req.user?.userId,
            workflowId: id
        });
    }
    catch (error) {
        if (error instanceof Error) {
            if (error.message.includes('not found')) {
                return res.status(404).json({
                    error: 'Workflow not found',
                    code: 'WORKFLOW_NOT_FOUND',
                });
            }
            if (error.message.includes('Access denied')) {
                return res.status(403).json({
                    error: 'Access denied',
                    code: 'ACCESS_DENIED',
                });
            }
        }
        logger_1.logger.error('Delete workflow failed', { error, userId: req.user?.userId, workflowId: req.params.id });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Execute workflow
router.post('/:id/execute', async (req, res) => {
    try {
        const { id } = req.params;
        const triggerData = req.body || {};
        const executionId = await execution_1.executionService.enqueueExecution(id, triggerData, req.user?.userId);
        res.status(202).json({
            message: 'Workflow execution started',
            data: { executionId },
        });
        logger_1.logger.info('Workflow execution started', {
            userId: req.user?.userId,
            workflowId: id,
            executionId
        });
    }
    catch (error) {
        if (error instanceof Error) {
            if (error.message.includes('not found') || error.message.includes('access denied')) {
                return res.status(404).json({
                    error: 'Workflow not found',
                    code: 'WORKFLOW_NOT_FOUND',
                });
            }
        }
        logger_1.logger.error('Execute workflow failed', { error, userId: req.user?.userId, workflowId: req.params.id, body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Duplicate workflow
router.post('/:id/duplicate', async (req, res) => {
    try {
        const { id } = req.params;
        const newName = req.body.name;
        const workflow = await workflow_1.workflowService.duplicateWorkflow(id, req.user?.userId, newName);
        res.status(201).json({
            message: 'Workflow duplicated successfully',
            data: { workflow },
        });
        logger_1.logger.info('Workflow duplicated', {
            userId: req.user?.userId,
            originalWorkflowId: id,
            newWorkflowId: workflow.id
        });
    }
    catch (error) {
        if (error instanceof Error) {
            if (error.message.includes('not found')) {
                return res.status(404).json({
                    error: 'Workflow not found',
                    code: 'WORKFLOW_NOT_FOUND',
                });
            }
            if (error.message.includes('Access denied')) {
                return res.status(403).json({
                    error: 'Access denied',
                    code: 'ACCESS_DENIED',
                });
            }
        }
        logger_1.logger.error('Duplicate workflow failed', { error, userId: req.user?.userId, workflowId: req.params.id, body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Get workflow execution statistics
router.get('/:id/stats', async (req, res) => {
    try {
        const { id } = req.params;
        const stats = await workflow_1.workflowService.getWorkflowExecutionStats(id, req.user?.userId);
        res.json({
            message: 'Workflow statistics retrieved successfully',
            data: stats,
        });
        logger_1.logger.debug('Workflow stats retrieved', {
            userId: req.user?.userId,
            workflowId: id
        });
    }
    catch (error) {
        if (error instanceof Error) {
            if (error.message.includes('not found')) {
                return res.status(404).json({
                    error: 'Workflow not found',
                    code: 'WORKFLOW_NOT_FOUND',
                });
            }
            if (error.message.includes('Access denied')) {
                return res.status(403).json({
                    error: 'Access denied',
                    code: 'ACCESS_DENIED',
                });
            }
        }
        logger_1.logger.error('Get workflow stats failed', { error, userId: req.user?.userId, workflowId: req.params.id });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
//# sourceMappingURL=workflows.js.map