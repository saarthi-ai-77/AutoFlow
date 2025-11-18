import { Router, Request, Response } from 'express';
import { workflowService, CreateWorkflowSchema, UpdateWorkflowSchema } from '@/services/workflow';
import { executionService } from '@/services/execution';
import { authenticate, requirePermission } from '@/api/middleware/auth';
import { z } from 'zod';
import { logger } from '@/utils/logger';

const router = Router();

// All workflow routes require authentication
router.use(authenticate);

// Get all workflows
router.get('/', requirePermission('read:workflows'), async (req: Request, res: Response) => {
  try {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const search = req.query.search as string;
    const tags = req.query.tags ? (req.query.tags as string).split(',') : undefined;
    const isPublic = req.query.isPublic ? req.query.isPublic === 'true' : undefined;

    const result = await workflowService.getWorkflows((req as any).user?.userId, {
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

    logger.debug('Workflows retrieved', {
      userId: (req as any).user?.userId,
      page,
      limit,
      count: result.workflows.length
    });
  } catch (error) {
    logger.error('Get workflows failed', { error, userId: (req as any).user?.userId, query: req.query });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Create workflow
router.post('/', async (req: Request, res: Response) => {
  try {
    const validatedData = CreateWorkflowSchema.parse(req.body);
    
    const workflow = await workflowService.createWorkflow((req as any).user?.userId, validatedData);

    res.status(201).json({
      message: 'Workflow created successfully',
      data: { workflow },
    });

    logger.info('Workflow created', {
      userId: (req as any).user?.userId,
      workflowId: workflow.id,
      name: workflow.name
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: error.errors,
      });
    }

    logger.error('Create workflow failed', { error, userId: (req as any).user?.userId, body: req.body });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Get workflow by ID
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    const workflow = await workflowService.getWorkflowById(id, (req as any).user?.userId);
    
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

    logger.debug('Workflow retrieved', {
      userId: (req as any).user?.userId,
      workflowId: id
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Access denied')) {
      return res.status(403).json({
        error: 'Access denied',
        code: 'ACCESS_DENIED',
      });
    }

    logger.error('Get workflow failed', { error, userId: (req as any).user?.userId, workflowId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Update workflow
router.put('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const validatedData = UpdateWorkflowSchema.parse(req.body);
    
    const workflow = await workflowService.updateWorkflow(id, (req as any).user?.userId, validatedData);

    res.json({
      message: 'Workflow updated successfully',
      data: { workflow },
    });

    logger.info('Workflow updated', {
      userId: (req as any).user?.userId,
      workflowId: id,
      version: workflow.version
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
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

    logger.error('Update workflow failed', { error, userId: (req as any).user?.userId, workflowId: req.params.id, body: req.body });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Delete workflow
router.delete('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    await workflowService.deleteWorkflow(id, (req as any).user?.userId);

    res.json({
      message: 'Workflow deleted successfully',
    });

    logger.info('Workflow deleted', {
      userId: (req as any).user?.userId,
      workflowId: id
    });
  } catch (error) {
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

    logger.error('Delete workflow failed', { error, userId: (req as any).user?.userId, workflowId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Execute workflow
router.post('/:id/execute', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const triggerData = req.body || {};
    
    const executionId = await executionService.enqueueExecution(id, triggerData, (req as any).user?.userId);

    res.status(202).json({
      message: 'Workflow execution started',
      data: { executionId },
    });

    logger.info('Workflow execution started', {
      userId: (req as any).user?.userId,
      workflowId: id,
      executionId
    });
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('not found') || error.message.includes('access denied')) {
        return res.status(404).json({
          error: 'Workflow not found',
          code: 'WORKFLOW_NOT_FOUND',
        });
      }
    }

    logger.error('Execute workflow failed', { error, userId: (req as any).user?.userId, workflowId: req.params.id, body: req.body });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Duplicate workflow
router.post('/:id/duplicate', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const newName = req.body.name;
    
    const workflow = await workflowService.duplicateWorkflow(id, (req as any).user?.userId, newName);

    res.status(201).json({
      message: 'Workflow duplicated successfully',
      data: { workflow },
    });

    logger.info('Workflow duplicated', {
      userId: (req as any).user?.userId,
      originalWorkflowId: id,
      newWorkflowId: workflow.id
    });
  } catch (error) {
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

    logger.error('Duplicate workflow failed', { error, userId: (req as any).user?.userId, workflowId: req.params.id, body: req.body });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Get workflow execution statistics
router.get('/:id/stats', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    
    const stats = await workflowService.getWorkflowExecutionStats(id, (req as any).user?.userId);

    res.json({
      message: 'Workflow statistics retrieved successfully',
      data: stats,
    });

    logger.debug('Workflow stats retrieved', {
      userId: (req as any).user?.userId,
      workflowId: id
    });
  } catch (error) {
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

    logger.error('Get workflow stats failed', { error, userId: (req as any).user?.userId, workflowId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

export { router as workflowRoutes };