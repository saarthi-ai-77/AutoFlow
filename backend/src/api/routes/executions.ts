import { Router, Request, Response } from 'express';
import { executionService } from '@/services/execution';
import { authenticate, AuthenticatedRequest } from '@/api/middleware/auth';
import { z } from 'zod';
import { logger } from '@/utils/logger';

const router = Router();

// All execution routes require authentication
router.use(authenticate);

// Get executions with filtering and pagination
router.get('/', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const workflowId = req.query.workflowId as string;
    const status = req.query.status as string;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const startDate = req.query.startDate ? new Date(req.query.startDate as string) : undefined;
    const endDate = req.query.endDate ? new Date(req.query.endDate as string) : undefined;

    const result = await executionService.getExecutions(workflowId, req.user?.userId, {
      status,
      page,
      limit,
      startDate,
      endDate,
    });

    res.json({
      message: 'Executions retrieved successfully',
      data: result,
    });

    logger.debug('Executions retrieved', { 
      userId: req.user?.userId, 
      workflowId, 
      page, 
      limit, 
      count: result.executions.length 
    });
  } catch (error) {
    logger.error('Get executions failed', { error, userId: req.user?.userId, query: req.query });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Get execution by ID
router.get('/:id', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    
    const execution = await executionService.getExecution(id, req.user?.userId);
    
    if (!execution) {
      return res.status(404).json({
        error: 'Execution not found',
        code: 'EXECUTION_NOT_FOUND',
      });
    }

    res.json({
      message: 'Execution retrieved successfully',
      data: { execution },
    });

    logger.debug('Execution retrieved', { 
      userId: req.user?.userId, 
      executionId: id 
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Access denied')) {
      return res.status(403).json({
        error: 'Access denied',
        code: 'ACCESS_DENIED',
      });
    }

    logger.error('Get execution failed', { error, userId: req.user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Get execution logs
router.get('/:id/logs', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    
    const execution = await executionService.getExecution(id, req.user?.userId);
    
    if (!execution) {
      return res.status(404).json({
        error: 'Execution not found',
        code: 'EXECUTION_NOT_FOUND',
      });
    }

    // Extract logs from node executions
    const logs = execution.nodeExecutions?.logs || [];
    const nodeLogs: Array<any> = [];

    // Flatten logs from all node executions
    if (execution.nodeExecutions && typeof execution.nodeExecutions === 'object') {
      Object.values(execution.nodeExecutions).forEach((nodeExec: any) => {
        if (nodeExec.logs) {
          nodeLogs.push(...nodeExec.logs);
        }
      });
    }

    // Sort logs by timestamp
    nodeLogs.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    res.json({
      message: 'Execution logs retrieved successfully',
      data: { 
        logs: nodeLogs,
        executionId: id,
        status: execution.status
      },
    });

    logger.debug('Execution logs retrieved', { 
      userId: req.user?.userId, 
      executionId: id,
      logCount: nodeLogs.length 
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Access denied')) {
      return res.status(403).json({
        error: 'Access denied',
        code: 'ACCESS_DENIED',
      });
    }

    logger.error('Get execution logs failed', { error, userId: req.user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Retry failed execution
router.post('/:id/retry', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    
    const newExecutionId = await executionService.retryExecution(id, req.user?.userId);

    res.json({
      message: 'Execution retry started',
      data: { executionId: newExecutionId, status: 'queued' },
    });

    logger.info('Execution retry started', { 
      userId: req.user?.userId, 
      originalExecutionId: id,
      newExecutionId 
    });
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: 'Execution not found',
          code: 'EXECUTION_NOT_FOUND',
        });
      }
      
      if (error.message.includes('Access denied')) {
        return res.status(403).json({
          error: 'Access denied',
          code: 'ACCESS_DENIED',
        });
      }

      if (error.message.includes('Only failed executions can be retried')) {
        return res.status(400).json({
          error: 'Only failed executions can be retried',
          code: 'INVALID_RETRY_STATE',
        });
      }
    }

    logger.error('Retry execution failed', { error, userId: req.user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Cancel execution
router.post('/:id/cancel', async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { id } = req.params;
    
    await executionService.cancelExecution(id, req.user?.userId);

    res.json({
      message: 'Execution cancelled successfully',
    });

    logger.info('Execution cancelled', { 
      userId: req.user?.userId, 
      executionId: id 
    });
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: 'Execution not found',
          code: 'EXECUTION_NOT_FOUND',
        });
      }
      
      if (error.message.includes('Access denied')) {
        return res.status(403).json({
          error: 'Access denied',
          code: 'ACCESS_DENIED',
        });
      }

      if (error.message.includes('Only queued or running executions can be cancelled')) {
        return res.status(400).json({
          error: 'Only queued or running executions can be cancelled',
          code: 'INVALID_CANCEL_STATE',
        });
      }
    }

    logger.error('Cancel execution failed', { error, userId: req.user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

export { router as executionRoutes };