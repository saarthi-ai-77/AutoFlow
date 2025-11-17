import { Router, RequestHandler } from 'express';
import { executionService } from '@/services/execution';
import { authenticate, AuthenticatedRequest } from '@/api/middleware/auth';
import { logger } from '@/utils/logger';

const router = Router();

// All execution routes require authentication
router.use(authenticate as any);

// Get executions with filtering and pagination
const getExecutions: RequestHandler = async (req, res): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const workflowId = req.query.workflowId as string;
    const status = req.query.status as string;
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 10;
    const startDate = req.query.startDate ? new Date(req.query.startDate as string) : undefined;
    const endDate = req.query.endDate ? new Date(req.query.endDate as string) : undefined;

    const result = await executionService.getExecutions(workflowId, authReq.user?.userId, {
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
      userId: authReq.user?.userId,
      workflowId,
      page,
      limit,
      count: result.executions.length,
    });
  } catch (error) {
    logger.error('Get executions failed', { error, userId: (req as AuthenticatedRequest).user?.userId, query: req.query });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
};

router.get('/', getExecutions);

// Get execution by ID
const getExecution: RequestHandler = async (req, res): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { id } = req.params;

    const execution = await executionService.getExecution(id, authReq.user?.userId);

    if (!execution) {
      res.status(404).json({
        error: 'Execution not found',
        code: 'EXECUTION_NOT_FOUND',
      });
      return;
    }

    res.json({
      message: 'Execution retrieved successfully',
      data: { execution },
    });

    logger.debug('Execution retrieved', {
      userId: authReq.user?.userId,
      executionId: id,
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        code: 'ACCESS_DENIED',
      });
      return;
    }

    logger.error('Get execution failed', { error, userId: (req as AuthenticatedRequest).user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
};

router.get('/:id', getExecution);

// Get execution logs
const getExecutionLogs: RequestHandler = async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { id } = req.params;

    const execution = await executionService.getExecution(id, authReq.user?.userId);

    if (!execution) {
      res.status(404).json({
        error: 'Execution not found',
        code: 'EXECUTION_NOT_FOUND',
      });
      return;
    }

    // Extract logs from node executions
    const nodeLogs: Array<any> = [];

    // Flatten logs from all node executions
    if (execution.nodeExecutions && typeof execution.nodeExecutions === 'object') {
      Object.values(execution.nodeExecutions).forEach((nodeExec: any) => {
        if (Array.isArray(nodeExec?.logs)) {
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
        status: execution.status,
      },
    });

    logger.debug('Execution logs retrieved', {
      userId: authReq.user?.userId,
      executionId: id,
      logCount: nodeLogs.length,
    });
  } catch (error) {
    if (error instanceof Error && error.message.includes('Access denied')) {
      res.status(403).json({
        error: 'Access denied',
        code: 'ACCESS_DENIED',
      });
      return;
    }

    logger.error('Get execution logs failed', { error, userId: (req as AuthenticatedRequest).user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
};

router.get('/:id/logs', getExecutionLogs);

// Retry failed execution
const retryExecution: RequestHandler = async (req, res): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { id } = req.params;

    const newExecutionId = await executionService.retryExecution(id, authReq.user?.userId);

    res.json({
      message: 'Execution retry started',
      data: { executionId: newExecutionId, status: 'queued' },
    });

    logger.info('Execution retry started', {
      userId: authReq.user?.userId,
      originalExecutionId: id,
      newExecutionId,
    });
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        res.status(404).json({
          error: 'Execution not found',
          code: 'EXECUTION_NOT_FOUND',
        });
        return;
      }

      if (error.message.includes('Access denied')) {
        res.status(403).json({
          error: 'Access denied',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      if (error.message.includes('Only failed executions can be retried')) {
        res.status(400).json({
          error: 'Only failed executions can be retried',
          code: 'INVALID_RETRY_STATE',
        });
        return;
      }
    }

    logger.error('Retry execution failed', { error, userId: (req as AuthenticatedRequest).user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
};

router.post('/:id/retry', retryExecution);

// Cancel execution
const cancelExecution: RequestHandler = async (req, res): Promise<void> => {
  try {
    const authReq = req as AuthenticatedRequest;
    const { id } = req.params;

    await executionService.cancelExecution(id, authReq.user?.userId);

    res.json({
      message: 'Execution cancelled successfully',
    });

    logger.info('Execution cancelled', {
      userId: authReq.user?.userId,
      executionId: id,
    });
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('not found')) {
        res.status(404).json({
          error: 'Execution not found',
          code: 'EXECUTION_NOT_FOUND',
        });
        return;
      }

      if (error.message.includes('Access denied')) {
        res.status(403).json({
          error: 'Access denied',
          code: 'ACCESS_DENIED',
        });
        return;
      }

      if (error.message.includes('Only queued or running executions can be cancelled')) {
        res.status(400).json({
          error: 'Only queued or running executions can be cancelled',
          code: 'INVALID_CANCEL_STATE',
        });
        return;
      }
    }

    logger.error('Cancel execution failed', { error, userId: (req as AuthenticatedRequest).user?.userId, executionId: req.params.id });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
};

router.post('/:id/cancel', cancelExecution);

export { router as executionRoutes };