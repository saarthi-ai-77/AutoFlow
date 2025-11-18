import { Router, Request, Response } from 'express';
import { authenticate } from '@/api/middleware/auth';
import { db } from '@/database/connection';
import { logger } from '@/utils/logger';
import { hashApiKey } from '@/utils/security';

const router = Router();

// All user routes require authentication
router.use(authenticate);

// POST /api/user/delete - Schedule account deletion (30-day grace)
router.post('/delete', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId || (req as any).user?.id;
    const { reason } = req.body;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
    }

    // Check if user is already marked for deletion
    const user = await db
      .selectFrom('users')
      .selectAll()
      .where('id', '=', userId)
      .executeTakeFirst();

    if (user && !user.is_active) {
      return res.status(400).json({
        error: 'Account deletion already scheduled',
        code: 'DELETION_ALREADY_SCHEDULED'
      });
    }

    // Schedule deletion for 30 days from now
    const scheduledFor = new Date();
    scheduledFor.setDate(scheduledFor.getDate() + 30);

    // Mark user as pending deletion
    await db
      .updateTable('users')
      .set({ is_active: false })
      .where('id', '=', userId)
      .execute();

    logger.info('Account deletion scheduled', { userId, scheduledFor });

    res.json({
      message: 'Account deletion scheduled successfully',
      data: {
        scheduledFor: scheduledFor.toISOString(),
        gracePeriodDays: 30
      }
    });
  } catch (error) {
    logger.error('Schedule account deletion failed', { error, userId: (req as any).user?.userId });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
});

// GET /api/user/export - Download all user data as JSON
router.get('/export', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId || (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
    }

    // Export user profile
    const user = await db
      .selectFrom('users')
      .select(['id', 'email', 'first_name', 'last_name', 'role', 'created_at', 'updated_at', 'last_login_at'])
      .where('id', '=', userId)
      .executeTakeFirst();

    // Export workflows
    const workflows = await db
      .selectFrom('workflows')
      .select(['id', 'name', 'description', 'version', 'is_public', 'tags', 'created_at', 'updated_at', 'execution_count'])
      .where('owner_id', '=', userId)
      .execute();

    // Export executions
    const executions = await db
      .selectFrom('executions')
      .innerJoin('workflows', 'workflows.id', 'executions.workflow_id')
      .select([
        'executions.id',
        'executions.workflow_id',
        'workflows.name as workflow_name',
        'executions.status',
        'executions.trigger_data',
        'executions.started_at',
        'executions.completed_at',
        'executions.execution_time_ms',
        'executions.error_message',
        'executions.created_at'
      ])
      .where('workflows.owner_id', '=', userId)
      .execute();

    // Export API keys (without actual keys, just metadata)
    const apiKeys = await db
      .selectFrom('api_keys')
      .select(['id', 'name', 'scopes', 'last_used_at', 'expires_at', 'created_at'])
      .where('user_id', '=', userId)
      .execute();

    const exportData = {
      exportedAt: new Date().toISOString(),
      user: user,
      workflows: workflows,
      executions: executions,
      apiKeys: apiKeys,
      dataRetention: {
        note: 'This export contains all your data. Some sensitive information may be hashed or omitted for security.'
      }
    };

    logger.info('User data exported', { userId, recordCount: workflows.length + executions.length + apiKeys.length });

    // Set headers for file download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="autoflow-data-export-${userId}.json"`);

    res.json(exportData);
  } catch (error) {
    logger.error('Export user data failed', { error, userId: (req as any).user?.userId });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
});

// POST /api/user/anonymize - Hash PII for analytics retention
router.post('/anonymize', async (req: Request, res: Response) => {
  try {
    const userId = (req as any).user?.userId || (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
    }

    // Hash personally identifiable information
    const anonymizedEmail = await hashApiKey(`${userId}-email-${Date.now()}`);
    const anonymizedName = await hashApiKey(`${userId}-name-${Date.now()}`);

    // Update user record with anonymized data
    await db
      .updateTable('users')
      .set({
        email: anonymizedEmail,
        first_name: anonymizedName,
        last_name: '',
        is_active: false, // Deactivate account
        updated_at: new Date()
      })
      .where('id', '=', userId)
      .execute();

    logger.info('User data anonymized', { userId });

    res.json({
      message: 'User data anonymized successfully',
      data: {
        anonymizedAt: new Date().toISOString(),
        note: 'Your account has been deactivated and PII has been hashed for analytics retention only.'
      }
    });
  } catch (error) {
    logger.error('Anonymize user data failed', { error, userId: (req as any).user?.userId });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
});

export { router as userRoutes };