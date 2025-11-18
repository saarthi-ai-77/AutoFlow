import { Request, Response, NextFunction } from 'express';
import { authService } from '@/services/auth';
import { logger } from '@/utils/logger';
import { JWTPayload } from '@/services/auth';
import { hashApiKey } from '@/utils/security';
import { db } from '@/database/connection';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: JWTPayload;
    }
  }
}

export interface AuthenticatedRequest extends Request {
  user: JWTPayload;
}

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    const apiKey = req.headers['x-api-key'] as string;

    // Try JWT authentication first
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7); // Remove 'Bearer ' prefix

      const payload = await authService.verifyToken(token);

      if (payload) {
        (req as any).user = payload;
        return next();
      }
    }

    // If JWT failed or not provided, try API key authentication
    if (apiKey) {
      try {
        // Validate API key format
        const isValidFormat = /^[a-zA-Z0-9\-_.]+$/.test(apiKey);
        if (!isValidFormat) {
          logger.warn('Invalid API key format', {
            apiKeyPreview: apiKey.substring(0, 10) + '...',
            userAgent: req.get('User-Agent'),
            ip: req.ip
          });
          return res.status(401).json({
            error: 'Invalid API key format',
            code: 'INVALID_API_KEY_FORMAT'
          });
        }

        // Validate API key against database
        const keyHash = await hashApiKey(apiKey);
        const apiKeyRecord = await db
          .selectFrom('api_keys')
          .selectAll()
          .where('key_hash', '=', keyHash)
          .where('is_active', '=', true)
          .where('expires_at', '>', new Date())
          .executeTakeFirst();

        if (!apiKeyRecord) {
          logger.warn('Invalid API key', {
            apiKeyPreview: apiKey.substring(0, 10) + '...',
            userAgent: req.get('User-Agent'),
            ip: req.ip
          });
          return res.status(401).json({
            error: 'Invalid API key',
            code: 'INVALID_API_KEY'
          });
        }

        // Get user associated with API key
        const user = await db
          .selectFrom('users')
          .select(['id', 'email', 'role', 'is_active'])
          .where('id', '=', apiKeyRecord.user_id)
          .where('is_active', '=', true)
          .executeTakeFirst();

        if (!user) {
          logger.warn('API key user not found or inactive', {
            apiKeyId: apiKeyRecord.id,
            userId: apiKeyRecord.user_id
          });
          return res.status(401).json({
            error: 'API key user not found',
            code: 'API_KEY_USER_INACTIVE'
          });
        }

        // Attach user and API key info to request
        (req as any).user = {
          id: user.id,
          email: user.email,
          role: user.role,
          apiKeyId: apiKeyRecord.id,
          scopes: apiKeyRecord.scopes,
        };

        // Update last used timestamp
        await db
          .updateTable('api_keys')
          .set({ last_used_at: new Date() })
          .where('id', '=', apiKeyRecord.id)
          .execute();

        logger.debug('API key authenticated successfully', {
          apiKeyId: apiKeyRecord.id,
          userId: user.id,
          path: req.path,
          method: req.method
        });

        return next();
      } catch (error) {
        logger.error('API key authentication error', { error });
        return res.status(500).json({
          error: 'Internal server error',
          code: 'INTERNAL_ERROR'
        });
      }
    }

    // No valid authentication found
    return res.status(401).json({
      error: 'Authentication required (Bearer token or API key)',
      code: 'UNAUTHORIZED'
    });
  } catch (error) {
    logger.error('Authentication error', { error });
    return res.status(401).json({
      error: 'Authentication failed',
      code: 'AUTH_ERROR'
    });
  }
};

export const requireRole = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    
    if (!user) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
    }

    if (!roles.includes(user.role)) {
      return res.status(403).json({
        error: 'Insufficient permissions',
        code: 'FORBIDDEN'
      });
    }

    next();
  };
};

export const requireOwnership = (resourceUserIdField: string = 'owner_id') => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = (req as any).user;
      
      if (!user) {
        return res.status(401).json({
          error: 'Authentication required',
          code: 'UNAUTHORIZED'
        });
      }

      // Admins can access any resource
      if (user.role === 'admin') {
        return next();
      }

      // Check if the authenticated user owns the resource
      // This will be implemented in the route handlers where we have access to the resource
      next();
    } catch (error) {
      logger.error('Ownership check error', { error });
      return res.status(500).json({
        error: 'Permission check failed',
        code: 'PERMISSION_ERROR'
      });
    }
  };
};

export const optionalAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const payload = await authService.verifyToken(token);
      
      if (payload) {
        (req as any).user = payload;
      }
    }

    next();
  } catch (error) {
    // For optional auth, we don't fail on invalid tokens
    logger.debug('Optional auth failed', { error });
    next();
  }
};

export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;

    if (!user) {
      return res.status(401).json({
        error: 'Authentication required',
        code: 'UNAUTHORIZED'
      });
    }

    // If authenticated via API key, check permissions
    if (user.apiKeyId && user.scopes) {
      if (!user.scopes.includes(permission)) {
        return res.status(403).json({
          error: 'API key lacks permission',
          code: 'FORBIDDEN'
        });
      }
    }

    // JWT users have full access (assuming role-based checks elsewhere)
    next();
  };
};

export const requireApiKey = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      return res.status(401).json({
        error: 'API key required',
        code: 'API_KEY_REQUIRED'
      });
    }

    // API key validation will be implemented here
    // For now, we'll just continue
    next();
  } catch (error) {
    logger.error('API key validation error', { error });
    return res.status(401).json({
      error: 'Invalid API key',
      code: 'API_KEY_INVALID'
    });
  }
};