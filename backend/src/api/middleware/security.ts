import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import { Request, Response, NextFunction } from 'express';
import { rateLimitConfig, env } from '@/config/environment';
import { logger, morganStream } from '@/utils/logger';
import { RateLimitKeySchema, hashApiKey } from '@/utils/security';
import { db } from '@/database/connection';

// Enhanced rate limiting tiers
const RATE_LIMIT_TIERS = {
  // Strict limits for authentication endpoints
  AUTH: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per 15 minutes
    message: {
      error: 'Too many authentication attempts, please try again later.',
      code: 'AUTH_RATE_LIMIT_EXCEEDED',
      retryAfter: 15 * 60
    },
    skipSuccessfulRequests: true,
    skipFailedRequests: false,
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // General API endpoints
  GENERAL: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per 15 minutes
    message: {
      error: 'Too many requests, please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: 15 * 60
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Execution endpoints (more lenient for active users)
  EXECUTION: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 1000, // 1000 requests per hour
    message: {
      error: 'Too many execution requests, please try again later.',
      code: 'EXECUTION_RATE_LIMIT_EXCEEDED',
      retryAfter: 60 * 60
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Workflow creation/editing (strict to prevent abuse)
  WORKFLOW: {
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 50, // 50 workflow operations per hour
    message: {
      error: 'Too many workflow operations, please try again later.',
      code: 'WORKFLOW_RATE_LIMIT_EXCEEDED',
      retryAfter: 60 * 60
    },
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Search and listing endpoints
  SEARCH: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // 200 searches per 15 minutes
    message: {
      error: 'Too many search requests, please try again later.',
      code: 'SEARCH_RATE_LIMIT_EXCEEDED',
      retryAfter: 15 * 60
    },
    standardHeaders: true,
    legacyHeaders: false,
  }
};

// Create enhanced rate limiter
export const createTieredRateLimiter = (
  tier: keyof typeof RATE_LIMIT_TIERS,
  customKeyGenerator?: (req: Request) => string
) => {
  const config = RATE_LIMIT_TIERS[tier];
  
  return rateLimit({
    ...config,
    skip: (req) => {
      // Skip rate limiting for health checks and internal monitoring
      if ((req as any).path === '/health' || (req as any).path === '/metrics' || (req as any).path?.startsWith('/api/health')) {
        return true;
      }

      // Skip rate limiting for OPTIONS requests (preflight)
      if (req.method === 'OPTIONS') {
        return true;
      }

      return false;
    },
    keyGenerator: (req) => {
      // Use custom key generator if provided
      if (customKeyGenerator) {
        return customKeyGenerator(req);
      }
      
      // Default key generation: user ID if authenticated, otherwise IP
      const userId = (req.user as any)?.userId;
      if (userId) {
        return `user:${userId}`;
      }
      
      // Fallback to IP address
      const ip = req.ip || req.connection.remoteAddress || 'unknown';
      return `ip:${ip}`;
    },
    handler: (req: Request, res: Response) => {
      const key = req.ip || 'unknown';
      logger.warn('Rate limit exceeded', {
        tier,
        key: RateLimitKeySchema.safeParse(key).success ? key : 'invalid',
        userAgent: req.get('User-Agent'),
        path: (req as any).path,
        method: req.method,
        userId: (req.user as any)?.userId
      });
      
      res.status(429).json(config.message);
    },
    onLimitReached: (req: Request, res: Response, optionsUsed: any) => {
      logger.warn('Rate limit reached', {
        tier,
        key: req.ip,
        path: (req as any).path,
        method: req.method,
        userId: (req.user as any)?.userId,
        userAgent: req.get('User-Agent')
      });
    }
  });
};

// Rate limiting configuration
export const createRateLimiter = (options?: Partial<{ windowMs: number; maxRequests: number }>) => {
  const config = { ...rateLimitConfig, ...options };
  
  return rateLimit({
    windowMs: config.windowMs,
    max: config.maxRequests,
    message: {
      error: 'Too many requests from this IP, please try again later.',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: Math.ceil(config.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Skip rate limiting for health checks
      return (req as any).path === '/health';
    },
    keyGenerator: (req) => {
      // Use user ID if authenticated, otherwise IP
      return (req.user as any)?.userId || req.ip;
    }
  });
};

// More strict rate limiting for auth endpoints
export const authRateLimiter = createTieredRateLimiter('AUTH');

// General rate limiting
export const generalRateLimiter = createTieredRateLimiter('GENERAL');

// Execution rate limiting
export const executionRateLimiter = createTieredRateLimiter('EXECUTION');

// Workflow rate limiting
export const workflowRateLimiter = createTieredRateLimiter('WORKFLOW');

// Search rate limiting
export const searchRateLimiter = createTieredRateLimiter('SEARCH');

// CORS origin validation function
export const corsOriginValidator = (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
  // Block requests with no origin for security
  if (!origin) {
    logger.warn('CORS blocked: undefined origin');
    return callback(new Error('Not allowed by CORS'));
  }

  // Parse multiple allowed origins from environment
  const allowedOrigins = env.FRONTEND_URL
    .split(',')
    .map(url => url.trim())
    .filter(Boolean);

  // Add localhost for development
  if (process.env.NODE_ENV === 'development') {
    allowedOrigins.push(
      'http://localhost:3000',
      'http://localhost:5173',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173'
    );
  }

  if (allowedOrigins.includes(origin)) {
    callback(null, true);
  } else {
    logger.warn('CORS origin rejected', { origin, allowedOrigins });
    callback(new Error('Not allowed by CORS'));
  }
};

// CORS configuration with strict security
export const corsMiddleware = cors({
  origin: corsOriginValidator,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-API-Key',
    'X-User-Agent',
    'X-Request-ID',
    'X-Correlation-ID'
  ],
  exposedHeaders: [
    'X-Request-ID',
    'X-Rate-Limit-Limit',
    'X-Rate-Limit-Remaining',
    'X-Rate-Limit-Reset',
    'X-Correlation-ID'
  ]
});

// Enhanced Helmet security headers
export const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "ws:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
});

// Enhanced compression middleware
export const compressionMiddleware = compression({
  level: 6,
  filter: (req, res) => {
    // Don't compress responses if the client doesn't support gzip
    const acceptEncoding = req.headers['accept-encoding'];
    if (!acceptEncoding || !acceptEncoding.includes('gzip')) {
      return false;
    }
    
    // Don't compress if response is too small
    const contentLength = parseInt(res.getHeader('content-length') as string);
    if (contentLength && contentLength < 1024) {
      return false;
    }
    
    // Don't compress if already compressed
    const contentType = res.getHeader('content-type') as string;
    if (contentType && (contentType.includes('image') || contentType.includes('video') || contentType.includes('audio'))) {
      return false;
    }
    
    // Don't compress JSON responses for small data sets
    if (contentType?.includes('application/json')) {
      return false;
    }
    
    return compression.filter(req, res);
  }
});

// Enhanced request logging with security focus
export const requestLogger = morgan(
  ':remote-addr - :method :url :status :res[content-length] - :response-time ms ":referrer" ":user-agent"',
  { 
    stream: morganStream,
    skip: (req) => {
      // Skip logging for health checks to reduce noise
      return (req as any).path === '/health' || (req as any).path === '/metrics';
    }
  }
);

// Security headers middleware with enhanced protection
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Remove server information
  res.removeHeader('X-Powered-By');

  // Add custom security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

  // Generate unique request ID
  const requestId = generateRequestId();
  res.setHeader('X-Request-ID', requestId);
  (req.headers as any)['x-request-id'] = requestId;

  // Add correlation ID for request tracing
  const correlationId = req.headers['x-correlation-id'] as string || generateRequestId();
  res.setHeader('X-Correlation-ID', correlationId);
  (req.headers as any)['x-correlation-id'] = correlationId;

  next();
};

// Generate unique request ID
const generateRequestId = (): string => {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
};

// Enhanced API key validation middleware
export const validateApiKey = async (req: Request, res: Response, next: NextFunction) => {
  const apiKey = req.headers['x-api-key'] as string;

  if (!apiKey) {
    return res.status(401).json({
      error: 'API key required',
      code: 'API_KEY_REQUIRED'
    });
  }

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

  try {
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

    // Check if API key has required scopes for the operation
    const requiredScopes = getRequiredScopes(req.path, req.method);
    const hasScopes = requiredScopes.every(scope => apiKeyRecord.scopes.includes(scope));

    if (!hasScopes) {
      logger.warn('API key missing required scopes', {
        apiKeyId: apiKeyRecord.id,
        requiredScopes,
        availableScopes: apiKeyRecord.scopes,
        path: req.path,
        method: req.method
      });
      return res.status(403).json({
        error: 'API key does not have required permissions',
        code: 'INSUFFICIENT_API_KEY_PERMISSIONS'
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

    logger.debug('API key validated successfully', {
      apiKeyId: apiKeyRecord.id,
      userId: user.id,
      path: req.path,
      method: req.method
    });

    next();
  } catch (error) {
    logger.error('API key validation error', { error });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};

// Get required scopes for a given path and method
const getRequiredScopes = (path: string, method: string): string[] => {
  // Define scope requirements for different endpoints
  const scopeMap: Record<string, string[]> = {
    'GET /api/workflows': ['read:workflows'],
    'POST /api/workflows': ['write:workflows'],
    'PUT /api/workflows/:id': ['write:workflows'],
    'DELETE /api/workflows/:id': ['write:workflows'],
    'POST /api/workflows/:id/execute': ['write:executions'],
    'GET /api/executions': ['read:executions'],
    'GET /api/executions/:id': ['read:executions'],
    'GET /api/executions/:id/logs': ['read:executions'],
    'POST /api/executions/:id/retry': ['write:executions'],
    'POST /api/executions/:id/cancel': ['write:executions'],
  };

  // Match path patterns
  for (const [pattern, scopes] of Object.entries(scopeMap)) {
    const [patternMethod, patternPath] = pattern.split(' ');
    if (method === patternMethod) {
      // Simple pattern matching - in production, use a proper router
      if (patternPath.includes(':id') && path.match(new RegExp(patternPath.replace(':id', '[^/]+')))) {
        return scopes;
      } else if (patternPath === path) {
        return scopes;
      }
    }
  }

  return []; // No specific scopes required
};

// Enhanced error handling middleware
export const errorHandler = (error: Error, req: Request, res: Response, next: NextFunction) => {
  const requestId = req.headers['x-request-id'] as string;
  const correlationId = req.headers['x-correlation-id'] as string;
  
  // Log error with enhanced context
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    method: req.method,
    url: req.url,
    userAgent: req.headers['user-agent'],
    requestId,
    correlationId,
    userId: (req.user as any)?.userId,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  
  // Don't expose internal errors in production
  const isDevelopment = env.NODE_ENV === 'development';
  
  // Handle specific error types
  if (error.name === 'ValidationError' || error.message.includes('validation')) {
    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: isDevelopment ? error.message : undefined,
      requestId,
      correlationId
    });
  }
  
  if (error.name === 'UnauthorizedError' || error.message.includes('Unauthorized') || error.message.includes('unauthorized')) {
    return res.status(401).json({
      error: 'Unauthorized',
      code: 'UNAUTHORIZED',
      requestId,
      correlationId
    });
  }
  
  if (error.message.includes('Forbidden') || error.message.includes('forbidden')) {
    return res.status(403).json({
      error: 'Forbidden',
      code: 'FORBIDDEN',
      requestId,
      correlationId
    });
  }
  
  if (error.message.includes('Not Found') || error.message.includes('not found')) {
    return res.status(404).json({
      error: 'Resource not found',
      code: 'NOT_FOUND',
      requestId,
      correlationId
    });
  }
  
  // Database errors
  if (error.message.includes('duplicate key') || error.message.includes('unique constraint')) {
    return res.status(409).json({
      error: 'Resource already exists',
      code: 'DUPLICATE_RESOURCE',
      requestId,
      correlationId
    });
  }
  
  // Rate limiting errors
  if (error.message.includes('Too Many Requests') || error.message.includes('rate limit')) {
    return res.status(429).json({
      error: 'Too many requests',
      code: 'RATE_LIMIT_EXCEEDED',
      requestId,
      correlationId
    });
  }
  
  // JWT errors
  if (error.name === 'JsonWebTokenError' || error.message.includes('jwt')) {
    return res.status(401).json({
      error: 'Invalid or expired token',
      code: 'INVALID_TOKEN',
      requestId,
      correlationId
    });
  }
  
  // Default error
  const statusCode = isDevelopment ? 500 : 500; // Always 500 in production for security
  
  res.status(statusCode).json({
    error: 'Internal server error',
    code: 'INTERNAL_ERROR',
    requestId,
    correlationId,
    ...(isDevelopment && { 
      details: error.message, 
      stack: error.stack 
    })
  });
};

// 404 handler with enhanced response
export const notFoundHandler = (req: Request, res: Response) => {
  const requestId = req.headers['x-request-id'] as string;
  
  logger.warn('404 Not Found', {
    method: req.method,
    url: req.url,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
    requestId,
    userId: (req.user as any)?.userId
  });
  
  res.status(404).json({
    error: `Route ${req.method} ${(req as any).path} not found`,
    code: 'NOT_FOUND',
    requestId,
    availableRoutes: [
      'POST /auth/register',
      'POST /auth/login',
      'POST /auth/refresh',
      'GET /auth/me',
      'POST /auth/logout',
      'GET /workflows',
      'POST /workflows',
      'GET /workflows/:id',
      'PUT /workflows/:id',
      'DELETE /workflows/:id',
      'POST /workflows/:id/execute',
      'GET /executions',
      'GET /executions/:id',
      'GET /executions/:id/logs',
      'POST /executions/:id/retry',
      'GET /health'
    ]
  });
};