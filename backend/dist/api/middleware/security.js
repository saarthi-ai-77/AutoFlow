"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.notFoundHandler = exports.errorHandler = exports.validateApiKey = exports.securityHeaders = exports.requestLogger = exports.compressionMiddleware = exports.helmetMiddleware = exports.corsMiddleware = exports.corsOriginValidator = exports.searchRateLimiter = exports.workflowRateLimiter = exports.executionRateLimiter = exports.generalRateLimiter = exports.authRateLimiter = exports.createRateLimiter = exports.createTieredRateLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const compression_1 = __importDefault(require("compression"));
const morgan_1 = __importDefault(require("morgan"));
const environment_1 = require("@/config/environment");
const logger_1 = require("@/utils/logger");
const security_1 = require("@/utils/security");
const connection_1 = require("@/database/connection");
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
const createTieredRateLimiter = (tier, customKeyGenerator) => {
    const config = RATE_LIMIT_TIERS[tier];
    return (0, express_rate_limit_1.default)({
        ...config,
        skip: (req) => {
            // Skip rate limiting for health checks and internal monitoring
            if (req.path === '/health' || req.path === '/metrics' || req.path.startsWith('/api/health')) {
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
            const userId = req.user?.userId;
            if (userId) {
                return `user:${userId}`;
            }
            // Fallback to IP address
            const ip = req.ip || req.connection.remoteAddress || 'unknown';
            return `ip:${ip}`;
        },
        handler: (req, res) => {
            const key = req.ip || 'unknown';
            logger_1.logger.warn('Rate limit exceeded', {
                tier,
                key: security_1.RateLimitKeySchema.safeParse(key).success ? key : 'invalid',
                userAgent: req.get('User-Agent'),
                path: req.path,
                method: req.method,
                userId: req.user?.userId
            });
            res.status(429).json(config.message);
        },
        onLimitReached: (req, res, optionsUsed) => {
            logger_1.logger.warn('Rate limit reached', {
                tier,
                key: req.ip,
                path: req.path,
                method: req.method,
                userId: req.user?.userId,
                userAgent: req.get('User-Agent')
            });
        }
    });
};
exports.createTieredRateLimiter = createTieredRateLimiter;
// Rate limiting configuration
const createRateLimiter = (options) => {
    const config = { ...environment_1.rateLimitConfig, ...options };
    return (0, express_rate_limit_1.default)({
        windowMs: config.windowMs,
        limit: config.maxRequests,
        message: {
            error: 'Too many requests from this IP, please try again later.',
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: Math.ceil(config.windowMs / 1000)
        },
        standardHeaders: true,
        legacyHeaders: false,
        skip: (req) => {
            // Skip rate limiting for health checks
            return req.path === '/health';
        },
        keyGenerator: (req) => {
            // Use user ID if authenticated, otherwise IP
            return req.user?.userId || req.ip;
        }
    });
};
exports.createRateLimiter = createRateLimiter;
// More strict rate limiting for auth endpoints
exports.authRateLimiter = (0, exports.createTieredRateLimiter)('AUTH');
// General rate limiting
exports.generalRateLimiter = (0, exports.createTieredRateLimiter)('GENERAL');
// Execution rate limiting
exports.executionRateLimiter = (0, exports.createTieredRateLimiter)('EXECUTION');
// Workflow rate limiting
exports.workflowRateLimiter = (0, exports.createTieredRateLimiter)('WORKFLOW');
// Search rate limiting
exports.searchRateLimiter = (0, exports.createTieredRateLimiter)('SEARCH');
// CORS origin validation function
const corsOriginValidator = (origin, callback) => {
    // Block requests with no origin for security
    if (!origin) {
        logger_1.logger.warn('CORS blocked: undefined origin');
        return callback(new Error('Not allowed by CORS'));
    }
    // Parse multiple allowed origins from environment
    const allowedOrigins = environment_1.env.FRONTEND_URL
        .split(',')
        .map(url => url.trim())
        .filter(Boolean);
    // Add localhost for development
    if (process.env.NODE_ENV === 'development') {
        allowedOrigins.push('http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000', 'http://127.0.0.1:5173');
    }
    if (allowedOrigins.includes(origin)) {
        callback(null, true);
    }
    else {
        logger_1.logger.warn('CORS origin rejected', { origin, allowedOrigins });
        callback(new Error('Not allowed by CORS'));
    }
};
exports.corsOriginValidator = corsOriginValidator;
// CORS configuration with strict security
exports.corsMiddleware = (0, cors_1.default)({
    origin: exports.corsOriginValidator,
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
exports.helmetMiddleware = (0, helmet_1.default)({
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
exports.compressionMiddleware = (0, compression_1.default)({
    level: 6,
    filter: (req, res) => {
        // Don't compress responses if the client doesn't support gzip
        const acceptEncoding = req.headers['accept-encoding'];
        if (!acceptEncoding || !acceptEncoding.includes('gzip')) {
            return false;
        }
        // Don't compress if response is too small
        const contentLength = parseInt(res.getHeader('content-length'));
        if (contentLength && contentLength < 1024) {
            return false;
        }
        // Don't compress if already compressed
        const contentType = res.getHeader('content-type');
        if (contentType && (contentType.includes('image') || contentType.includes('video') || contentType.includes('audio'))) {
            return false;
        }
        // Don't compress JSON responses for small data sets
        if (contentType?.includes('application/json')) {
            return false;
        }
        return compression_1.default.filter(req, res);
    }
});
// Enhanced request logging with security focus
exports.requestLogger = (0, morgan_1.default)(':remote-addr - :method :url :status :res[content-length] - :response-time ms ":referrer" ":user-agent"', {
    stream: logger_1.morganStream,
    skip: (req) => {
        // Skip logging for health checks to reduce noise
        return req.path === '/health' || req.path === '/metrics';
    }
});
// Security headers middleware with enhanced protection
const securityHeaders = (req, res, next) => {
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
    req.headers['x-request-id'] = requestId;
    // Add correlation ID for request tracing
    const correlationId = req.headers['x-correlation-id'] || generateRequestId();
    res.setHeader('X-Correlation-ID', correlationId);
    req.headers['x-correlation-id'] = correlationId;
    next();
};
exports.securityHeaders = securityHeaders;
// Generate unique request ID
const generateRequestId = () => {
    return Math.random().toString(36).substring(2, 15) +
        Math.random().toString(36).substring(2, 15);
};
// Enhanced API key validation middleware
const validateApiKey = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({
            error: 'API key required',
            code: 'API_KEY_REQUIRED'
        });
    }
    // Validate API key format
    const isValidFormat = /^[a-zA-Z0-9\-_.]+$/.test(apiKey);
    if (!isValidFormat) {
        logger_1.logger.warn('Invalid API key format', {
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
        const keyHash = await (0, security_1.hashApiKey)(apiKey);
        const apiKeyRecord = await connection_1.db
            .selectFrom('api_keys')
            .selectAll()
            .where('key_hash', '=', keyHash)
            .where('is_active', '=', true)
            .where('expires_at', '>', new Date())
            .executeTakeFirst();
        if (!apiKeyRecord) {
            logger_1.logger.warn('Invalid API key', {
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
        const user = await connection_1.db
            .selectFrom('users')
            .select(['id', 'email', 'role', 'is_active'])
            .where('id', '=', apiKeyRecord.user_id)
            .where('is_active', '=', true)
            .executeTakeFirst();
        if (!user) {
            logger_1.logger.warn('API key user not found or inactive', {
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
            logger_1.logger.warn('API key missing required scopes', {
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
        req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            apiKeyId: apiKeyRecord.id,
            scopes: apiKeyRecord.scopes,
        };
        // Update last used timestamp
        await connection_1.db
            .updateTable('api_keys')
            .set({ last_used_at: new Date() })
            .where('id', '=', apiKeyRecord.id)
            .execute();
        logger_1.logger.debug('API key validated successfully', {
            apiKeyId: apiKeyRecord.id,
            userId: user.id,
            path: req.path,
            method: req.method
        });
        next();
    }
    catch (error) {
        logger_1.logger.error('API key validation error', { error });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR'
        });
    }
};
exports.validateApiKey = validateApiKey;
// Get required scopes for a given path and method
const getRequiredScopes = (path, method) => {
    // Define scope requirements for different endpoints
    const scopeMap = {
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
            }
            else if (patternPath === path) {
                return scopes;
            }
        }
    }
    return []; // No specific scopes required
};
// Enhanced error handling middleware
const errorHandler = (error, req, res, next) => {
    const requestId = req.headers['x-request-id'];
    const correlationId = req.headers['x-correlation-id'];
    // Log error with enhanced context
    logger_1.logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent'],
        requestId,
        correlationId,
        userId: req.user?.userId,
        ip: req.ip,
        timestamp: new Date().toISOString()
    });
    // Don't expose internal errors in production
    const isDevelopment = environment_1.env.NODE_ENV === 'development';
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
exports.errorHandler = errorHandler;
// 404 handler with enhanced response
const notFoundHandler = (req, res) => {
    const requestId = req.headers['x-request-id'];
    logger_1.logger.warn('404 Not Found', {
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent'],
        ip: req.ip,
        requestId,
        userId: req.user?.userId
    });
    res.status(404).json({
        error: `Route ${req.method} ${req.path} not found`,
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
exports.notFoundHandler = notFoundHandler;
//# sourceMappingURL=security.js.map