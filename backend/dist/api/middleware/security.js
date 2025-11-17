"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.notFoundHandler = exports.errorHandler = exports.validateApiKey = exports.securityHeaders = exports.requestLogger = exports.compressionMiddleware = exports.helmetMiddleware = exports.corsMiddleware = exports.generalRateLimiter = exports.authRateLimiter = exports.createRateLimiter = void 0;
const express_rate_limit_1 = __importDefault(require("express-rate-limit"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const compression_1 = __importDefault(require("compression"));
const morgan_1 = __importDefault(require("morgan"));
const environment_1 = require("@/config/environment");
const logger_1 = require("@/utils/logger");
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
exports.authRateLimiter = (0, exports.createRateLimiter)({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per 15 minutes
    message: {
        error: 'Too many authentication attempts, please try again later.',
        code: 'AUTH_RATE_LIMIT_EXCEEDED',
        retryAfter: 15 * 60
    }
});
// General rate limiting
exports.generalRateLimiter = (0, exports.createRateLimiter)();
// CORS configuration
exports.corsMiddleware = (0, cors_1.default)({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin)
            return callback(null, true);
        const allowedOrigins = [
            environment_1.env.FRONTEND_URL,
            'http://localhost:3000',
            'http://localhost:5173',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:5173'
        ];
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        }
        else {
            callback(new Error('Not allowed by CORS'));
        }
    },
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
        'X-Request-ID'
    ],
    exposedHeaders: [
        'X-Request-ID',
        'X-Rate-Limit-Limit',
        'X-Rate-Limit-Remaining',
        'X-Rate-Limit-Reset'
    ]
});
// Helmet security headers
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
        },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
});
// Compression middleware
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
        if (contentType && (contentType.includes('image') || contentType.includes('video'))) {
            return false;
        }
        return compression_1.default.filter(req, res);
    }
});
// Request logging
exports.requestLogger = (0, morgan_1.default)(':method :url :status :res[content-length] - :response-time ms', { stream: logger_1.morganStream });
// Security headers middleware
const securityHeaders = (req, res, next) => {
    // Remove server information
    res.removeHeader('X-Powered-By');
    // Add custom security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Generate unique request ID
    const requestId = generateRequestId();
    res.setHeader('X-Request-ID', requestId);
    req.headers['x-request-id'] = requestId;
    next();
};
exports.securityHeaders = securityHeaders;
// Generate unique request ID
const generateRequestId = () => {
    return Math.random().toString(36).substring(2, 15) +
        Math.random().toString(36).substring(2, 15);
};
// API key validation middleware
const validateApiKey = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({
            error: 'API key required',
            code: 'API_KEY_REQUIRED'
        });
    }
    // API key validation will be implemented in the service layer
    // For now, we'll just continue
    next();
};
exports.validateApiKey = validateApiKey;
// Error handling middleware
const errorHandler = (error, req, res, next) => {
    logger_1.logger.error('Unhandled error', {
        error: error.message,
        stack: error.stack,
        method: req.method,
        url: req.url,
        userAgent: req.headers['user-agent'],
        requestId: req.headers['x-request-id']
    });
    // Don't expose internal errors in production
    const isDevelopment = environment_1.env.NODE_ENV === 'development';
    if (error.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation failed',
            code: 'VALIDATION_ERROR',
            details: isDevelopment ? error.message : undefined
        });
    }
    if (error.name === 'UnauthorizedError' || error.message.includes('Unauthorized')) {
        return res.status(401).json({
            error: 'Unauthorized',
            code: 'UNAUTHORIZED'
        });
    }
    if (error.message.includes('Forbidden')) {
        return res.status(403).json({
            error: 'Forbidden',
            code: 'FORBIDDEN'
        });
    }
    if (error.message.includes('Not Found')) {
        return res.status(404).json({
            error: 'Resource not found',
            code: 'NOT_FOUND'
        });
    }
    // Database errors
    if (error.message.includes('duplicate key')) {
        return res.status(409).json({
            error: 'Resource already exists',
            code: 'DUPLICATE_RESOURCE'
        });
    }
    // Rate limiting errors
    if (error.message.includes('Too Many Requests')) {
        return res.status(429).json({
            error: 'Too many requests',
            code: 'RATE_LIMIT_EXCEEDED'
        });
    }
    // Default error
    res.status(500).json({
        error: 'Internal server error',
        code: 'INTERNAL_ERROR',
        requestId: req.headers['x-request-id'],
        ...(isDevelopment && { details: error.message, stack: error.stack })
    });
};
exports.errorHandler = errorHandler;
// 404 handler
const notFoundHandler = (req, res) => {
    res.status(404).json({
        error: `Route ${req.method} ${req.path} not found`,
        code: 'NOT_FOUND',
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