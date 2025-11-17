"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireApiKey = exports.optionalAuth = exports.requireOwnership = exports.requireRole = exports.authenticate = void 0;
const auth_1 = require("@/services/auth");
const logger_1 = require("@/utils/logger");
const security_1 = require("@/utils/security");
const connection_1 = require("@/database/connection");
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        const apiKey = req.headers['x-api-key'];
        // Try JWT authentication first
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7); // Remove 'Bearer ' prefix
            const payload = await auth_1.authService.verifyToken(token);
            if (payload) {
                req.user = payload;
                return next();
            }
        }
        // If JWT failed or not provided, try API key authentication
        if (apiKey) {
            try {
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
                logger_1.logger.debug('API key authenticated successfully', {
                    apiKeyId: apiKeyRecord.id,
                    userId: user.id,
                    path: req.path,
                    method: req.method
                });
                return next();
            }
            catch (error) {
                logger_1.logger.error('API key authentication error', { error });
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
    }
    catch (error) {
        logger_1.logger.error('Authentication error', { error });
        return res.status(401).json({
            error: 'Authentication failed',
            code: 'AUTH_ERROR'
        });
    }
};
exports.authenticate = authenticate;
const requireRole = (roles) => {
    return (req, res, next) => {
        const user = req.user;
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
exports.requireRole = requireRole;
const requireOwnership = (resourceUserIdField = 'owner_id') => {
    return async (req, res, next) => {
        try {
            const user = req.user;
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
        }
        catch (error) {
            logger_1.logger.error('Ownership check error', { error });
            return res.status(500).json({
                error: 'Permission check failed',
                code: 'PERMISSION_ERROR'
            });
        }
    };
};
exports.requireOwnership = requireOwnership;
const optionalAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const payload = await auth_1.authService.verifyToken(token);
            if (payload) {
                req.user = payload;
            }
        }
        next();
    }
    catch (error) {
        // For optional auth, we don't fail on invalid tokens
        logger_1.logger.debug('Optional auth failed', { error });
        next();
    }
};
exports.optionalAuth = optionalAuth;
const requireApiKey = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey) {
            return res.status(401).json({
                error: 'API key required',
                code: 'API_KEY_REQUIRED'
            });
        }
        // API key validation will be implemented here
        // For now, we'll just continue
        next();
    }
    catch (error) {
        logger_1.logger.error('API key validation error', { error });
        return res.status(401).json({
            error: 'Invalid API key',
            code: 'API_KEY_INVALID'
        });
    }
};
exports.requireApiKey = requireApiKey;
//# sourceMappingURL=auth.js.map