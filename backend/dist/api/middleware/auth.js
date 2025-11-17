"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.requireApiKey = exports.optionalAuth = exports.requireOwnership = exports.requireRole = exports.authenticate = void 0;
const auth_1 = require("@/services/auth");
const logger_1 = require("@/utils/logger");
const authenticate = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Access token required',
                code: 'UNAUTHORIZED'
            });
        }
        const token = authHeader.substring(7); // Remove 'Bearer ' prefix
        const payload = await auth_1.authService.verifyToken(token);
        if (!payload) {
            return res.status(401).json({
                error: 'Invalid or expired token',
                code: 'TOKEN_INVALID'
            });
        }
        req.user = payload;
        next();
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