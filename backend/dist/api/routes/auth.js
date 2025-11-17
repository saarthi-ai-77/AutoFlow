"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.authRoutes = void 0;
const express_1 = require("express");
const auth_1 = require("@/services/auth");
const zod_1 = require("zod");
const logger_1 = require("@/utils/logger");
const router = (0, express_1.Router)();
exports.authRoutes = router;
// Register endpoint
router.post('/register', async (req, res) => {
    try {
        const validatedData = auth_1.RegisterSchema.parse(req.body);
        const result = await auth_1.authService.register({
            email: validatedData.email,
            password: validatedData.password,
            firstName: validatedData.firstName,
            lastName: validatedData.lastName,
        });
        res.status(201).json({
            message: 'User registered successfully',
            data: result,
        });
        logger_1.logger.info('User registration successful', {
            userId: result.user.id,
            email: result.user.email
        });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.errors,
            });
        }
        if (error instanceof Error && error.message.includes('already exists')) {
            return res.status(409).json({
                error: error.message,
                code: 'USER_EXISTS',
            });
        }
        logger_1.logger.error('Registration failed', { error, body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Login endpoint
router.post('/login', async (req, res) => {
    try {
        const validatedData = auth_1.LoginSchema.parse(req.body);
        const result = await auth_1.authService.login({
            email: validatedData.email,
            password: validatedData.password,
        });
        // Set refresh token as httpOnly cookie
        res.cookie('refreshToken', result.tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        // Return only access token in response
        res.json({
            message: 'Login successful',
            data: {
                user: result.user,
                accessToken: result.tokens.accessToken,
                expiresIn: result.tokens.expiresIn,
            },
        });
        logger_1.logger.info('User login successful', {
            userId: result.user.id,
            email: result.user.email
        });
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.errors,
            });
        }
        if (error instanceof Error && (error.message.includes('Invalid') || error.message.includes('not found'))) {
            return res.status(401).json({
                error: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS',
            });
        }
        logger_1.logger.error('Login failed', { error, body: req.body });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Refresh token endpoint
router.post('/refresh', async (req, res) => {
    try {
        // Get refresh token from cookie or body
        const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
        if (!refreshToken) {
            return res.status(401).json({
                error: 'Refresh token required',
                code: 'REFRESH_TOKEN_REQUIRED',
            });
        }
        const tokens = await auth_1.authService.refreshToken(refreshToken);
        // Set new refresh token as httpOnly cookie
        res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        // Return only access token in response
        res.json({
            message: 'Token refreshed successfully',
            data: {
                accessToken: tokens.accessToken,
                expiresIn: tokens.expiresIn,
            },
        });
        logger_1.logger.info('Token refresh successful');
    }
    catch (error) {
        if (error instanceof zod_1.z.ZodError) {
            return res.status(400).json({
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.errors,
            });
        }
        logger_1.logger.error('Token refresh failed', { error, body: req.body });
        res.status(401).json({
            error: 'Invalid refresh token',
            code: 'INVALID_REFRESH_TOKEN',
        });
    }
});
// Get current user
router.get('/me', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                error: 'Access token required',
                code: 'UNAUTHORIZED',
            });
        }
        const token = authHeader.substring(7);
        const payload = await auth_1.authService.verifyToken(token);
        if (!payload) {
            return res.status(401).json({
                error: 'Invalid or expired token',
                code: 'TOKEN_INVALID',
            });
        }
        const user = await auth_1.authService.getUserById(payload.userId);
        res.json({
            message: 'User retrieved successfully',
            data: { user },
        });
        logger_1.logger.debug('User profile retrieved', { userId: user.id });
    }
    catch (error) {
        logger_1.logger.error('Get user profile failed', { error, headers: req.headers });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
// Logout endpoint
router.post('/logout', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        const refreshToken = req.cookies.refreshToken;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const payload = await auth_1.authService.verifyToken(token);
            if (payload) {
                await auth_1.authService.logout(payload.userId, payload.tokenId);
            }
        }
        // Clear refresh token cookie
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
        });
        res.json({
            message: 'Logout successful',
        });
        logger_1.logger.info('User logout successful');
    }
    catch (error) {
        logger_1.logger.error('Logout failed', { error });
        res.status(500).json({
            error: 'Internal server error',
            code: 'INTERNAL_ERROR',
        });
    }
});
//# sourceMappingURL=auth.js.map