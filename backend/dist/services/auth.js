"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authService = exports.AuthService = exports.RefreshTokenSchema = exports.LoginSchema = exports.RegisterSchema = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const uuid_1 = require("uuid");
const connection_1 = require("@/database/connection");
const logger_1 = require("@/utils/logger");
const environment_1 = require("@/config/environment");
const redis_cache_1 = require("@/utils/redis-cache");
const security_1 = require("@/utils/security");
// Enhanced schemas with strong security validation
exports.RegisterSchema = security_1.EnhancedRegisterSchema;
exports.LoginSchema = security_1.EnhancedLoginSchema;
exports.RefreshTokenSchema = security_1.EnhancedRefreshTokenSchema;
class AuthService {
    JWT_SECRET = environment_1.jwtConfig.secret;
    ACCESS_EXPIRES_IN = environment_1.jwtConfig.accessExpiresIn;
    REFRESH_EXPIRES_IN = environment_1.jwtConfig.refreshExpiresIn;
    async register(data) {
        try {
            // Enhanced input sanitization
            const sanitizedData = {
                email: (0, security_1.sanitizeString)(data.email.toLowerCase(), 254),
                password: data.password, // Don't sanitize password, validate it
                firstName: (0, security_1.sanitizeString)(data.firstName, 50),
                lastName: (0, security_1.sanitizeString)(data.lastName, 50),
            };
            // Validate with enhanced schemas
            const validatedData = exports.RegisterSchema.parse(sanitizedData);
            // Check if user already exists (case-insensitive)
            const existingUser = await connection_1.db
                .selectFrom('users')
                .select('id')
                .where('email', '=', validatedData.email)
                .executeTakeFirst();
            if (existingUser) {
                throw new Error('User with this email already exists');
            }
            // Enhanced password hashing with higher cost factor
            const passwordHash = await bcrypt_1.default.hash(validatedData.password, 12);
            // Create user with additional security fields
            const userId = (0, uuid_1.v4)();
            const now = new Date();
            await connection_1.db
                .insertInto('users')
                .values({
                id: userId,
                email: validatedData.email,
                password_hash: passwordHash,
                first_name: validatedData.firstName,
                last_name: validatedData.lastName,
                role: 'user',
                is_active: true,
                email_verified: false,
                failed_login_attempts: 0,
                last_failed_login_at: undefined,
                token_version: 1, // Track token versions for invalidation
                created_at: now,
                updated_at: now,
            })
                .execute();
            // Generate tokens with version tracking
            const tokens = await this.generateTokens(userId, validatedData.email, 'user', 1);
            logger_1.logger.info('User registered successfully', {
                userId,
                email: validatedData.email,
                ip: 'redacted', // Don't log IP for privacy
                userAgent: 'redacted'
            });
            return {
                user: {
                    id: userId,
                    email: validatedData.email,
                    firstName: validatedData.firstName,
                    lastName: validatedData.lastName,
                    role: 'user',
                },
                tokens,
            };
        }
        catch (error) {
            // Sanitize error logging
            const sanitizedEmail = (0, security_1.sanitizeString)(data.email, 10);
            logger_1.logger.error('Registration failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                email: sanitizedEmail
            });
            throw error;
        }
    }
    async login(data) {
        try {
            // Input sanitization
            const sanitizedEmail = (0, security_1.sanitizeString)(data.email.toLowerCase(), 254);
            const validatedData = exports.LoginSchema.parse({
                email: sanitizedEmail,
                password: data.password,
            });
            // Rate limiting check - implement basic rate limiting here
            await this.checkLoginRateLimit(validatedData.email);
            // Find user by email with security checks
            const user = await connection_1.db
                .selectFrom('users')
                .selectAll()
                .where('email', '=', validatedData.email)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                // Log failed attempt even for non-existent users
                await this.recordFailedLoginAttempt(null, validatedData.email);
                throw new Error('Invalid email or password');
            }
            // Check if account is locked
            if (await this.isAccountLocked(user.id)) {
                await this.recordFailedLoginAttempt(user.id, validatedData.email);
                throw new Error('Account is temporarily locked due to too many failed attempts');
            }
            // Verify password
            const isValidPassword = await bcrypt_1.default.compare(validatedData.password, user.password_hash);
            if (!isValidPassword) {
                await this.recordFailedLoginAttempt(user.id, validatedData.email);
                throw new Error('Invalid email or password');
            }
            // Reset failed login attempts on successful login
            await this.resetFailedLoginAttempts(user.id);
            // Update last login
            await connection_1.db
                .updateTable('users')
                .set({
                last_login_at: new Date(),
                updated_at: new Date(),
            })
                .where('id', '=', user.id)
                .execute();
            // Generate tokens with current token version
            const tokens = await this.generateTokens(user.id, user.email, user.role, user.token_version || 1);
            logger_1.logger.info('User logged in successfully', {
                userId: user.id,
                email: user.email,
                tokenVersion: user.token_version
            });
            return {
                user: {
                    id: user.id,
                    email: user.email,
                    firstName: user.first_name,
                    lastName: user.last_name,
                    role: user.role,
                },
                tokens,
            };
        }
        catch (error) {
            const sanitizedEmail = (0, security_1.sanitizeString)(data.email, 10);
            logger_1.logger.error('Login failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                email: sanitizedEmail
            });
            throw error;
        }
    }
    async refreshToken(refreshToken) {
        try {
            // Validate refresh token format first
            security_1.EnhancedRefreshTokenSchema.parse({ refreshToken });
            // Verify refresh token
            const payload = jsonwebtoken_1.default.verify(refreshToken, this.JWT_SECRET);
            // Check if refresh token exists and is not used
            const tokenHash = await (0, security_1.hashApiKey)(refreshToken);
            const storedToken = await connection_1.db
                .selectFrom('refresh_tokens')
                .selectAll()
                .where('token_hash', '=', tokenHash)
                .where('is_used', '=', false)
                .where('expires_at', '>', new Date())
                .executeTakeFirst();
            if (!storedToken) {
                throw new Error('Refresh token not found or already used');
            }
            // Check if user still exists and is active
            const user = await connection_1.db
                .selectFrom('users')
                .selectAll()
                .where('id', '=', payload.userId)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                throw new Error('User not found or inactive');
            }
            // Verify token version hasn't been invalidated
            if ((user.token_version || 1) !== payload.version) {
                throw new Error('Token has been invalidated');
            }
            // Mark old refresh token as used
            await connection_1.db
                .updateTable('refresh_tokens')
                .set({
                is_used: true,
                used_at: new Date(),
            })
                .where('id', '=', storedToken.id)
                .execute();
            // Generate new tokens with same version
            const tokens = await this.generateTokens(user.id, user.email, user.role, user.token_version || 1);
            logger_1.logger.info('Tokens refreshed successfully', {
                userId: user.id,
                tokenVersion: user.token_version
            });
            return tokens;
        }
        catch (error) {
            logger_1.logger.error('Token refresh failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                refreshToken: refreshToken.substring(0, 20) + '...'
            });
            throw new Error('Invalid refresh token');
        }
    }
    async getUserById(userId) {
        try {
            // Validate UUID format
            security_1.UUIDSchema.parse(userId);
            // Try cache first
            const cachedUser = await redis_cache_1.cacheService.get(`user:profile:${userId}`);
            if (cachedUser) {
                return cachedUser;
            }
            // Cache miss, fetch from database
            const user = await connection_1.db
                .selectFrom('users')
                .selectAll()
                .where('id', '=', userId)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                throw new Error('User not found');
            }
            const userData = {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                role: user.role,
                createdAt: user.created_at,
                lastLoginAt: user.last_login_at,
                emailVerified: user.email_verified,
            };
            // Cache for 1 minute
            await redis_cache_1.cacheService.set(`user:profile:${userId}`, userData, 60);
            return userData;
        }
        catch (error) {
            logger_1.logger.error('Failed to get user by ID', { error, userId: (0, security_1.sanitizeString)(userId, 10) });
            throw error;
        }
    }
    async verifyToken(token) {
        try {
            const payload = jsonwebtoken_1.default.verify(token, this.JWT_SECRET);
            // Verify user still exists and is active
            const user = await connection_1.db
                .selectFrom('users')
                .select(['id', 'is_active', 'token_version'])
                .where('id', '=', payload.userId)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                return null;
            }
            // Verify token version
            if ((user.token_version || 1) !== payload.version) {
                return null;
            }
            return payload;
        }
        catch (error) {
            logger_1.logger.debug('Token verification failed', { error: error instanceof Error ? error.message : 'Unknown error' });
            return null;
        }
    }
    // Invalidate all tokens for a user (for security breaches)
    async invalidateUserTokens(userId) {
        try {
            await connection_1.db
                .updateTable('users')
                .set({
                token_version: (userId) => userId.token_version + 1,
                updated_at: new Date()
            })
                .where('id', '=', userId)
                .execute();
            logger_1.logger.info('User tokens invalidated', { userId });
        }
        catch (error) {
            logger_1.logger.error('Failed to invalidate user tokens', { error, userId });
            throw error;
        }
    }
    async generateTokens(userId, email, role, version) {
        const tokenId = (0, uuid_1.v4)();
        const payload = {
            userId,
            email,
            role,
            tokenId,
            version,
        };
        const accessToken = jsonwebtoken_1.default.sign(payload, this.JWT_SECRET, {
            expiresIn: this.ACCESS_EXPIRES_IN,
        });
        const refreshToken = jsonwebtoken_1.default.sign(payload, this.JWT_SECRET, {
            expiresIn: this.REFRESH_EXPIRES_IN,
        });
        // Store refresh token hash for rotation
        const tokenHash = await (0, security_1.hashApiKey)(refreshToken);
        const expiresAt = new Date(Date.now() + this.getExpirationTime(this.REFRESH_EXPIRES_IN) * 1000);
        await connection_1.db
            .insertInto('refresh_tokens')
            .values({
            id: (0, uuid_1.v4)(),
            user_id: userId,
            token_hash: tokenHash,
            token_id: tokenId,
            is_used: false,
            expires_at: expiresAt,
            created_at: new Date(),
        })
            .execute();
        return {
            accessToken,
            refreshToken,
            expiresIn: this.getExpirationTime(this.ACCESS_EXPIRES_IN),
        };
    }
    getExpirationTime(expiresIn) {
        const value = parseInt(expiresIn.replace(/[a-zA-Z]/g, ''));
        const unit = expiresIn.replace(/[0-9]/g, '').toLowerCase();
        switch (unit) {
            case 's':
                return value;
            case 'm':
                return value * 60;
            case 'h':
                return value * 60 * 60;
            case 'd':
                return value * 24 * 60 * 60;
            default:
                return 15 * 60; // Default to 15 minutes
        }
    }
    async logout(userId, tokenId) {
        try {
            // For now, we'll just log the logout
            // In a production system, you might want to maintain a token blacklist
            logger_1.logger.info('User logged out', { userId, tokenId: (0, security_1.sanitizeString)(tokenId, 10) });
            return true;
        }
        catch (error) {
            logger_1.logger.error('Logout failed', { error, userId });
            throw error;
        }
    }
    // Security methods for login protection
    async checkLoginRateLimit(email) {
        // Basic rate limiting - in production, use Redis
        const windowMs = 15 * 60 * 1000; // 15 minutes
        const maxAttempts = 5;
        // This would typically check Redis or a database table
        // For now, we'll implement a basic check
        // TODO: Implement proper Redis-based rate limiting
    }
    async recordFailedLoginAttempt(userId, email) {
        try {
            if (userId) {
                await connection_1.db
                    .updateTable('users')
                    .set({
                    failed_login_attempts: (userId) => userId.failed_login_attempts + 1,
                    last_failed_login_at: new Date(),
                    updated_at: new Date()
                })
                    .where('id', '=', userId)
                    .execute();
            }
            logger_1.logger.warn('Failed login attempt', {
                userId,
                email: (0, security_1.sanitizeString)(email, 10)
            });
        }
        catch (error) {
            logger_1.logger.error('Failed to record login attempt', { error });
        }
    }
    async resetFailedLoginAttempts(userId) {
        try {
            await connection_1.db
                .updateTable('users')
                .set({
                failed_login_attempts: 0,
                last_failed_login_at: undefined,
                updated_at: new Date()
            })
                .where('id', '=', userId)
                .execute();
        }
        catch (error) {
            logger_1.logger.error('Failed to reset login attempts', { error, userId });
        }
    }
    async isAccountLocked(userId) {
        try {
            const user = await connection_1.db
                .selectFrom('users')
                .select(['failed_login_attempts', 'last_failed_login_at'])
                .where('id', '=', userId)
                .executeTakeFirst();
            if (!user)
                return false;
            const maxAttempts = 5;
            const lockoutDuration = 30 * 60 * 1000; // 30 minutes
            const now = new Date();
            if (user.failed_login_attempts >= maxAttempts) {
                const lastFailed = user.last_failed_login_at ? new Date(user.last_failed_login_at) : null;
                if (lastFailed && (now.getTime() - lastFailed.getTime()) < lockoutDuration) {
                    return true; // Account is locked
                }
                else {
                    // Lockout period expired, reset attempts
                    await this.resetFailedLoginAttempts(userId);
                    return false;
                }
            }
            return false;
        }
        catch (error) {
            logger_1.logger.error('Failed to check account lock status', { error, userId });
            return false; // Don't lock account on error
        }
    }
}
exports.AuthService = AuthService;
exports.authService = new AuthService();
//# sourceMappingURL=auth.js.map