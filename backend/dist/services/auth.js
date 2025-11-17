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
const zod_1 = require("zod");
// User schemas for validation
exports.RegisterSchema = zod_1.z.object({
    email: zod_1.z.string().email('Invalid email format'),
    password: zod_1.z.string().min(8, 'Password must be at least 8 characters'),
    firstName: zod_1.z.string().min(1, 'First name is required'),
    lastName: zod_1.z.string().min(1, 'Last name is required'),
});
exports.LoginSchema = zod_1.z.object({
    email: zod_1.z.string().email('Invalid email format'),
    password: zod_1.z.string().min(1, 'Password is required'),
});
exports.RefreshTokenSchema = zod_1.z.object({
    refreshToken: zod_1.z.string().min(1, 'Refresh token is required'),
});
class AuthService {
    JWT_SECRET = environment_1.jwtConfig.secret;
    ACCESS_EXPIRES_IN = environment_1.jwtConfig.accessExpiresIn;
    REFRESH_EXPIRES_IN = environment_1.jwtConfig.refreshExpiresIn;
    async register(data) {
        try {
            // Check if user already exists
            const existingUser = await connection_1.db
                .selectFrom('users')
                .select('id')
                .where('email', '=', data.email)
                .executeTakeFirst();
            if (existingUser) {
                throw new Error('User with this email already exists');
            }
            // Hash password
            const passwordHash = await bcrypt_1.default.hash(data.password, 12);
            // Create user
            const userId = (0, uuid_1.v4)();
            await connection_1.db
                .insertInto('users')
                .values({
                id: userId,
                email: data.email,
                password_hash: passwordHash,
                first_name: data.firstName,
                last_name: data.lastName,
                role: 'user',
                is_active: true,
            })
                .execute();
            // Generate tokens
            const tokens = await this.generateTokens(userId, data.email, 'user');
            logger_1.logger.info('User registered successfully', { userId, email: data.email });
            return {
                user: {
                    id: userId,
                    email: data.email,
                    firstName: data.firstName,
                    lastName: data.lastName,
                    role: 'user',
                },
                tokens,
            };
        }
        catch (error) {
            logger_1.logger.error('Registration failed', { error, email: data.email });
            throw error;
        }
    }
    async login(data) {
        try {
            // Find user by email
            const user = await connection_1.db
                .selectFrom('users')
                .selectAll()
                .where('email', '=', data.email)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                throw new Error('Invalid email or password');
            }
            // Verify password
            const isValidPassword = await bcrypt_1.default.compare(data.password, user.password_hash);
            if (!isValidPassword) {
                throw new Error('Invalid email or password');
            }
            // Update last login
            await connection_1.db
                .updateTable('users')
                .set({ last_login_at: new Date() })
                .where('id', '=', user.id)
                .execute();
            // Generate tokens
            const tokens = await this.generateTokens(user.id, user.email, user.role);
            logger_1.logger.info('User logged in successfully', { userId: user.id, email: user.email });
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
            logger_1.logger.error('Login failed', { error, email: data.email });
            throw error;
        }
    }
    async refreshToken(refreshToken) {
        try {
            // Verify refresh token
            const payload = jsonwebtoken_1.default.verify(refreshToken, this.JWT_SECRET);
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
            // Generate new tokens
            const tokens = await this.generateTokens(user.id, user.email, user.role);
            logger_1.logger.info('Tokens refreshed successfully', { userId: user.id });
            return tokens;
        }
        catch (error) {
            logger_1.logger.error('Token refresh failed', { error, refreshToken: refreshToken.substring(0, 20) + '...' });
            throw new Error('Invalid refresh token');
        }
    }
    async getUserById(userId) {
        try {
            const user = await connection_1.db
                .selectFrom('users')
                .selectAll()
                .where('id', '=', userId)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                throw new Error('User not found');
            }
            return {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                role: user.role,
                createdAt: user.created_at,
                lastLoginAt: user.last_login_at,
            };
        }
        catch (error) {
            logger_1.logger.error('Failed to get user by ID', { error, userId });
            throw error;
        }
    }
    async verifyToken(token) {
        try {
            const payload = jsonwebtoken_1.default.verify(token, this.JWT_SECRET);
            // Verify user still exists and is active
            const user = await connection_1.db
                .selectFrom('users')
                .select('id')
                .where('id', '=', payload.userId)
                .where('is_active', '=', true)
                .executeTakeFirst();
            if (!user) {
                return null;
            }
            return payload;
        }
        catch (error) {
            logger_1.logger.debug('Token verification failed', { error });
            return null;
        }
    }
    async generateTokens(userId, email, role) {
        const tokenId = (0, uuid_1.v4)();
        const payload = {
            userId,
            email,
            role,
            tokenId,
        };
        const accessToken = jsonwebtoken_1.default.sign(payload, this.JWT_SECRET, {
            expiresIn: this.ACCESS_EXPIRES_IN,
            issuer: environment_1.jwtConfig.issuer,
            audience: environment_1.jwtConfig.audience,
        });
        const refreshToken = jsonwebtoken_1.default.sign(payload, this.JWT_SECRET, {
            expiresIn: this.REFRESH_EXPIRES_IN,
            issuer: environment_1.jwtConfig.issuer,
            audience: environment_1.jwtConfig.audience,
        });
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
            // In a production system, you'd want to maintain a blacklist
            // of revoked tokens. For now, we'll just log the logout
            logger_1.logger.info('User logged out', { userId, tokenId });
            return true;
        }
        catch (error) {
            logger_1.logger.error('Logout failed', { error, userId });
            throw error;
        }
    }
}
exports.AuthService = AuthService;
exports.authService = new AuthService();
//# sourceMappingURL=auth.js.map