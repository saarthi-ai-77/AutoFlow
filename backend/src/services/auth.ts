import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/database/connection';
import { logger } from '@/utils/logger';
import { jwtConfig } from '@/config/environment';
import { cacheService } from '@/utils/redis-cache';
import {
  EmailSchema,
  PasswordSchema,
  NameSchema,
  UUIDSchema,
  EnhancedRegisterSchema,
  EnhancedLoginSchema,
  EnhancedRefreshTokenSchema,
  sanitizeString,
  hashApiKey,
  verifyApiKey
} from '@/utils/security';

// Enhanced schemas with strong security validation
export const RegisterSchema = EnhancedRegisterSchema;
export const LoginSchema = EnhancedLoginSchema;
export const RefreshTokenSchema = EnhancedRefreshTokenSchema;

export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface JWTPayload {
  userId: string;
  email: string;
  role: string;
  tokenId: string;
  version: number; // Token version for invalidation
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export class AuthService {
  private readonly JWT_SECRET = jwtConfig.secret;
  private readonly ACCESS_EXPIRES_IN = jwtConfig.accessExpiresIn;
  private readonly REFRESH_EXPIRES_IN = jwtConfig.refreshExpiresIn;

  async register(data: RegisterRequest) {
    try {
      // Enhanced input sanitization
      const sanitizedData = {
        email: sanitizeString(data.email.toLowerCase(), 254),
        password: data.password, // Don't sanitize password, validate it
        firstName: sanitizeString(data.firstName, 50),
        lastName: sanitizeString(data.lastName, 50),
      };

      // Validate with enhanced schemas
      const validatedData = RegisterSchema.parse(sanitizedData);

      // Check if user already exists (case-insensitive)
      const existingUser = await db
        .selectFrom('users')
        .select('id')
        .where('email', '=', validatedData.email)
        .executeTakeFirst();

      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Enhanced password hashing with higher cost factor
      const passwordHash = await bcrypt.hash(validatedData.password, 12);

      // Create user with additional security fields
      const userId = uuidv4();
      const now = new Date();
      
      await db
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

      logger.info('User registered successfully', { 
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
    } catch (error) {
      // Sanitize error logging
      const sanitizedEmail = sanitizeString(data.email, 10);
      logger.error('Registration failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        email: sanitizedEmail
      });
      throw error;
    }
  }

  async login(data: LoginRequest) {
    try {
      // Input sanitization
      const sanitizedEmail = sanitizeString(data.email.toLowerCase(), 254);
      const validatedData = LoginSchema.parse({
        email: sanitizedEmail,
        password: data.password,
      });

      // Rate limiting check - implement basic rate limiting here
      await this.checkLoginRateLimit(validatedData.email);

      // Find user by email with security checks
      const user = await db
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
      const isValidPassword = await bcrypt.compare(validatedData.password, user.password_hash);
      if (!isValidPassword) {
        await this.recordFailedLoginAttempt(user.id, validatedData.email);
        throw new Error('Invalid email or password');
      }

      // Reset failed login attempts on successful login
      await this.resetFailedLoginAttempts(user.id);

      // Update last login
      await db
        .updateTable('users')
        .set({
          last_login_at: new Date(),
          updated_at: new Date(),
        })
        .where('id', '=', user.id)
        .execute();

      // Generate tokens with current token version
      const tokens = await this.generateTokens(user.id, user.email, user.role, user.token_version || 1);

      logger.info('User logged in successfully', { 
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
    } catch (error) {
      const sanitizedEmail = sanitizeString(data.email, 10);
      logger.error('Login failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        email: sanitizedEmail
      });
      throw error;
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      // Validate refresh token format first
      EnhancedRefreshTokenSchema.parse({ refreshToken });

      // Verify refresh token
      const payload = jwt.verify(refreshToken, this.JWT_SECRET) as JWTPayload;

      // Check if refresh token exists and is not used
      const tokenHash = await hashApiKey(refreshToken);
      const storedToken = await db
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
      const user = await db
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
      await db
        .updateTable('refresh_tokens')
        .set({
          is_used: true,
          used_at: new Date(),
        })
        .where('id', '=', storedToken.id)
        .execute();

      // Generate new tokens with same version
      const tokens = await this.generateTokens(user.id, user.email, user.role, user.token_version || 1);

      logger.info('Tokens refreshed successfully', {
        userId: user.id,
        tokenVersion: user.token_version
      });

      return tokens;
    } catch (error) {
      logger.error('Token refresh failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        refreshToken: refreshToken.substring(0, 20) + '...'
      });
      throw new Error('Invalid refresh token');
    }
  }

  async getUserById(userId: string) {
    try {
      // Validate UUID format
      UUIDSchema.parse(userId);

      // Try cache first
      const cachedUser = await cacheService.get(`user:profile:${userId}`);
      if (cachedUser) {
        return cachedUser;
      }

      // Cache miss, fetch from database
      const user = await db
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
      await cacheService.set(`user:profile:${userId}`, userData, 60);

      return userData;
    } catch (error) {
      logger.error('Failed to get user by ID', { error, userId: sanitizeString(userId, 10) });
      throw error;
    }
  }

  async verifyToken(token: string): Promise<JWTPayload | null> {
    try {
      const payload = jwt.verify(token, this.JWT_SECRET) as JWTPayload;
      
      // Verify user still exists and is active
      const user = await db
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
    } catch (error) {
      logger.debug('Token verification failed', { error: error instanceof Error ? error.message : 'Unknown error' });
      return null;
    }
  }

  // Invalidate all tokens for a user (for security breaches)
  async invalidateUserTokens(userId: string) {
    try {
      await db
        .updateTable('users')
        .set({ 
          token_version: (userId: any) => (userId as any).token_version + 1,
          updated_at: new Date()
        })
        .where('id', '=', userId)
        .execute();

      logger.info('User tokens invalidated', { userId });
    } catch (error) {
      logger.error('Failed to invalidate user tokens', { error, userId });
      throw error;
    }
  }

  private async generateTokens(userId: string, email: string, role: string, version: number): Promise<AuthTokens> {
    const tokenId = uuidv4();

    const payload: JWTPayload = {
      userId,
      email,
      role,
      tokenId,
      version,
    };

    const accessToken = jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.ACCESS_EXPIRES_IN,
    } as any);

    const refreshToken = jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.REFRESH_EXPIRES_IN,
    } as any);

    // Store refresh token hash for rotation
    const tokenHash = await hashApiKey(refreshToken);
    const expiresAt = new Date(Date.now() + this.getExpirationTime(this.REFRESH_EXPIRES_IN) * 1000);

    await db
      .insertInto('refresh_tokens')
      .values({
        id: uuidv4(),
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

  private getExpirationTime(expiresIn: string): number {
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

  async logout(userId: string, tokenId: string) {
    try {
      // For now, we'll just log the logout
      // In a production system, you might want to maintain a token blacklist
      logger.info('User logged out', { userId, tokenId: sanitizeString(tokenId, 10) });
      
      return true;
    } catch (error) {
      logger.error('Logout failed', { error, userId });
      throw error;
    }
  }

  // Security methods for login protection
  private async checkLoginRateLimit(email: string) {
    // Basic rate limiting - in production, use Redis
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxAttempts = 5;
    
    // This would typically check Redis or a database table
    // For now, we'll implement a basic check
    // TODO: Implement proper Redis-based rate limiting
  }

  private async recordFailedLoginAttempt(userId: string | null, email: string) {
    try {
      if (userId) {
        await db
          .updateTable('users')
          .set({
            failed_login_attempts: (userId: any) => (userId as any).failed_login_attempts + 1,
            last_failed_login_at: new Date(),
            updated_at: new Date()
          })
          .where('id', '=', userId)
          .execute();
      }
      
      logger.warn('Failed login attempt', { 
        userId, 
        email: sanitizeString(email, 10) 
      });
    } catch (error) {
      logger.error('Failed to record login attempt', { error });
    }
  }

  private async resetFailedLoginAttempts(userId: string) {
    try {
      await db
        .updateTable('users')
        .set({
          failed_login_attempts: 0,
          last_failed_login_at: undefined,
          updated_at: new Date()
        })
        .where('id', '=', userId)
        .execute();
    } catch (error) {
      logger.error('Failed to reset login attempts', { error, userId });
    }
  }

  private async isAccountLocked(userId: string): Promise<boolean> {
    try {
      const user = await db
        .selectFrom('users')
        .select(['failed_login_attempts', 'last_failed_login_at'])
        .where('id', '=', userId)
        .executeTakeFirst();

      if (!user) return false;

      const maxAttempts = 5;
      const lockoutDuration = 30 * 60 * 1000; // 30 minutes
      const now = new Date();
      
      if (user.failed_login_attempts >= maxAttempts) {
        const lastFailed = user.last_failed_login_at ? new Date(user.last_failed_login_at) : null;
        if (lastFailed && (now.getTime() - lastFailed.getTime()) < lockoutDuration) {
          return true; // Account is locked
        } else {
          // Lockout period expired, reset attempts
          await this.resetFailedLoginAttempts(userId);
          return false;
        }
      }
      
      return false;
    } catch (error) {
      logger.error('Failed to check account lock status', { error, userId });
      return false; // Don't lock account on error
    }
  }
}

export const authService = new AuthService();