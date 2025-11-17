import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/database/connection';
import { logger } from '@/utils/logger';
import { jwtConfig } from '@/config/environment';
import { z } from 'zod';

// User schemas for validation
export const RegisterSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  firstName: z.string().min(1, 'First name is required'),
  lastName: z.string().min(1, 'Last name is required'),
});

export const LoginSchema = z.object({
  email: z.string().email('Invalid email format'),
  password: z.string().min(1, 'Password is required'),
});

export const RefreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

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
      // Check if user already exists
      const existingUser = await db
        .selectFrom('users')
        .select('id')
        .where('email', '=', data.email)
        .executeTakeFirst();

      if (existingUser) {
        throw new Error('User with this email already exists');
      }

      // Hash password
      const passwordHash = await bcrypt.hash(data.password, 12);

      // Create user
      const userId = uuidv4();
      await db
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

      logger.info('User registered successfully', { userId, email: data.email });

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
    } catch (error) {
      logger.error('Registration failed', { error, email: data.email });
      throw error;
    }
  }

  async login(data: LoginRequest) {
    try {
      // Find user by email
      const user = await db
        .selectFrom('users')
        .selectAll()
        .where('email', '=', data.email)
        .where('is_active', '=', true)
        .executeTakeFirst();

      if (!user) {
        throw new Error('Invalid email or password');
      }

      // Verify password
      const isValidPassword = await bcrypt.compare(data.password, user.password_hash);
      if (!isValidPassword) {
        throw new Error('Invalid email or password');
      }

      // Update last login
      await db
        .updateTable('users')
        .set({ last_login_at: new Date() })
        .where('id', '=', user.id)
        .execute();

      // Generate tokens
      const tokens = await this.generateTokens(user.id, user.email, user.role);

      logger.info('User logged in successfully', { userId: user.id, email: user.email });

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
      logger.error('Login failed', { error, email: data.email });
      throw error;
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      // Verify refresh token
      const payload = jwt.verify(refreshToken, this.JWT_SECRET) as JWTPayload;
      
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

      // Generate new tokens
      const tokens = await this.generateTokens(user.id, user.email, user.role);

      logger.info('Tokens refreshed successfully', { userId: user.id });

      return tokens;
    } catch (error) {
      logger.error('Token refresh failed', { error, refreshToken: refreshToken.substring(0, 20) + '...' });
      throw new Error('Invalid refresh token');
    }
  }

  async getUserById(userId: string) {
    try {
      const user = await db
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
    } catch (error) {
      logger.error('Failed to get user by ID', { error, userId });
      throw error;
    }
  }

  async verifyToken(token: string): Promise<JWTPayload | null> {
    try {
      const payload = jwt.verify(token, this.JWT_SECRET) as JWTPayload;
      
      // Verify user still exists and is active
      const user = await db
        .selectFrom('users')
        .select('id')
        .where('id', '=', payload.userId)
        .where('is_active', '=', true)
        .executeTakeFirst();

      if (!user) {
        return null;
      }

      return payload;
    } catch (error) {
      logger.debug('Token verification failed', { error });
      return null;
    }
  }

  private async generateTokens(userId: string, email: string, role: string): Promise<AuthTokens> {
    const tokenId = uuidv4();
    
    const payload: JWTPayload = {
      userId,
      email,
      role,
      tokenId,
    };

    const accessToken = jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.ACCESS_EXPIRES_IN,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
    });

    const refreshToken = jwt.sign(payload, this.JWT_SECRET, {
      expiresIn: this.REFRESH_EXPIRES_IN,
      issuer: jwtConfig.issuer,
      audience: jwtConfig.audience,
    });

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
      // In a production system, you'd want to maintain a blacklist
      // of revoked tokens. For now, we'll just log the logout
      logger.info('User logged out', { userId, tokenId });
      
      return true;
    } catch (error) {
      logger.error('Logout failed', { error, userId });
      throw error;
    }
  }
}

export const authService = new AuthService();