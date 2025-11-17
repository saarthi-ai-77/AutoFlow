import { Router, Request, Response } from 'express';
import { authService, RegisterSchema, LoginSchema, RefreshTokenSchema } from '@/services/auth';
import { z } from 'zod';
import { logger } from '@/utils/logger';

const router = Router();

// Register endpoint
router.post('/register', async (req: Request, res: Response) => {
  try {
    const validatedData = RegisterSchema.parse(req.body);
    
    const result = await authService.register({
      email: validatedData.email,
      password: validatedData.password,
      firstName: validatedData.firstName,
      lastName: validatedData.lastName,
    });

    res.status(201).json({
      message: 'User registered successfully',
      data: result,
    });

    logger.info('User registration successful', { 
      userId: result.user.id, 
      email: result.user.email 
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
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

    logger.error('Registration failed', { error, body: req.body });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Login endpoint
router.post('/login', async (req: Request, res: Response) => {
  try {
    const validatedData = LoginSchema.parse(req.body);
    
    const result = await authService.login({
      email: validatedData.email,
      password: validatedData.password,
    });

    res.json({
      message: 'Login successful',
      data: result,
    });

    logger.info('User login successful', { 
      userId: result.user.id, 
      email: result.user.email 
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
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

    logger.error('Login failed', { error, body: req.body });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Refresh token endpoint
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const validatedData = RefreshTokenSchema.parse(req.body);
    
    const tokens = await authService.refreshToken(validatedData.refreshToken);

    res.json({
      message: 'Token refreshed successfully',
      data: { tokens },
    });

    logger.info('Token refresh successful');
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: error.errors,
      });
    }

    logger.error('Token refresh failed', { error, body: req.body });
    res.status(401).json({
      error: 'Invalid refresh token',
      code: 'INVALID_REFRESH_TOKEN',
    });
  }
});

// Get current user
router.get('/me', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Access token required',
        code: 'UNAUTHORIZED',
      });
    }

    const token = authHeader.substring(7);
    const payload = await authService.verifyToken(token);
    
    if (!payload) {
      return res.status(401).json({
        error: 'Invalid or expired token',
        code: 'TOKEN_INVALID',
      });
    }

    const user = await authService.getUserById(payload.userId);

    res.json({
      message: 'User retrieved successfully',
      data: { user },
    });

    logger.debug('User profile retrieved', { userId: user.id });
  } catch (error) {
    logger.error('Get user profile failed', { error, headers: req.headers });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

// Logout endpoint
router.post('/logout', async (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const payload = await authService.verifyToken(token);
      
      if (payload) {
        await authService.logout(payload.userId, payload.tokenId);
      }
    }

    res.json({
      message: 'Logout successful',
    });

    logger.info('User logout successful');
  } catch (error) {
    logger.error('Logout failed', { error });
    res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
    });
  }
});

export { router as authRoutes };