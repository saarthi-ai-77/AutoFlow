import { z } from 'zod';
import crypto from 'crypto';

// Custom sanitization function
export const sanitizeString = (input: string, maxLength = 255): string => {
  if (typeof input !== 'string') {
    throw new Error('Input must be a string');
  }
  
  // Remove any potential XSS characters
  const sanitized = input
    .replace(/[<>]/g, '') // Remove < and > tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .replace(/['"]/g, '') // Remove quotes that could break SQL
    .trim();
  
  // Limit length
  return sanitized.substring(0, maxLength);
};

// Email validation with stricter rules
export const EmailSchema = z.string()
  .email('Invalid email format')
  .refine(
    (email) => {
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      return emailRegex.test(email);
    },
    'Email format is invalid'
  )
  .refine(
    (email) => email.length <= 254, // RFC 5321 limit
    'Email is too long'
  );

// Password validation with strong security requirements
export const PasswordSchema = z.string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password is too long')
  .refine(
    (password) => /[a-z]/.test(password),
    'Password must contain at least one lowercase letter'
  )
  .refine(
    (password) => /[A-Z]/.test(password),
    'Password must contain at least one uppercase letter'
  )
  .refine(
    (password) => /[0-9]/.test(password),
    'Password must contain at least one number'
  )
  .refine(
    (password) => /[^a-zA-Z0-9]/.test(password),
    'Password must contain at least one special character'
  )
  .refine(
    (password) => !/(.)\1{2,}/.test(password), // No 3+ repeated characters
    'Password cannot contain 3 or more repeated characters'
  )
  .refine(
    (password) => !/(?:password|123|qwerty|admin)/i.test(password), // No common passwords
    'Password cannot contain common patterns'
  );

// Name validation
export const NameSchema = z.string()
  .min(1, 'Name is required')
  .max(50, 'Name is too long')
  .regex(/^[a-zA-Z\s\-'\.]+$/, 'Name contains invalid characters')
  .refine(
    (name) => sanitizeString(name) === name,
    'Name contains potentially dangerous characters'
  );

// UUID validation
export const UUIDSchema = z.string()
  .uuid('Invalid UUID format')
  .refine(
    (uuid) => {
      // Additional UUID format validation
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      return uuidRegex.test(uuid);
    },
    'Invalid UUID format'
  );

// URL validation with security checks
export const SecureUrlSchema = z.string()
  .url('Invalid URL format')
  .refine(
    (url) => {
      try {
        const parsed = new URL(url);
        // Only allow HTTP and HTTPS
        if (!['http:', 'https:'].includes(parsed.protocol)) {
          return false;
        }
        // Disallow localhost and private IPs in production-like URLs
        const hostname = parsed.hostname.toLowerCase();
        if (
          hostname === 'localhost' ||
          hostname === '127.0.0.1' ||
          hostname.startsWith('10.') ||
          hostname.startsWith('192.168.') ||
          hostname.startsWith('172.')
        ) {
          // Allow localhost only if not in production
          return process.env.NODE_ENV !== 'production';
        }
        return true;
      } catch {
        return false;
      }
    },
    'URL contains unsafe or invalid address'
  )
  .max(2048, 'URL is too long');

// API Key validation
export const ApiKeySchema = z.string()
  .min(1, 'API key is required')
  .max(256, 'API key is too long')
  .regex(/^[a-zA-Z0-9\-_.]+$/, 'API key contains invalid characters');

// Workflow name validation
export const WorkflowNameSchema = z.string()
  .min(1, 'Workflow name is required')
  .max(100, 'Workflow name is too long')
  .refine(
    (name) => sanitizeString(name, 100) === name,
    'Workflow name contains potentially dangerous characters'
  )
  .regex(/^[a-zA-Z0-9\s\-_\.]+$/, 'Workflow name contains invalid characters');

// Workflow description validation
export const WorkflowDescriptionSchema = z.string()
  .max(1000, 'Description is too long')
  .refine(
    (desc) => sanitizeString(desc, 1000) === desc,
    'Description contains potentially dangerous characters'
  )
  .optional();

// Node type validation
export const NodeTypeSchema = z.enum([
  'trigger',
  'http',
  'email',
  'condition',
  'delay',
  'transform',
  'filter',
  'webhook',
  'custom'
]);

// Node data validation
export const NodeDataSchema = z.record(z.any())
  .refine(
    (data) => {
      // Prevent deeply nested objects that could cause DoS
      const getDepth = (obj: any, depth = 0): number => {
        if (depth > 10) return depth; // Max depth of 10
        if (typeof obj !== 'object' || obj === null) return depth;
        return Math.max(...Object.values(obj).map(value => getDepth(value, depth + 1)));
      };
      return getDepth(data) <= 10;
    },
    'Node data is too complex'
  );

// Pagination validation
export const PaginationSchema = z.object({
  page: z.number()
    .int('Page must be an integer')
    .min(1, 'Page must be at least 1')
    .max(1000, 'Page cannot exceed 1000'),
  limit: z.number()
    .int('Limit must be an integer')
    .min(1, 'Limit must be at least 1')
    .max(100, 'Limit cannot exceed 100'),
});

// Search validation
export const SearchSchema = z.string()
  .max(100, 'Search query is too long')
  .refine(
    (query) => {
      // Prevent SQL injection and XSS in search queries
      const dangerous = /(<script|javascript:|data:|vbscript:|onload=|onerror=|union|select|insert|delete|update|drop|create|alter)/i;
      return !dangerous.test(query);
    },
    'Search query contains invalid patterns'
  );

// Rate limiting key validation
export const RateLimitKeySchema = z.string()
  .max(100, 'Rate limit key is too long')
  .regex(/^[a-zA-Z0-9\-_.]+$/, 'Invalid rate limit key format');

// Enhanced schemas for authentication
export const EnhancedRegisterSchema = z.object({
  email: EmailSchema,
  password: PasswordSchema,
  firstName: NameSchema,
  lastName: NameSchema,
});

export const EnhancedLoginSchema = z.object({
  email: EmailSchema,
  password: z.string().min(1, 'Password is required'),
});

export const EnhancedRefreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

// Sanitization middleware
export const createSanitizationMiddleware = (schema: z.ZodSchema) => {
  return (req: any, res: any, next: any) => {
    try {
      // Sanitize request body
      if (req.body && typeof req.body === 'object') {
        req.body = sanitizeObject(req.body);
      }
      
      // Sanitize query parameters
      if (req.query && typeof req.query === 'object') {
        req.query = sanitizeObject(req.query);
      }
      
      // Validate against schema
      schema.parse(req.body || {});
      
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: error.errors,
        });
      }
      return res.status(400).json({
        error: 'Invalid input data',
        code: 'INVALID_INPUT',
      });
    }
  };
};

// Recursive object sanitization
const sanitizeObject = (obj: any): any => {
  if (typeof obj === 'string') {
    return sanitizeString(obj);
  }
  
  if (Array.isArray(obj)) {
    return obj.map(sanitizeObject);
  }
  
  if (typeof obj === 'object' && obj !== null) {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      // Sanitize keys as well
      const sanitizedKey = sanitizeString(key, 50);
      sanitized[sanitizedKey] = sanitizeObject(value);
    }
    return sanitized;
  }
  
  return obj;
};

// Security headers validation
export const validateSecurityHeaders = (headers: Record<string, string>) => {
  // Check for suspicious patterns
  const suspicious = ['<script', 'javascript:', 'data:', 'vbscript:'];
  
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      for (const pattern of suspicious) {
        if (value.toLowerCase().includes(pattern)) {
          throw new Error(`Suspicious pattern detected in header ${key}`);
        }
      }
    }
  }
};

// Hash utilities for API keys
export const hashApiKey = (apiKey: string, salt?: string): string => {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(apiKey, usedSalt, 10000, 64, 'sha256');
  return `${usedSalt}:${hash.toString('hex')}`;
};

export const verifyApiKey = (apiKey: string, hashedApiKey: string): boolean => {
  const [salt, originalHash] = hashedApiKey.split(':');
  const hash = crypto.pbkdf2Sync(apiKey, salt, 10000, 64, 'sha256');
  return hash.toString('hex') === originalHash;
};