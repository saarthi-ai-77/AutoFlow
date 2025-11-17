import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const EnvSchema = z.object({
  // Database Configuration
  DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
  DATABASE_HOST: z.string().default('localhost'),
  DATABASE_PORT: z.string().transform(Number).default('5432'),
  DATABASE_NAME: z.string().default('autoflow'),
  DATABASE_USER: z.string().default('postgres'),
  DATABASE_PASSWORD: z.string().default('password'),

  // Redis Configuration
  REDIS_URL: z.string().min(1, 'REDIS_URL is required'),
  REDIS_HOST: z.string().default('localhost'),
  REDIS_PORT: z.string().transform(Number).default('6379'),
  REDIS_PASSWORD: z.string().optional(),

  // Server Configuration
  PORT: z.string().transform(Number).default('3001'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  FRONTEND_URL: z.string().url('FRONTEND_URL must be a valid URL'),

  // Authentication
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  JWT_ISSUER: z.string().default('autoflow'),
  JWT_AUDIENCE: z.string().default('autoflow-users'),

  // Encryption
  CRYPTO_SECRET: z.string().min(32, 'CRYPTO_SECRET must be at least 32 characters'),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.string().transform(Number).default('900000'),
  RATE_LIMIT_MAX_REQUESTS: z.string().transform(Number).default('100'),

  // API Keys
  API_KEY_PREFIX: z.string().default('af_live_'),
  API_KEY_HASH_ALGO: z.enum(['sha256', 'sha512']).default('sha256'),

  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  LOG_FORMAT: z.enum(['json', 'simple']).default('json'),

  // Webhook Configuration
  WEBHOOK_BASE_URL: z.string().url(),

  // Queue Configuration
  QUEUE_CONCURRENCY: z.string().transform(Number).default('5'),
  QUEUE_ATTEMPTS: z.string().transform(Number).default('3'),
  QUEUE_BACKOFF_DELAY: z.string().transform(Number).default('5000'),

  // Health Check
  HEALTH_CHECK_INTERVAL: z.string().transform(Number).default('30000'),

  // Test Configuration
  TEST_DATABASE_URL: z.string().optional(),
  TEST_REDIS_URL: z.string().optional(),
});

export type Environment = z.infer<typeof EnvSchema>;

export const env: Environment = EnvSchema.parse(process.env);

export const isDevelopment = env.NODE_ENV === 'development';
export const isProduction = env.NODE_ENV === 'production';
export const isTest = env.NODE_ENV === 'test';

export const databaseConfig = {
  url: isTest ? env.TEST_DATABASE_URL || env.DATABASE_URL : env.DATABASE_URL,
  host: env.DATABASE_HOST,
  port: env.DATABASE_PORT,
  database: env.DATABASE_NAME,
  username: env.DATABASE_USER,
  password: env.DATABASE_PASSWORD,
};

export const redisConfig = {
  url: isTest ? env.TEST_REDIS_URL || env.REDIS_URL : env.REDIS_URL,
  host: env.REDIS_HOST,
  port: env.REDIS_PORT,
  password: env.REDIS_PASSWORD,
};

export const jwtConfig = {
  secret: env.JWT_SECRET,
  accessExpiresIn: env.JWT_ACCESS_EXPIRES_IN,
  refreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN,
  issuer: env.JWT_ISSUER,
  audience: env.JWT_AUDIENCE,
};

export const rateLimitConfig = {
  windowMs: env.RATE_LIMIT_WINDOW_MS,
  maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
};

export const queueConfig = {
  concurrency: env.QUEUE_CONCURRENCY,
  attempts: env.QUEUE_ATTEMPTS,
  backoffDelay: env.QUEUE_BACKOFF_DELAY,
};