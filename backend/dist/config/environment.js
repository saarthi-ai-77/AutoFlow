"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.queueConfig = exports.rateLimitConfig = exports.jwtConfig = exports.redisConfig = exports.databaseConfig = exports.isTest = exports.isProduction = exports.isDevelopment = exports.env = void 0;
const zod_1 = require("zod");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const EnvSchema = zod_1.z.object({
    // Database Configuration
    DATABASE_URL: zod_1.z.string().min(1, 'DATABASE_URL is required'),
    DATABASE_HOST: zod_1.z.string().default('localhost'),
    DATABASE_PORT: zod_1.z.string().transform(Number).default('5432'),
    DATABASE_NAME: zod_1.z.string().default('autoflow'),
    DATABASE_USER: zod_1.z.string().default('postgres'),
    DATABASE_PASSWORD: zod_1.z.string().default('password'),
    // Redis Configuration
    REDIS_URL: zod_1.z.string().min(1, 'REDIS_URL is required'),
    REDIS_HOST: zod_1.z.string().default('localhost'),
    REDIS_PORT: zod_1.z.string().transform(Number).default('6379'),
    REDIS_PASSWORD: zod_1.z.string().optional(),
    // Server Configuration
    PORT: zod_1.z.string().transform(Number).default('3001'),
    NODE_ENV: zod_1.z.enum(['development', 'production', 'test']).default('development'),
    FRONTEND_URL: zod_1.z.string().url('FRONTEND_URL must be a valid URL'),
    // Authentication
    JWT_SECRET: zod_1.z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
    JWT_ACCESS_EXPIRES_IN: zod_1.z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN: zod_1.z.string().default('7d'),
    JWT_ISSUER: zod_1.z.string().default('autoflow'),
    JWT_AUDIENCE: zod_1.z.string().default('autoflow-users'),
    // Encryption
    CRYPTO_SECRET: zod_1.z.string().min(32, 'CRYPTO_SECRET must be at least 32 characters'),
    // Rate Limiting
    RATE_LIMIT_WINDOW_MS: zod_1.z.string().transform(Number).default('900000'),
    RATE_LIMIT_MAX_REQUESTS: zod_1.z.string().transform(Number).default('100'),
    // API Keys
    API_KEY_PREFIX: zod_1.z.string().default('af_live_'),
    API_KEY_HASH_ALGO: zod_1.z.enum(['sha256', 'sha512']).default('sha256'),
    // Logging
    LOG_LEVEL: zod_1.z.enum(['error', 'warn', 'info', 'debug']).default('info'),
    LOG_FORMAT: zod_1.z.enum(['json', 'simple']).default('json'),
    // Webhook Configuration
    WEBHOOK_BASE_URL: zod_1.z.string().url(),
    // Queue Configuration
    QUEUE_CONCURRENCY: zod_1.z.string().transform(Number).default('5'),
    QUEUE_ATTEMPTS: zod_1.z.string().transform(Number).default('3'),
    QUEUE_BACKOFF_DELAY: zod_1.z.string().transform(Number).default('5000'),
    // Health Check
    HEALTH_CHECK_INTERVAL: zod_1.z.string().transform(Number).default('30000'),
    // Test Configuration
    TEST_DATABASE_URL: zod_1.z.string().optional(),
    TEST_REDIS_URL: zod_1.z.string().optional(),
});
exports.env = EnvSchema.parse(process.env);
exports.isDevelopment = exports.env.NODE_ENV === 'development';
exports.isProduction = exports.env.NODE_ENV === 'production';
exports.isTest = exports.env.NODE_ENV === 'test';
exports.databaseConfig = {
    url: exports.isTest ? exports.env.TEST_DATABASE_URL || exports.env.DATABASE_URL : exports.env.DATABASE_URL,
    host: exports.env.DATABASE_HOST,
    port: exports.env.DATABASE_PORT,
    database: exports.env.DATABASE_NAME,
    username: exports.env.DATABASE_USER,
    password: exports.env.DATABASE_PASSWORD,
};
exports.redisConfig = {
    url: exports.isTest ? exports.env.TEST_REDIS_URL || exports.env.REDIS_URL : exports.env.REDIS_URL,
    host: exports.env.REDIS_HOST,
    port: exports.env.REDIS_PORT,
    password: exports.env.REDIS_PASSWORD,
};
exports.jwtConfig = {
    secret: exports.env.JWT_SECRET,
    accessExpiresIn: exports.env.JWT_ACCESS_EXPIRES_IN,
    refreshExpiresIn: exports.env.JWT_REFRESH_EXPIRES_IN,
    issuer: exports.env.JWT_ISSUER,
    audience: exports.env.JWT_AUDIENCE,
};
exports.rateLimitConfig = {
    windowMs: exports.env.RATE_LIMIT_WINDOW_MS,
    maxRequests: exports.env.RATE_LIMIT_MAX_REQUESTS,
};
exports.queueConfig = {
    concurrency: exports.env.QUEUE_CONCURRENCY,
    attempts: exports.env.QUEUE_ATTEMPTS,
    backoffDelay: exports.env.QUEUE_BACKOFF_DELAY,
};
//# sourceMappingURL=environment.js.map