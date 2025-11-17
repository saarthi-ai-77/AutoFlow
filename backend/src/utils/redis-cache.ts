import Redis from 'ioredis';
import { env, isProduction } from '@/config/environment';
import { logger } from '@/utils/logger';

/**
 * Comprehensive Redis caching service for AutoFlow
 * Implements cache-aside pattern with automatic invalidation
 */
export class RedisCacheService {
  private redis: Redis;
  private readonly defaultTTL = 300; // 5 minutes default
  private metrics = {
    hits: 0,
    misses: 0,
    sets: 0,
    deletes: 0,
    evictions: 0,
    averageGetTime: 0,
    averageSetTime: 0,
    errors: 0
  };

  constructor() {
    // Enhanced Redis configuration
    this.redis = new Redis(env.REDIS_URL, {
      // Connection settings
      host: env.REDIS_HOST,
      port: env.REDIS_PORT,
      password: env.REDIS_PASSWORD || undefined,
      
      // Performance settings
      lazyConnect: true,
      maxRetriesPerRequest: 3,
      retryDelayOnFailover: 100,
      enableReadyCheck: true,
      
      // Memory management
      maxmemory: '256mb',
      'maxmemory-policy': 'allkeys-lru',
      
      // Connection pooling
      connectionTimeout: 5000,
      commandTimeout: 5000,
      
      // Keepalive
      keepAlive: 30000,
      
      // TLS for production
      tls: isProduction ? {
        rejectUnauthorized: false
      } : undefined,
      
      // Monitoring
      enableAutoPipelining: true,
    });

    this.setupEventListeners();
    this.startMetricsCollection();
  }

  private setupEventListeners(): void {
    this.redis.on('connect', () => {
      logger.info('Redis connected successfully');
    });

    this.redis.on('ready', () => {
      logger.info('Redis ready for commands');
    });

    this.redis.on('error', (error) => {
      logger.error('Redis error', { error });
      this.metrics.errors++;
    });

    this.redis.on('close', () => {
      logger.warn('Redis connection closed');
    });

    this.redis.on('reconnecting', () => {
      logger.info('Redis reconnecting');
    });

    this.redis.on('end', () => {
      logger.error('Redis connection ended');
    });
  }

  private startMetricsCollection(): void {
    setInterval(() => {
      this.logMetrics();
    }, 30000); // Log metrics every 30 seconds
  }

  private logMetrics(): void {
    const hitRate = this.metrics.hits + this.metrics.misses > 0 
      ? (this.metrics.hits / (this.metrics.hits + this.metrics.misses) * 100).toFixed(2)
      : '0.00';

    logger.info('Redis cache metrics', {
      hitRate: `${hitRate}%`,
      hits: this.metrics.hits,
      misses: this.metrics.misses,
      sets: this.metrics.sets,
      deletes: this.metrics.deletes,
      evictions: this.metrics.evictions,
      avgGetTime: `${this.metrics.averageGetTime.toFixed(2)}ms`,
      avgSetTime: `${this.metrics.averageSetTime.toFixed(2)}ms`,
      errors: this.metrics.errors
    });
  }

  // Generic cache operations
  async get<T = any>(key: string): Promise<T | null> {
    const startTime = Date.now();
    
    try {
      const value = await this.redis.get(key);
      
      if (value === null) {
        this.metrics.misses++;
        return null;
      }

      this.metrics.hits++;
      const parsedValue = JSON.parse(value);
      
      logger.debug('Cache hit', { key, valueSize: value.length });
      return parsedValue;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache get error', { key, error });
      return null;
    } finally {
      const duration = Date.now() - startTime;
      this.updateAverageGetTime(duration);
    }
  }

  async set(
    key: string, 
    value: any, 
    ttlSeconds?: number, 
    options?: { nx?: boolean; xx?: boolean }
  ): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const serializedValue = JSON.stringify(value);
      const ttl = ttlSeconds || this.defaultTTL;
      
      let result;
      if (options?.nx) {
        result = await this.redis.setnx(key, serializedValue);
        if (result) {
          await this.redis.expire(key, ttl);
        }
      } else if (options?.xx) {
        result = await this.redis.set(key, serializedValue, 'EX', ttl, 'XX');
      } else {
        result = await this.redis.set(key, serializedValue, 'EX', ttl);
      }

      this.metrics.sets++;
      
      logger.debug('Cache set', { 
        key, 
        valueSize: serializedValue.length,
        ttl: ttl,
        result: result
      });
      
      return result !== null;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache set error', { key, error });
      return false;
    } finally {
      const duration = Date.now() - startTime;
      this.updateAverageSetTime(duration);
    }
  }

  async delete(key: string): Promise<boolean> {
    try {
      const result = await this.redis.del(key);
      this.metrics.deletes++;
      return result === 1;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache delete error', { key, error });
      return false;
    }
  }

  async exists(key: string): Promise<boolean> {
    try {
      const result = await this.redis.exists(key);
      return result === 1;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache exists error', { key, error });
      return false;
    }
  }

  async expire(key: string, ttlSeconds: number): Promise<boolean> {
    try {
      const result = await this.redis.expire(key, ttlSeconds);
      return result === 1;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache expire error', { key, error });
      return false;
    }
  }

  // Batch operations
  async mget<T = any>(keys: string[]): Promise<Array<T | null>> {
    try {
      const values = await this.redis.mget(...keys);
      return values.map(value => {
        if (value === null) {
          this.metrics.misses++;
          return null;
        }
        this.metrics.hits++;
        return JSON.parse(value);
      });
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache mget error', { keys, error });
      return keys.map(() => null);
    }
  }

  async mset(keyValuePairs: Record<string, any>, ttlSeconds?: number): Promise<boolean> {
    try {
      const pipeline = this.redis.pipeline();
      
      Object.entries(keyValuePairs).forEach(([key, value]) => {
        const serializedValue = JSON.stringify(value);
        pipeline.set(key, serializedValue, 'EX', ttlSeconds || this.defaultTTL);
      });

      await pipeline.exec();
      this.metrics.sets += Object.keys(keyValuePairs).length;
      
      return true;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache mset error', { keyCount: Object.keys(keyValuePairs).length, error });
      return false;
    }
  }

  // Pattern-based operations
  async deletePattern(pattern: string): Promise<number> {
    try {
      const keys = await this.redis.keys(pattern);
      if (keys.length === 0) {
        return 0;
      }
      
      const result = await this.redis.del(...keys);
      this.metrics.deletes += result;
      
      logger.debug('Cache pattern delete', { pattern, deletedKeys: result });
      return result;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache pattern delete error', { pattern, error });
      return 0;
    }
  }

  async getKeys(pattern: string): Promise<string[]> {
    try {
      const keys = await this.redis.keys(pattern);
      return keys;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache get keys error', { pattern, error });
      return [];
    }
  }

  // Increment/Decrement operations
  async increment(key: string, amount = 1): Promise<number> {
    try {
      const result = await this.redis.incrby(key, amount);
      
      // Set expiration if key doesn't exist
      await this.redis.expire(key, this.defaultTTL);
      
      return result;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache increment error', { key, amount, error });
      return 0;
    }
  }

  async decrement(key: string, amount = 1): Promise<number> {
    try {
      const result = await this.redis.decrby(key, amount);
      
      // Set expiration if key doesn't exist
      await this.redis.expire(key, this.defaultTTL);
      
      return result;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache decrement error', { key, amount, error });
      return 0;
    }
  }

  // Hash operations
  async hset(key: string, field: string, value: any): Promise<boolean> {
    try {
      const serializedValue = JSON.stringify(value);
      await this.redis.hset(key, field, serializedValue);
      await this.redis.expire(key, this.defaultTTL);
      return true;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache hset error', { key, field, error });
      return false;
    }
  }

  async hget<T = any>(key: string, field: string): Promise<T | null> {
    try {
      const value = await this.redis.hget(key, field);
      
      if (value === null) {
        this.metrics.misses++;
        return null;
      }

      this.metrics.hits++;
      return JSON.parse(value);
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache hget error', { key, field, error });
      return null;
    }
  }

  async hgetall<T = Record<string, any>>(key: string): Promise<T> {
    try {
      const hash = await this.redis.hgetall(key);
      const result: any = {};
      
      for (const [field, value] of Object.entries(hash)) {
        try {
          result[field] = JSON.parse(value);
        } catch {
          result[field] = value;
        }
      }
      
      // Update metrics based on result
      if (Object.keys(result).length > 0) {
        this.metrics.hits++;
      } else {
        this.metrics.misses++;
      }
      
      return result;
    } catch (error) {
      this.metrics.errors++;
      logger.error('Cache hgetall error', { key, error });
      return {};
    }
  }

  // Specialized cache methods for AutoFlow
  async cacheWorkflow(workflowId: string, workflow: any, ttlSeconds = 300): Promise<void> {
    const cacheKey = `workflow:${workflowId}`;
    await this.set(cacheKey, workflow, ttlSeconds);
  }

  async getCachedWorkflow(workflowId: string): Promise<any | null> {
    const cacheKey = `workflow:${workflowId}`;
    return this.get(cacheKey);
  }

  async invalidateWorkflow(workflowId: string): Promise<void> {
    const cacheKey = `workflow:${workflowId}`;
    await this.delete(cacheKey);
    
    // Also invalidate user workflow lists
    await this.deletePattern(`user:workflows:*`);
  }

  async cacheUserWorkflows(userId: string, workflows: any[], ttlSeconds = 120): Promise<void> {
    const cacheKey = `user:workflows:${userId}`;
    await this.set(cacheKey, workflows, ttlSeconds);
  }

  async getCachedUserWorkflows(userId: string): Promise<any[] | null> {
    const cacheKey = `user:workflows:${userId}`;
    return this.get(cacheKey);
  }

  async cacheExecution(executionId: string, execution: any, ttlSeconds = 600): Promise<void> {
    const cacheKey = `execution:${executionId}`;
    await this.set(cacheKey, execution, ttlSeconds);
  }

  async getCachedExecution(executionId: string): Promise<any | null> {
    const cacheKey = `execution:${executionId}`;
    return this.get(cacheKey);
  }

  async cacheUserProfile(userId: string, profile: any, ttlSeconds = 180): Promise<void> {
    const cacheKey = `user:profile:${userId}`;
    await this.set(cacheKey, profile, ttlSeconds);
  }

  async getCachedUserProfile(userId: string): Promise<any | null> {
    const cacheKey = `user:profile:${userId}`;
    return this.get(cacheKey);
  }

  async invalidateUserProfile(userId: string): Promise<void> {
    const cacheKey = `user:profile:${userId}`;
    await this.delete(cacheKey);
  }

  // Rate limiting cache
  async incrementRateLimit(key: string, windowSeconds: number, maxRequests: number): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
  }> {
    const now = Date.now();
    const window = Math.floor(now / (windowSeconds * 1000));
    const redisKey = `ratelimit:${key}:${window}`;
    
    try {
      const current = await this.increment(redisKey);
      const remaining = Math.max(0, maxRequests - current);
      const resetTime = (window + 1) * windowSeconds * 1000;
      
      // Set expiration for the window
      await this.redis.expire(redisKey, windowSeconds);
      
      return {
        allowed: current <= maxRequests,
        remaining,
        resetTime
      };
    } catch (error) {
      this.metrics.errors++;
      logger.error('Rate limit increment error', { key, error });
      return {
        allowed: true,
        remaining: maxRequests,
        resetTime: now + (windowSeconds * 1000)
      };
    }
  }

  // Health check and monitoring
  async healthCheck(): Promise<{
    isHealthy: boolean;
    metrics: typeof this.metrics;
    redisInfo: any;
    recommendations: string[];
  }> {
    const recommendations: string[] = [];
    
    try {
      // Test connectivity
      const startTime = Date.now();
      await this.redis.ping();
      const responseTime = Date.now() - startTime;

      // Get Redis info
      const redisInfo = await this.redis.info();
      const info = this.parseRedisInfo(redisInfo);

      // Analyze metrics
      const hitRate = this.metrics.hits + this.metrics.misses > 0 
        ? (this.metrics.hits / (this.metrics.hits + this.metrics.misses))
        : 1;

      if (hitRate < 0.8) {
        recommendations.push('Low cache hit rate detected. Consider increasing TTL or reviewing cache keys.');
      }

      if (this.metrics.errors > 10) {
        recommendations.push('High error rate detected. Check Redis connectivity and configuration.');
      }

      if (info.memory.used_memory_percentage > 90) {
        recommendations.push('High memory usage detected. Consider increasing Redis memory or implementing more aggressive eviction.');
      }

      if (info.stats.keyspace_hits < info.stats.keyspace_misses) {
        recommendations.push('More misses than hits. Review cache strategy and key design.');
      }

      const isHealthy = responseTime < 100 && hitRate > 0.7 && this.metrics.errors < 5;

      return {
        isHealthy,
        metrics: { ...this.metrics },
        redisInfo: info,
        recommendations
      };
    } catch (error) {
      logger.error('Redis health check failed', { error });
      return {
        isHealthy: false,
        metrics: { ...this.metrics },
        redisInfo: {},
        recommendations: ['Redis connection failed. Check Redis server status.']
      };
    }
  }

  private parseRedisInfo(info: string): any {
    const sections = info.split('\r\n\r\n');
    const parsed: any = {};
    
    for (const section of sections) {
      const lines = section.split('\r\n');
      if (lines[0]?.startsWith('#')) {
        const sectionName = lines[0].substring(1).trim();
        const sectionData: any = {};
        
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i];
          if (line.includes(':')) {
            const [key, value] = line.split(':');
            sectionData[key] = isNaN(Number(value)) ? value : Number(value);
          }
        }
        
        parsed[sectionName] = sectionData;
      }
    }
    
    return parsed;
  }

  private updateAverageGetTime(duration: number): void {
    const current = this.metrics.averageGetTime;
    this.metrics.averageGetTime = (current + duration) / 2;
  }

  private updateAverageSetTime(duration: number): void {
    const current = this.metrics.averageSetTime;
    this.metrics.averageSetTime = (current + duration) / 2;
  }

  // Cache warming utilities
  async warmCache(workflowIds: string[]): Promise<void> {
    logger.info('Starting cache warming', { workflowCount: workflowIds.length });
    
    try {
      // This would typically fetch from database and cache
      // For now, just log the action
      for (const workflowId of workflowIds) {
        logger.debug('Warming cache for workflow', { workflowId });
      }
      
      logger.info('Cache warming completed');
    } catch (error) {
      logger.error('Cache warming failed', { error });
    }
  }

  // Graceful shutdown
  async close(): Promise<void> {
    try {
      await this.redis.quit();
      logger.info('Redis connection closed gracefully');
    } catch (error) {
      logger.error('Error closing Redis connection', { error });
    }
  }
}

// Cache-aside pattern implementation
export class CacheService {
  private cache: RedisCacheService;

  constructor() {
    this.cache = new RedisCacheService();
  }

  async getOrSet<T>(
    key: string,
    fetchFunction: () => Promise<T>,
    ttlSeconds?: number
  ): Promise<T> {
    // Try to get from cache first
    let value = await this.cache.get<T>(key);
    
    if (value !== null) {
      return value;
    }

    // Cache miss, fetch from source
    try {
      value = await fetchFunction();
      
      // Cache the result
      if (value !== null) {
        await this.cache.set(key, value, ttlSeconds);
      }
      
      return value;
    } catch (error) {
      logger.error('Cache get-or-set fetch failed', { key, error });
      throw error;
    }
  }

  // Delegate cache operations
  async set(key: string, value: any, ttlSeconds?: number): Promise<boolean> {
    return this.cache.set(key, value, ttlSeconds);
  }

  async get<T = any>(key: string): Promise<T | null> {
    return this.cache.get<T>(key);
  }

  async delete(key: string): Promise<boolean> {
    return this.cache.delete(key);
  }

  async deletePattern(pattern: string): Promise<number> {
    return this.cache.deletePattern(pattern);
  }

  async healthCheck(): Promise<any> {
    return this.cache.healthCheck();
  }
}

// Export singleton instance
export const cacheService = new CacheService();

// Setup cache monitoring
export const setupCacheMonitoring = () => {
  // Monitor cache health every 2 minutes
  setInterval(async () => {
    try {
      const health = await cacheService.healthCheck();
      
      if (!health.isHealthy) {
        logger.warn('Cache health check failed', {
          recommendations: health.recommendations
        });
      }
      
    } catch (error) {
      logger.error('Cache monitoring failed', { error });
    }
  }, 120000); // Check every 2 minutes
};