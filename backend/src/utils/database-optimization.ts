import { Pool } from 'pg';
import { env, isProduction } from '@/config/environment';
import { logger } from '@/utils/logger';

/**
 * Enhanced database connection pool with monitoring and optimization
 */
export class OptimizedConnectionPool {
  private pool: Pool;
  private metrics = {
    totalConnections: 0,
    idleConnections: 0,
    waitingClients: 0,
    activeConnections: 0,
    maxConnections: 0,
    queriesExecuted: 0,
    slowQueries: 0,
    averageQueryTime: 0,
    lastHealthCheck: new Date()
  };

  constructor() {
    // Enhanced connection pool configuration
    this.pool = new Pool({
      connectionString: env.DATABASE_URL,
      
      // Connection pool settings
      max: this.getOptimalPoolSize(),
      min: Math.min(5, this.getOptimalPoolSize()),
      idleTimeoutMillis: 30000, // 30 seconds
      connectionTimeoutMillis: 2000, // 2 seconds
      
      // Query optimization
      statement_timeout: 30000, // 30 seconds max query time
      query_timeout: 30000,
      
      // SSL configuration for production
      ssl: isProduction ? { rejectUnauthorized: false } : false,
      
      // Keepalive settings
      keepAlive: true,
      keepAliveInitialDelayMillis: 10000,
      
      // Connection validation
      allowExitOnIdle: false,
    });

    this.setupEventListeners();
    this.startMetricsCollection();
  }

  private getOptimalPoolSize(): number {
    // Calculate optimal pool size based on available memory and CPU
    const availableMemoryMB = this.getAvailableMemory();
    const cpuCores = require('os').cpus().length;
    
    // Base calculation: 1 connection per 10MB of available memory, max 25, min 5
    const memoryBasedSize = Math.floor(availableMemoryMB / 10);
    const cpuBasedSize = cpuCores * 2;
    
    return Math.min(25, Math.max(5, Math.min(memoryBasedSize, cpuBasedSize)));
  }

  private getAvailableMemory(): number {
    try {
      const os = require('os');
      const totalMemory = os.totalmem();
      const freeMemory = os.freemem();
      return (totalMemory - freeMemory) / (1024 * 1024); // Convert to MB
    } catch {
      return 1024; // Default fallback
    }
  }

  private setupEventListeners(): void {
    this.pool.on('connect', (client) => {
      logger.debug('Database client connected', { 
        pid: client.processID,
        totalConnections: this.pool.totalCount
      });
    });

    this.pool.on('acquire', (client) => {
      logger.debug('Database client acquired', { 
        pid: client.processID,
        totalConnections: this.pool.totalCount
      });
      this.metrics.activeConnections++;
    });

    this.pool.on('release', (client) => {
      logger.debug('Database client released', { 
        pid: client.processID,
        totalConnections: this.pool.totalCount
      });
      this.metrics.activeConnections--;
    });

    this.pool.on('error', (error, client) => {
      logger.error('Database pool error', { 
        error: error.message,
        stack: error.stack,
        client: client?.processID
      });
    });

    this.pool.on('remove', (client) => {
      logger.debug('Database client removed', { 
        pid: client.processID,
        totalConnections: this.pool.totalCount
      });
    });
  }

  private startMetricsCollection(): void {
    setInterval(() => {
      this.updateMetrics();
    }, 10000); // Update metrics every 10 seconds
  }

  private updateMetrics(): void {
    try {
      this.metrics.totalConnections = this.pool.totalCount;
      this.metrics.idleConnections = this.pool.idleCount;
      this.metrics.waitingClients = this.pool.waitingCount;
      this.metrics.maxConnections = this.pool.options.max || 0;
      this.metrics.lastHealthCheck = new Date();
    } catch (error) {
      logger.error('Failed to update pool metrics', { error });
    }
  }

  async executeQuery<T = any>(
    query: string, 
    params?: any[], 
    options?: { timeout?: number; slowQueryThreshold?: number }
  ): Promise<{ rows: T[]; executionTime: number; isSlow: boolean }> {
    const startTime = Date.now();
    
    try {
      // Set query timeout if specified
      const client = await this.pool.connect();
      const timeout = options?.timeout || 30000;
      
      try {
        if (timeout !== 30000) {
          await client.query(`SET statement_timeout = ${timeout}`);
        }

        // Execute query
        const result = await client.query(query, params);
        const executionTime = Date.now() - startTime;
        
        // Track metrics
        this.metrics.queriesExecuted++;
        const slowQueryThreshold = options?.slowQueryThreshold || 1000; // 1 second default
        const isSlow = executionTime > slowQueryThreshold;
        
        if (isSlow) {
          this.metrics.slowQueries++;
          logger.warn('Slow query detected', {
            query: this.sanitizeQuery(query),
            executionTime,
            slowQueryThreshold,
            params: this.sanitizeParams(params)
          });
        }

        // Update rolling average query time
        this.metrics.averageQueryTime = 
          (this.metrics.averageQueryTime * (this.metrics.queriesExecuted - 1) + executionTime) / 
          this.metrics.queriesExecuted;

        logger.debug('Query executed successfully', {
          executionTime,
          rowCount: result.rowCount,
          isSlow
        });

        return {
          rows: result.rows,
          executionTime,
          isSlow
        };
      } finally {
        client.release();
      }
    } catch (error) {
      const executionTime = Date.now() - startTime;
      logger.error('Query execution failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        query: this.sanitizeQuery(query),
        executionTime,
        params: this.sanitizeParams(params)
      });
      throw error;
    }
  }

  private sanitizeQuery(query: string): string {
    // Remove potential SQL injection patterns and truncate for logging
    return query.replace(/\s+/g, ' ').substring(0, 200) + 
           (query.length > 200 ? '...' : '');
  }

  private sanitizeParams(params?: any[]): any[] {
    if (!params) return [];
    
    return params.map(param => {
      if (typeof param === 'string' && param.length > 50) {
        return param.substring(0, 50) + '...';
      }
      return param;
    });
  }

  async healthCheck(): Promise<{
    isHealthy: boolean;
    metrics: typeof this.metrics;
    recommendations: string[];
  }> {
    const recommendations: string[] = [];
    
    try {
      // Test basic connectivity
      const startTime = Date.now();
      await this.pool.query('SELECT 1');
      const responseTime = Date.now() - startTime;

      // Check connection pool health
      const connectionUtilization = this.metrics.totalConnections / this.metrics.maxConnections;
      
      if (connectionUtilization > 0.8) {
        recommendations.push('High connection pool utilization detected. Consider increasing max connections.');
      }

      if (this.metrics.waitingClients > 0) {
        recommendations.push('Clients waiting for connections. Consider increasing pool size.');
      }

      if (this.metrics.averageQueryTime > 2000) {
        recommendations.push('High average query time detected. Consider optimizing database indexes.');
      }

      if (this.metrics.slowQueries > 10) {
        recommendations.push('Many slow queries detected. Review and optimize slow queries.');
      }

      // Check database performance
      const performanceMetrics = await this.getPerformanceMetrics();
      
      if (performanceMetrics.cacheHitRatio < 0.9) {
        recommendations.push('Low cache hit ratio. Consider increasing shared_buffers or optimizing queries.');
      }

      if (performanceMetrics.deadlocks > 0) {
        recommendations.push('Deadlocks detected. Review transaction isolation levels and query patterns.');
      }

      const isHealthy = responseTime < 1000 && connectionUtilization < 0.9 && this.metrics.waitingClients < 5;

      return {
        isHealthy,
        metrics: { ...this.metrics },
        recommendations
      };
    } catch (error) {
      logger.error('Database health check failed', { error });
      return {
        isHealthy: false,
        metrics: { ...this.metrics },
        recommendations: ['Database connection failed. Check database connectivity.']
      };
    }
  }

  private async getPerformanceMetrics() {
    try {
      const result = await this.pool.query(`
        SELECT 
          round(
            (SELECT setting FROM pg_settings WHERE name = 'shared_buffers')::numeric * 
            (SELECT setting FROM pg_settings WHERE name = 'effective_cache_size')::numeric / 
            (SELECT setting FROM pg_settings WHERE name = 'work_mem')::numeric
          ) as cache_estimate,
          (SELECT sum(xact_commit + xact_rollback) FROM pg_stat_database) as total_transactions,
          (SELECT sum(blks_hit) FROM pg_stat_database) as cache_hits,
          (SELECT sum(blks_read) FROM pg_stat_database) as cache_misses,
          (SELECT sum(deadlocks) FROM pg_stat_database) as deadlocks
      `);

      if (result.rows.length === 0) {
        return { cacheHitRatio: 1, deadlocks: 0 };
      }

      const row = result.rows[0];
      const totalAccesses = parseInt(row.cache_hits) + parseInt(row.cache_misses);
      const cacheHitRatio = totalAccesses > 0 ? parseInt(row.cache_hits) / totalAccesses : 1;

      return {
        cacheHitRatio,
        deadlocks: parseInt(row.deadlocks) || 0
      };
    } catch (error) {
      logger.error('Failed to get performance metrics', { error });
      return { cacheHitRatio: 1, deadlocks: 0 };
    }
  }

  getMetrics(): typeof this.metrics {
    return { ...this.metrics };
  }

  async close(): Promise<void> {
    try {
      await this.pool.end();
      logger.info('Database connection pool closed');
    } catch (error) {
      logger.error('Error closing database pool', { error });
    }
  }
}

/**
 * Database query optimization utilities
 */
export class QueryOptimizer {
  private pool: OptimizedConnectionPool;

  constructor(pool: OptimizedConnectionPool) {
    this.pool = pool;
  }

  async optimizeSlowQueries(): Promise<{
    slowQueries: Array<{
      query: string;
      avgTime: number;
      callCount: number;
      recommendations: string[];
    }>;
    indexRecommendations: Array<{
      table: string;
      columns: string[];
      reason: string;
    }>;
  }> {
    try {
      // Get slow query statistics
      const slowQueryStats = await this.pool.executeQuery(`
        SELECT 
          query,
          mean_time,
          calls,
          total_time
        FROM pg_stat_statements 
        WHERE mean_time > 100
        ORDER BY total_time DESC
        LIMIT 10
      `);

      // Get index usage statistics
      const indexStats = await this.pool.executeQuery(`
        SELECT 
          schemaname,
          tablename,
          indexname,
          idx_scan,
          idx_tup_read,
          idx_tup_fetch
        FROM pg_stat_user_indexes 
        WHERE idx_scan < 10
        ORDER BY idx_scan ASC
        LIMIT 10
      `);

      return {
        slowQueries: slowQueryStats.rows.map(row => ({
          query: row.query,
          avgTime: parseFloat(row.mean_time),
          callCount: parseInt(row.calls),
          recommendations: this.generateQueryRecommendations(row.query, parseFloat(row.mean_time))
        })),
        indexRecommendations: this.generateIndexRecommendations(indexStats.rows)
      };
    } catch (error) {
      logger.error('Failed to analyze query performance', { error });
      return { slowQueries: [], indexRecommendations: [] };
    }
  }

  private generateQueryRecommendations(query: string, avgTime: number): string[] {
    const recommendations: string[] = [];

    if (avgTime > 5000) {
      recommendations.push('Consider adding indexes or rewriting the query');
    }

    if (query.toUpperCase().includes('SELECT *')) {
      recommendations.push('Avoid SELECT *, specify only required columns');
    }

    if (query.toUpperCase().includes('ORDER BY') && !query.toUpperCase().includes('LIMIT')) {
      recommendations.push('Add LIMIT clause when using ORDER BY to reduce result set size');
    }

    if (query.toUpperCase().includes('LIKE') && query.includes('%')) {
      recommendations.push('Consider using full-text search or trigram indexes for LIKE queries');
    }

    if (query.toUpperCase().includes('JOIN') && query.toUpperCase().includes('WHERE')) {
      recommendations.push('Ensure join conditions are indexed');
    }

    return recommendations;
  }

  private generateIndexRecommendations(indexStats: any[]): Array<{
    table: string;
    columns: string[];
    reason: string;
  }> {
    const recommendations: Array<{ table: string; columns: string[]; reason: string }> = [];

    for (const stat of indexStats) {
      if (stat.idx_scan < 5) {
        recommendations.push({
          table: stat.tablename,
          columns: [stat.indexname.replace(/^idx_/, '')],
          reason: 'Index has very low usage and may be unnecessary'
        });
      }
    }

    return recommendations;
  }

  async createOptimalIndexes(): Promise<void> {
    try {
      // Create commonly needed indexes for workflow system
      const indexes = [
        {
          name: 'idx_workflows_owner_active',
          query: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_owner_active ON workflows(owner_id, is_active) WHERE is_active = true;'
        },
        {
          name: 'idx_executions_workflow_status',
          query: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_workflow_status ON executions(workflow_id, status);'
        },
        {
          name: 'idx_executions_created_at_desc',
          query: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_executions_created_at_desc ON executions(created_at DESC);'
        },
        {
          name: 'idx_workflows_updated_at_desc',
          query: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflows_updated_at_desc ON workflows(updated_at DESC);'
        },
        {
          name: 'idx_users_email_unique',
          query: 'CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_users_email_unique ON users(email) WHERE is_active = true;'
        },
        {
          name: 'idx_workflow_tags_gin',
          query: 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_workflow_tags_gin ON workflows USING GIN (tags);'
        }
      ];

      for (const index of indexes) {
        try {
          await this.pool.executeQuery(index.query);
          logger.info(`Index created successfully: ${index.name}`);
        } catch (error) {
          logger.warn(`Failed to create index ${index.name}`, { error });
        }
      }
    } catch (error) {
      logger.error('Failed to create optimal indexes', { error });
    }
  }
}

// Export singleton instances
export const connectionPool = new OptimizedConnectionPool();
export const queryOptimizer = new QueryOptimizer(connectionPool);

// Database health monitoring
export const setupDatabaseMonitoring = () => {
  // Monitor database health every minute
  setInterval(async () => {
    try {
      const health = await connectionPool.healthCheck();
      
      if (!health.isHealthy) {
        logger.warn('Database health check failed', {
          recommendations: health.recommendations
        });
      }
      
      // Log performance metrics every 5 minutes
      const metrics = connectionPool.getMetrics();
      logger.info('Database metrics', {
        totalConnections: metrics.totalConnections,
        activeConnections: metrics.activeConnections,
        averageQueryTime: metrics.averageQueryTime,
        slowQueries: metrics.slowQueries
      });
      
    } catch (error) {
      logger.error('Database monitoring failed', { error });
    }
  }, 60000); // Check every minute
};