import { Kysely, PostgresDialect } from 'kysely';
import { Pool } from 'pg';
import { env } from '@/config/environment';
import { logger } from '@/utils/logger';

// Database interface definition
export interface Database {
  users: UserTable;
  workflows: WorkflowTable;
  executions: ExecutionTable;
  api_keys: ApiKeyTable;
}

export interface UserTable {
  id: string;
  email: string;
  password_hash: string;
  role: 'user' | 'admin';
  first_name?: string;
  last_name?: string;
  created_at: Date;
  updated_at: Date;
  last_login_at?: Date;
  is_active: boolean;
}

export interface WorkflowTable {
  id: string;
  name: string;
  description?: string;
  graph: any; // JSONB - workflow graph definition
  version: number;
  owner_id: string;
  is_active: boolean;
  is_public: boolean;
  tags: string[];
  execution_count: number;
  last_executed_at?: Date;
  avg_execution_time_ms?: number;
  created_at: Date;
  updated_at: Date;
}

export interface ExecutionTable {
  id: string;
  workflow_id: string;
  trigger_data: any; // JSONB
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  started_at?: Date;
  completed_at?: Date;
  error_message?: string;
  execution_time_ms?: number;
  node_executions: any; // JSONB - detailed node execution results
  created_at: Date;
  updated_at: Date;
}

export interface ApiKeyTable {
  id: string;
  user_id: string;
  name: string;
  key_hash: string;
  scopes: string[]; // ['read:workflows', 'write:executions', etc.]
  last_used_at?: Date;
  expires_at?: Date;
  created_at: Date;
  updated_at: Date;
  is_active: boolean;
}

// Create database instance
const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 60000,
  connectionTimeoutMillis: 2000,
});

export const db = new Kysely<Database>({
  dialect: new PostgresDialect({ pool }),
});

// Database utilities
export const databaseService = {
  async query<T = any>(query: string, params?: any[]): Promise<T[]> {
    try {
      const result = await db.executeQuery(query, params);
      return result.rows as T[];
    } catch (error) {
      logger.error('Database query error', { error, query, params });
      throw error;
    }
  },

  async transaction<T>(fn: (trx: Kysely<Database>) => Promise<T>): Promise<T> {
    try {
      return await db.transaction().execute(fn);
    } catch (error) {
      logger.error('Database transaction error', { error });
      throw error;
    }
  },

  async healthCheck(): Promise<boolean> {
    try {
      await db.selectFrom('users').select('id').limit(1).execute();
      return true;
    } catch (error) {
      logger.error('Database health check failed', { error });
      return false;
    }
  },

  async close(): Promise<void> {
    try {
      await db.destroy();
      await pool.end();
      logger.info('Database connection closed');
    } catch (error) {
      logger.error('Error closing database connection', { error });
    }
  },
};

// Handle graceful shutdown
process.on('SIGINT', async () => {
  logger.info('Received SIGINT, closing database connections...');
  await databaseService.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  logger.info('Received SIGTERM, closing database connections...');
  await databaseService.close();
  process.exit(0);
});

export { pool };