import { pool } from './connection';
import { logger } from '@/utils/logger';

// Migration definitions
interface Migration {
  version: string;
  name: string;
  up: string;
  down?: string;
}

const migrations: Migration[] = [
  {
    version: '001_initial_schema',
    name: 'Create initial database schema',
    up: `
      -- Enable UUID extension
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      
      -- Users table
      CREATE TABLE users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_login_at TIMESTAMP WITH TIME ZONE,
        is_active BOOLEAN DEFAULT true
      );
      
      -- Workflows table
      CREATE TABLE workflows (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(255) NOT NULL,
        description TEXT,
        graph JSONB NOT NULL,
        version INTEGER DEFAULT 1,
        owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
        is_active BOOLEAN DEFAULT true,
        is_public BOOLEAN DEFAULT false,
        tags TEXT[] DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
      
      -- Executions table
      CREATE TABLE executions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        workflow_id UUID REFERENCES workflows(id) ON DELETE CASCADE,
        trigger_data JSONB,
        status VARCHAR(20) DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
        started_at TIMESTAMP WITH TIME ZONE,
        completed_at TIMESTAMP WITH TIME ZONE,
        error_message TEXT,
        execution_time_ms INTEGER,
        node_executions JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
      
      -- API Keys table
      CREATE TABLE api_keys (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        key_hash VARCHAR(255) NOT NULL UNIQUE,
        scopes TEXT[] NOT NULL DEFAULT '{}',
        last_used_at TIMESTAMP WITH TIME ZONE,
        expires_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        is_active BOOLEAN DEFAULT true
      );
      
      -- Create indexes for performance
      CREATE INDEX idx_workflows_owner_id ON workflows(owner_id);
      CREATE INDEX idx_workflows_active ON workflows(is_active) WHERE is_active = true;
      CREATE INDEX idx_workflows_created_at ON workflows(created_at DESC);
      CREATE INDEX idx_executions_workflow_id ON executions(workflow_id);
      CREATE INDEX idx_executions_status ON executions(status);
      CREATE INDEX idx_executions_created_at ON executions(created_at DESC);
      CREATE INDEX idx_users_email ON users(email);
      CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
      CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

      -- Composite indexes for common query patterns
      CREATE INDEX idx_executions_workflow_created ON executions(workflow_id, created_at DESC);
      CREATE INDEX idx_executions_status_created ON executions(status, created_at DESC);

      -- Create GIN indexes for JSONB columns
      CREATE INDEX idx_workflows_graph ON workflows USING GIN (graph);
      CREATE INDEX idx_executions_trigger_data ON executions USING GIN (trigger_data);
      CREATE INDEX idx_executions_node_executions ON executions USING GIN (node_executions);
      
      -- Updated_at trigger function
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ language 'plpgsql';
      
      -- Apply triggers to all tables
      CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
      
      CREATE TRIGGER update_workflows_updated_at BEFORE UPDATE ON workflows
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
      
      CREATE TRIGGER update_executions_updated_at BEFORE UPDATE ON executions
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
      
      CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    `
  },
  {
    version: '002_add_workflow_metrics',
    name: 'Add workflow execution metrics',
    up: `
      -- Add execution metrics to workflows
      ALTER TABLE workflows ADD COLUMN execution_count INTEGER DEFAULT 0;
      ALTER TABLE workflows ADD COLUMN last_executed_at TIMESTAMP WITH TIME ZONE;
      ALTER TABLE workflows ADD COLUMN avg_execution_time_ms INTEGER;

      -- Create index on workflow execution metrics
      CREATE INDEX idx_workflows_execution_metrics ON workflows(execution_count, last_executed_at);
    `
  },
  {
    version: '003_add_security_fields',
    name: 'Add security fields to users table',
    up: `
      -- Add security fields to users table
      ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT false;
      ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
      ALTER TABLE users ADD COLUMN last_failed_login_at TIMESTAMP WITH TIME ZONE;
      ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1;

      -- Create refresh tokens table for token rotation
      CREATE TABLE refresh_tokens (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL UNIQUE,
        token_id VARCHAR(255) NOT NULL,
        is_used BOOLEAN DEFAULT false,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        used_at TIMESTAMP WITH TIME ZONE
      );

      -- Create indexes for refresh tokens
      CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
      CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
      CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

      -- Apply trigger to refresh_tokens
      CREATE TRIGGER update_refresh_tokens_updated_at BEFORE UPDATE ON refresh_tokens
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    `
  }
];

class MigrationManager {
  private tableName = 'migration_history';

  async ensureMigrationTable(): Promise<void> {
    const query = `
      CREATE TABLE IF NOT EXISTS ${this.tableName} (
        version VARCHAR(50) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `;
    
    await pool.query(query);
    logger.info('Migration history table ensured');
  }

  async getAppliedMigrations(): Promise<string[]> {
    const query = `SELECT version FROM ${this.tableName} ORDER BY version;`;
    const result = await pool.query(query);
    return result.rows.map((row: any) => row.version);
  }

  async applyMigration(migration: Migration): Promise<void> {
    try {
      await pool.query('BEGIN');
      
      // Execute migration
      await pool.query(migration.up);
      
      // Record migration as applied
      const insertQuery = `
        INSERT INTO ${this.tableName} (version, name)
        VALUES ($1, $2)
      `;
      await pool.query(insertQuery, [migration.version, migration.name]);
      
      await pool.query('COMMIT');
      logger.info(`Applied migration: ${migration.version} - ${migration.name}`);
    } catch (error) {
      await pool.query('ROLLBACK');
      logger.error(`Failed to apply migration: ${migration.version}`, { error });
      throw error;
    }
  }

  async migrate(): Promise<void> {
    try {
      await this.ensureMigrationTable();
      const appliedMigrations = await this.getAppliedMigrations();
      
      const pendingMigrations = migrations.filter(
        migration => !appliedMigrations.includes(migration.version)
      );

      if (pendingMigrations.length === 0) {
        logger.info('No pending migrations');
        return;
      }

      logger.info(`Found ${pendingMigrations.length} pending migrations`);

      for (const migration of pendingMigrations) {
        await this.applyMigration(migration);
      }

      logger.info('All migrations applied successfully');
    } catch (error) {
      logger.error('Migration failed', { error });
      throw error;
    }
  }

  async rollbackMigration(version: string): Promise<void> {
    const migration = migrations.find(m => m.version === version);
    if (!migration) {
      throw new Error(`Migration not found: ${version}`);
    }

    if (!migration.down) {
      throw new Error(`No rollback script for migration: ${version}`);
    }

    try {
      await pool.query('BEGIN');
      
      // Execute rollback
      await pool.query(migration.down);
      
      // Remove from migration history
      const deleteQuery = `DELETE FROM ${this.tableName} WHERE version = $1`;
      await pool.query(deleteQuery, [version]);
      
      await pool.query('COMMIT');
      logger.info(`Rolled back migration: ${version}`);
    } catch (error) {
      await pool.query('ROLLBACK');
      logger.error(`Failed to rollback migration: ${version}`, { error });
      throw error;
    }
  }
}

export const migrationManager = new MigrationManager();

if (require.main === module) {
  // Run migrations if called directly
  migrationManager.migrate()
    .then(() => {
      logger.info('Migrations completed successfully');
      process.exit(0);
    })
    .catch(error => {
      logger.error('Migration failed', { error });
      process.exit(1);
    });
}