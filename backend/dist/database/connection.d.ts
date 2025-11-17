import { Kysely } from 'kysely';
import { Pool } from 'pg';
export interface Database {
    users: UserTable;
    workflows: WorkflowTable;
    executions: ExecutionTable;
    api_keys: ApiKeyTable;
    refresh_tokens: RefreshTokenTable;
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
    email_verified: boolean;
    failed_login_attempts: number;
    last_failed_login_at?: Date;
    token_version: number;
}
export interface WorkflowTable {
    id: string;
    name: string;
    description?: string;
    graph: any;
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
    trigger_data: any;
    status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
    started_at?: Date;
    completed_at?: Date;
    error_message?: string;
    execution_time_ms?: number;
    node_executions: any;
    created_at: Date;
    updated_at: Date;
}
export interface ApiKeyTable {
    id: string;
    user_id: string;
    name: string;
    key_hash: string;
    scopes: string[];
    last_used_at?: Date;
    expires_at?: Date;
    created_at: Date;
    updated_at: Date;
    is_active: boolean;
}
export interface RefreshTokenTable {
    id: string;
    user_id: string;
    token_hash: string;
    token_id: string;
    is_used: boolean;
    expires_at: Date;
    created_at: Date;
    used_at?: Date;
}
declare const pool: Pool;
export declare const db: Kysely<Database>;
export declare const databaseService: {
    query<T = any>(query: string, params?: any[]): Promise<T[]>;
    transaction<T>(fn: (trx: Kysely<Database>) => Promise<T>): Promise<T>;
    healthCheck(): Promise<boolean>;
    close(): Promise<void>;
};
export { pool };
//# sourceMappingURL=connection.d.ts.map