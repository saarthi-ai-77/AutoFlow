interface Migration {
    version: string;
    name: string;
    up: string;
    down?: string;
}
declare class MigrationManager {
    private tableName;
    ensureMigrationTable(): Promise<void>;
    getAppliedMigrations(): Promise<string[]>;
    applyMigration(migration: Migration): Promise<void>;
    migrate(): Promise<void>;
    rollbackMigration(version: string): Promise<void>;
}
export declare const migrationManager: MigrationManager;
export {};
//# sourceMappingURL=migrate.d.ts.map