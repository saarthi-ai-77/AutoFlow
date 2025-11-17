"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.pool = exports.databaseService = exports.db = void 0;
const kysely_1 = require("kysely");
const pg_1 = require("pg");
const environment_1 = require("@/config/environment");
const logger_1 = require("@/utils/logger");
// Create database instance
const pool = new pg_1.Pool({
    connectionString: environment_1.env.DATABASE_URL,
    min: 5,
    max: 20,
    idleTimeoutMillis: 60000,
    connectionTimeoutMillis: 2000,
    query_timeout: 30000, // 30 seconds statement timeout
    statement_timeout: 30000, // 30 seconds statement timeout
});
exports.pool = pool;
exports.db = new kysely_1.Kysely({
    dialect: new kysely_1.PostgresDialect({ pool }),
});
// Database utilities
exports.databaseService = {
    async query(query, params) {
        try {
            const result = await exports.db.executeQuery(query, params);
            return result.rows;
        }
        catch (error) {
            logger_1.logger.error('Database query error', { error, query, params });
            throw error;
        }
    },
    async transaction(fn) {
        try {
            return await exports.db.transaction().execute(fn);
        }
        catch (error) {
            logger_1.logger.error('Database transaction error', { error });
            throw error;
        }
    },
    async healthCheck() {
        try {
            await exports.db.selectFrom('users').select('id').limit(1).execute();
            return true;
        }
        catch (error) {
            logger_1.logger.error('Database health check failed', { error });
            return false;
        }
    },
    async close() {
        try {
            await exports.db.destroy();
            await pool.end();
            logger_1.logger.info('Database connection closed');
        }
        catch (error) {
            logger_1.logger.error('Error closing database connection', { error });
        }
    },
};
// Handle graceful shutdown
process.on('SIGINT', async () => {
    logger_1.logger.info('Received SIGINT, closing database connections...');
    await exports.databaseService.close();
    process.exit(0);
});
process.on('SIGTERM', async () => {
    logger_1.logger.info('Received SIGTERM, closing database connections...');
    await exports.databaseService.close();
    process.exit(0);
});
//# sourceMappingURL=connection.js.map