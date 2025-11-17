"use strict";
/// <reference types="node" />
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.io = exports.server = exports.app = void 0;
const express_1 = __importDefault(require("express"));
const http_1 = require("http");
const socket_io_1 = require("socket.io");
const swagger_jsdoc_1 = __importDefault(require("swagger-jsdoc"));
const swagger_ui_express_1 = __importDefault(require("swagger-ui-express"));
const environment_1 = require("@/config/environment");
const logger_1 = require("@/utils/logger");
const connection_1 = require("@/database/connection");
const migrate_1 = require("@/database/migrate");
const execution_1 = require("@/services/execution");
const ioredis_1 = __importDefault(require("ioredis"));
const security_1 = require("@/api/middleware/security");
const auth_1 = require("@/api/routes/auth");
const workflows_1 = require("@/api/routes/workflows");
const executions_1 = require("@/api/routes/executions");
const websocket_1 = require("@/websocket");
// Swagger configuration
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'AutoFlow Backend API',
            version: '1.0.0',
            description: 'Production-ready Node.js backend for AutoFlow Studio automation tool',
            contact: {
                name: 'AutoFlow Team',
                email: 'support@autoflow.dev',
            },
        },
        servers: [
            {
                url: environment_1.env.NODE_ENV === 'production'
                    ? 'https://api.autoflow.dev'
                    : `http://localhost:${environment_1.env.PORT}`,
                description: environment_1.env.NODE_ENV === 'production' ? 'Production server' : 'Development server',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
        },
        security: [
            {
                bearerAuth: [],
            },
        ],
    },
    apis: ['./src/api/routes/*.ts', './src/services/*.ts'],
};
const swaggerSpec = (0, swagger_jsdoc_1.default)(swaggerOptions);
// Create Express application
const app = (0, express_1.default)();
exports.app = app;
const server = (0, http_1.createServer)(app);
exports.server = server;
// Create Redis instance for health checks
const redis = new ioredis_1.default(environment_1.env.REDIS_URL, {
    lazyConnect: true,
    maxRetriesPerRequest: 3,
});
// Create Socket.IO server
const io = new socket_io_1.Server(server, {
    cors: {
        origin: security_1.corsOriginValidator,
        credentials: true,
        methods: ['GET', 'POST']
    },
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000,
});
exports.io = io;
// Comprehensive health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Check PostgreSQL connectivity
        const dbHealthy = await connection_1.databaseService.healthCheck();
        // Check Redis connectivity
        let redisHealthy = false;
        try {
            await redis.ping();
            redisHealthy = true;
        }
        catch (error) {
            logger_1.logger.warn('Redis health check failed', { error });
        }
        // Check WebSocket server status
        const wsHealthy = io && io.sockets && io.sockets.sockets.size >= 0;
        // Check disk space (simplified - in production use system calls)
        const diskHealthy = true; // Placeholder - implement actual disk check
        const services = {
            database: dbHealthy ? 'healthy' : 'unhealthy',
            redis: redisHealthy ? 'healthy' : 'unhealthy',
            websocket: wsHealthy ? 'healthy' : 'unhealthy',
            disk: diskHealthy ? 'healthy' : 'warning',
        };
        const overallHealthy = dbHealthy && redisHealthy && wsHealthy;
        const healthStatus = {
            status: overallHealthy ? 'healthy' : 'unhealthy',
            timestamp: new Date().toISOString(),
            uptime: Math.floor(process.uptime()),
            version: '1.0.0',
            services,
            memory: process.memoryUsage(),
            activeConnections: io ? io.sockets.sockets.size : 0,
        };
        res.status(overallHealthy ? 200 : 503).json(healthStatus);
        logger_1.logger.info('Deep health check completed', {
            overallHealthy,
            services
        });
    }
    catch (error) {
        logger_1.logger.error('Health check failed', { error });
        res.status(503).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            error: 'Health check failed',
        });
    }
});
// Readiness probe endpoint
app.get('/api/ready', (req, res) => {
    // Simple check if server is listening
    res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString(),
    });
});
// Liveness probe endpoint
app.get('/api/live', (req, res) => {
    // Always return 200 if process is alive
    res.status(200).json({
        status: 'alive',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
    });
});
// Basic middleware (no auth required)
app.use(security_1.securityHeaders);
app.use(security_1.corsMiddleware);
app.use(security_1.helmetMiddleware);
app.use(security_1.compressionMiddleware);
app.use(security_1.requestLogger);
// Rate limiting for general API routes
app.use('/api', security_1.generalRateLimiter);
// More strict rate limiting for auth routes
app.use('/api/auth', security_1.authRateLimiter);
// Body parsing middleware
app.use(express_1.default.json({ limit: '10mb' }));
app.use(express_1.default.urlencoded({ extended: true, limit: '10mb' }));
// Swagger documentation
if (environment_1.env.NODE_ENV !== 'production') {
    app.use('/api/docs', swagger_ui_express_1.default.serve, swagger_ui_express_1.default.setup(swaggerSpec, {
        explorer: true,
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: 'AutoFlow API Documentation',
    }));
}
// API routes
app.use('/api/auth', auth_1.authRoutes);
app.use('/api/workflows', workflows_1.workflowRoutes);
app.use('/api/executions', executions_1.executionRoutes);
// API info endpoint
app.get('/api', (req, res) => {
    res.json({
        message: 'AutoFlow Backend API',
        version: '1.0.0',
        documentation: environment_1.env.NODE_ENV !== 'production' ? '/api/docs' : null,
        endpoints: [
            'POST /api/auth/register',
            'POST /api/auth/login',
            'POST /api/auth/refresh',
            'GET /api/auth/me',
            'POST /api/auth/logout',
            'GET /api/workflows',
            'POST /api/workflows',
            'GET /api/workflows/:id',
            'PUT /api/workflows/:id',
            'DELETE /api/workflows/:id',
            'POST /api/workflows/:id/execute',
            'GET /api/executions',
            'GET /api/executions/:id',
            'GET /api/executions/:id/logs',
            'POST /api/executions/:id/retry',
            'POST /api/executions/:id/cancel',
            'GET /health'
        ],
    });
});
// Error handlers
app.use(security_1.notFoundHandler);
app.use(security_1.errorHandler);
// Initialize WebSocket service
websocket_1.websocketSecurityService.initialize(io);
// Graceful shutdown handling
const gracefulShutdown = async (signal) => {
    logger_1.logger.info(`Received ${signal}, starting graceful shutdown...`);
    try {
        // Stop accepting new connections
        server.close(() => {
            logger_1.logger.info('HTTP server closed');
        });
        // Close Socket.IO connections
        io.close(() => {
            logger_1.logger.info('Socket.IO server closed');
        });
        // Close database connections
        await connection_1.databaseService.close();
        // Close queue connections
        await execution_1.executionQueue.close();
        logger_1.logger.info('Graceful shutdown completed');
        process.exit(0);
    }
    catch (error) {
        logger_1.logger.error('Error during graceful shutdown', { error });
        process.exit(1);
    }
};
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
// Start server
const startServer = async () => {
    try {
        // Run database migrations
        logger_1.logger.info('Running database migrations...');
        await migrate_1.migrationManager.migrate();
        logger_1.logger.info('Database migrations completed');
        // Start server
        const port = environment_1.env.PORT;
        server.listen(port, () => {
            logger_1.logger.info(`🚀 AutoFlow Backend server started on port ${port}`);
            logger_1.logger.info(`📚 API Documentation available at http://localhost:${port}/api/docs (dev only)`);
            logger_1.logger.info(`🏥 Health check available at http://localhost:${port}/health`);
            if (environment_1.env.NODE_ENV === 'development') {
                logger_1.logger.info('🌍 Environment: Development');
            }
            else if (environment_1.env.NODE_ENV === 'production') {
                logger_1.logger.info('🌍 Environment: Production');
            }
        });
    }
    catch (error) {
        logger_1.logger.error('Failed to start server', { error });
        process.exit(1);
    }
};
// Start the server
startServer();
//# sourceMappingURL=server.js.map