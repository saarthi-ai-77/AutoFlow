/// <reference types="node" />

import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { env } from '@/config/environment';
import { logger } from '@/utils/logger';
import { databaseService } from '@/database/connection';
import { migrationManager } from '@/database/migrate';
import { executionQueue } from '@/services/execution';
import Redis from 'ioredis';
import {
  requestLogger,
  securityHeaders,
  errorHandler,
  notFoundHandler,
  corsMiddleware,
  corsOriginValidator,
  helmetMiddleware,
  compressionMiddleware,
  generalRateLimiter,
  authRateLimiter
} from '@/api/middleware/security';
import { authenticate } from '@/api/middleware/auth';
import { authRoutes } from '@/api/routes/auth';
import { workflowRoutes } from '@/api/routes/workflows';
import { executionRoutes } from '@/api/routes/executions';
import { websocketSecurityService } from '@/websocket';

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
        url: env.NODE_ENV === 'production' 
          ? 'https://api.autoflow.dev' 
          : `http://localhost:${env.PORT}`,
        description: env.NODE_ENV === 'production' ? 'Production server' : 'Development server',
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

const swaggerSpec = swaggerJSDoc(swaggerOptions);

// Create Express application
const app = express();
const server = createServer(app);

// Create Redis instance for health checks
const redis = new Redis(env.REDIS_URL, {
  lazyConnect: true,
  maxRetriesPerRequest: 3,
});

// Create Socket.IO server
const io = new Server(server, {
  cors: {
    origin: corsOriginValidator,
    credentials: true,
    methods: ['GET', 'POST']
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Comprehensive health check endpoint
app.get('/api/health', async (req: Request, res: Response) => {
  try {
    // Check PostgreSQL connectivity
    const dbHealthy = await databaseService.healthCheck();

    // Check Redis connectivity
    let redisHealthy = false;
    try {
      await redis.ping();
      redisHealthy = true;
    } catch (error) {
      logger.warn('Redis health check failed', { error });
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

    logger.info('Deep health check completed', {
      overallHealthy,
      services
    });
  } catch (error) {
    logger.error('Health check failed', { error });
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
    });
  }
});

// Readiness probe endpoint
app.get('/api/ready', (req: Request, res: Response) => {
  // Simple check if server is listening
  res.status(200).json({
    status: 'ready',
    timestamp: new Date().toISOString(),
  });
});

// Liveness probe endpoint
app.get('/api/live', (req: Request, res: Response) => {
  // Always return 200 if process is alive
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
  });
});

// Basic middleware (no auth required)
app.use(securityHeaders);
app.use(corsMiddleware);
app.use(helmetMiddleware);
app.use(compressionMiddleware);
app.use(requestLogger);

// Rate limiting for general API routes
app.use('/api', generalRateLimiter);

// More strict rate limiting for auth routes
app.use('/api/auth', authRateLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Swagger documentation
if (env.NODE_ENV !== 'production') {
  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    explorer: true,
    customCss: '.swagger-ui .topbar { display: none }',
    customSiteTitle: 'AutoFlow API Documentation',
  }));
}

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/workflows', workflowRoutes);
app.use('/api/executions', executionRoutes);

// API info endpoint
app.get('/api', (req: Request, res: Response) => {
  res.json({
    message: 'AutoFlow Backend API',
    version: '1.0.0',
    documentation: env.NODE_ENV !== 'production' ? '/api/docs' : null,
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
app.use(notFoundHandler);
app.use(errorHandler);

// Initialize WebSocket service
websocketSecurityService.initialize(io);

// Graceful shutdown handling
const gracefulShutdown = async (signal: string) => {
  logger.info(`Received ${signal}, starting graceful shutdown...`);
  
  try {
    // Stop accepting new connections
    server.close(() => {
      logger.info('HTTP server closed');
    });
    
    // Close Socket.IO connections
    io.close(() => {
      logger.info('Socket.IO server closed');
    });
    
    // Close database connections
    await databaseService.close();
    
    // Close queue connections
    await executionQueue.close();
    
    logger.info('Graceful shutdown completed');
    process.exit(0);
  } catch (error) {
    logger.error('Error during graceful shutdown', { error });
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const startServer = async () => {
  try {
    // Run database migrations
    logger.info('Running database migrations...');
    await migrationManager.migrate();
    logger.info('Database migrations completed');

    // Start server
    const port = env.PORT;
    server.listen(port, () => {
      logger.info(`🚀 AutoFlow Backend server started on port ${port}`);
      logger.info(`📚 API Documentation available at http://localhost:${port}/api/docs (dev only)`);
      logger.info(`🏥 Health check available at http://localhost:${port}/health`);
      
      if (env.NODE_ENV === 'development') {
        logger.info('🌍 Environment: Development');
      } else if (env.NODE_ENV === 'production') {
        logger.info('🌍 Environment: Production');
      }
    });
  } catch (error) {
    logger.error('Failed to start server', { error });
    process.exit(1);
  }
};

// Start the server
startServer();

export { app, server, io };