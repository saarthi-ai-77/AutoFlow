import { Server, Socket } from 'socket.io';
import { logger } from '@/utils/logger';
import jwt from 'jsonwebtoken';
import { jwtConfig, isProduction } from '@/config/environment';
import { authService } from '@/services/auth';
import { db } from '@/database/connection';
import { UUIDSchema } from '@/utils/security';

interface AuthenticatedSocket extends Socket {
  userId: string;
  userRole: string;
  tokenVersion: number;
  socketId: string;
  connectedAt: Date;
  lastActivity: Date;
  subscriptionPermissions: Set<string>;
}

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

class WebSocketSecurityService {
  private io: Server | null = null;
  private connectedUsers: Map<string, AuthenticatedSocket> = new Map();
  private connectionRateLimits: Map<string, RateLimitEntry> = new Map();
  private messageRateLimits: Map<string, RateLimitEntry> = new Map();
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private readonly maxConnectionsPerIP = 10;
  private readonly maxConnectionsPerUser = 5;
  private readonly connectionRateLimitWindow = 60000; // 1 minute
  private readonly messageRateLimitWindow = 30000; // 30 seconds
  private readonly maxMessagesPerWindow = 100;
  private readonly heartbeatIntervalMs = 30000; // 30 seconds
  private readonly connectionTimeoutMs = 300000; // 5 minutes

  initialize(io: Server): void {
    this.io = io;
    
    // Enhanced authentication middleware with comprehensive security checks
    io.use(async (socket, next) => {
      try {
        await this.authenticateSocket(socket, next);
      } catch (error) {
        logger.warn('WebSocket authentication failed', { 
          error: error instanceof Error ? error.message : 'Unknown error',
          socketId: socket.id,
          ip: this.getClientIP(socket)
        });
        next(new Error('Authentication failed'));
      }
    });

    io.on('connection', (socket) => {
      this.handleSecureConnection(socket as AuthenticatedSocket);
    });

    // Start heartbeat monitoring
    this.startHeartbeat();

    logger.info('WebSocket security service initialized');
  }

  private async authenticateSocket(socket: Socket, next: (err?: Error) => void): Promise<void> {
    const clientIP = this.getClientIP(socket);
    const token = socket.handshake.auth.token || 
                  socket.handshake.headers.authorization?.replace('Bearer ', '');

    // Basic security checks
    if (!token) {
      return next(new Error('Authentication token required'));
    }

    // Rate limiting by IP
    if (this.isRateLimited(clientIP, 'connection')) {
      return next(new Error('Connection rate limit exceeded'));
    }

    // Check if IP has too many concurrent connections
    const ipConnectionCount = this.getIPConnectionCount(clientIP);
    if (ipConnectionCount >= this.maxConnectionsPerIP) {
      logger.warn('Too many connections from IP', { 
        ip: clientIP, 
        connections: ipConnectionCount 
      });
      return next(new Error('Too many connections from this IP'));
    }

    try {
      // Enhanced JWT verification with token version checking
      const payload = jwt.verify(token, jwtConfig.secret) as any;
      if (!payload || !payload.userId) {
        return next(new Error('Invalid token format'));
      }

      // Verify user still exists and is active using auth service
      const user = await authService.getUserById(payload.userId);
      if (!user) {
        return next(new Error('User not found or inactive'));
      }

      // Verify token version hasn't been invalidated
      const tokenValid = await authService.verifyToken(token);
      if (!tokenValid) {
        return next(new Error('Token has been invalidated'));
      }

      // Attach enhanced user info to socket
      (socket as any).userId = payload.userId;
      (socket as any).userRole = payload.role;
      (socket as any).tokenVersion = payload.version;
      (socket as any).socketId = socket.id;
      (socket as any).connectedAt = new Date();
      (socket as any).lastActivity = new Date();
      (socket as any).subscriptionPermissions = new Set();

      // Record successful authentication
      this.recordConnection(clientIP);

      logger.info('WebSocket authenticated successfully', { 
        userId: payload.userId, 
        socketId: socket.id,
        ip: clientIP,
        userAgent: socket.handshake.headers['user-agent']
      });

      next();
    } catch (error) {
      logger.error('JWT verification failed', { 
        error: error instanceof Error ? error.message : 'Unknown error',
        tokenPreview: token ? token.substring(0, 20) + '...' : 'none'
      });
      return next(new Error('Token verification failed'));
    }
  }

  private handleSecureConnection(socket: AuthenticatedSocket): void {
    const userId = socket.userId;
    const socketId = socket.id;

    // Check user connection limits
    const userConnectionCount = this.getUserConnectionCount(userId);
    if (userConnectionCount >= this.maxConnectionsPerUser) {
      logger.warn('User exceeded connection limit', { 
        userId, 
        connections: userConnectionCount 
      });
      socket.emit('error', { 
        code: 'CONNECTION_LIMIT_EXCEEDED',
        message: 'Too many connections for this user'
      });
      socket.disconnect(true);
      return;
    }

    // Store connected user with enhanced tracking
    this.connectedUsers.set(socketId, socket);

    logger.info('User connected via secure WebSocket', { 
      userId, 
      socketId,
      ip: this.getClientIP(socket),
      totalConnections: this.connectedUsers.size
    });

    // Set up connection timeout
    const timeoutId = setTimeout(() => {
      if (socket.connected) {
        logger.warn('WebSocket connection timeout', { userId, socketId });
        socket.emit('error', { 
          code: 'CONNECTION_TIMEOUT',
          message: 'Connection timeout'
        });
        socket.disconnect(true);
      }
    }, this.connectionTimeoutMs);

    // Clear timeout on disconnect
    socket.on('disconnect', () => {
      clearTimeout(timeoutId);
    });

    // Enhanced subscription handlers with authorization
    this.setupSecureEventHandlers(socket);

    // Send connection success with security info
    socket.emit('connected', {
      message: 'Securely connected to AutoFlow WebSocket',
      userId,
      socketId,
      timestamp: new Date().toISOString(),
      securityLevel: 'high'
    });

    // Track activity for heartbeat
    this.trackActivity(socket);
  }

  private setupSecureEventHandlers(socket: AuthenticatedSocket): void {
    const userId = socket.userId;

    // Heartbeat handler
    socket.on('pong', () => {
      socket.lastActivity = new Date();
      logger.debug('Received pong from client', { userId, socketId: socket.id });
    });

    // Secure workflow subscription with authorization
    socket.on('subscribe-workflow', async (workflowId: string) => {
      try {
        // Rate limiting for subscription attempts
        if (this.isRateLimited(socket.id, 'message')) {
          socket.emit('error', { 
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many subscription attempts'
          });
          return;
        }

        // Validate workflow ID
        UUIDSchema.parse(workflowId);

        // Check user authorization for this workflow
        const hasPermission = await this.checkWorkflowAccess(userId, workflowId, 'read');
        if (!hasPermission) {
          logger.warn('Unauthorized workflow subscription attempt', { 
            userId, 
            workflowId, 
            socketId: socket.id 
          });
          socket.emit('error', { 
            code: 'UNAUTHORIZED',
            message: 'Access denied to workflow'
          });
          return;
        }

        // Add to workflow room
        socket.join(`workflow-${workflowId}`);
        socket.subscriptionPermissions.add(`workflow-${workflowId}`);
        
        logger.debug('User subscribed to workflow', { userId, workflowId, socketId: socket.id });
        socket.emit('subscribed', { type: 'workflow', id: workflowId });

      } catch (error) {
        logger.error('Workflow subscription error', { 
          error: error instanceof Error ? error.message : 'Unknown error',
          userId, 
          workflowId 
        });
        socket.emit('error', { 
          code: 'SUBSCRIPTION_FAILED',
          message: 'Failed to subscribe to workflow'
        });
      }
    });

    socket.on('unsubscribe-workflow', (workflowId: string) => {
      try {
        socket.leave(`workflow-${workflowId}`);
        socket.subscriptionPermissions.delete(`workflow-${workflowId}`);
        logger.debug('User unsubscribed from workflow', { userId, workflowId, socketId: socket.id });
        socket.emit('unsubscribed', { type: 'workflow', id: workflowId });
      } catch (error) {
        logger.error('Workflow unsubscription error', { error, userId, workflowId });
      }
    });

    // Secure execution subscription
    socket.on('subscribe-execution', async (executionId: string) => {
      try {
        if (this.isRateLimited(socket.id, 'message')) {
          socket.emit('error', { 
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many subscription attempts'
          });
          return;
        }

        UUIDSchema.parse(executionId);

        // Check execution access through workflow ownership
        const hasPermission = await this.checkExecutionAccess(userId, executionId, 'read');
        if (!hasPermission) {
          logger.warn('Unauthorized execution subscription attempt', { 
            userId, 
            executionId, 
            socketId: socket.id 
          });
          socket.emit('error', { 
            code: 'UNAUTHORIZED',
            message: 'Access denied to execution'
          });
          return;
        }

        socket.join(`execution-${executionId}`);
        socket.subscriptionPermissions.add(`execution-${executionId}`);
        
        logger.debug('User subscribed to execution', { userId, executionId, socketId: socket.id });
        socket.emit('subscribed', { type: 'execution', id: executionId });

      } catch (error) {
        logger.error('Execution subscription error', { 
          error: error instanceof Error ? error.message : 'Unknown error',
          userId, 
          executionId 
        });
        socket.emit('error', { 
          code: 'SUBSCRIPTION_FAILED',
          message: 'Failed to subscribe to execution'
        });
      }
    });

    socket.on('unsubscribe-execution', (executionId: string) => {
      try {
        socket.leave(`execution-${executionId}`);
        socket.subscriptionPermissions.delete(`execution-${executionId}`);
        logger.debug('User unsubscribed from execution', { userId, executionId, socketId: socket.id });
        socket.emit('unsubscribed', { type: 'execution', id: executionId });
      } catch (error) {
        logger.error('Execution unsubscription error', { error, userId, executionId });
      }
    });

    // Secure ping handler
    socket.on('ping', () => {
      socket.lastActivity = new Date();
      socket.emit('pong', { timestamp: Date.now() });
    });

    // Handle disconnect with cleanup
    socket.on('disconnect', (reason) => {
      logger.info('User disconnected from secure WebSocket', { 
        userId, 
        socketId: socket.id, 
        reason,
        duration: Date.now() - socket.connectedAt.getTime()
      });
      this.connectedUsers.delete(socket.id);
      this.cleanupRateLimits(socket.id);
    });
  }

  // Authorization helpers
  private async checkWorkflowAccess(userId: string, workflowId: string, action: 'read' | 'write'): Promise<boolean> {
    try {
      const workflow = await db
        .selectFrom('workflows')
        .select(['owner_id', 'is_public'])
        .where('id', '=', workflowId)
        .where('is_active', '=', true)
        .executeTakeFirst();

      if (!workflow) {
        return false;
      }

      // Owner can always access
      if (workflow.owner_id === userId) {
        return true;
      }

      // Public workflows allow read access
      if (action === 'read' && workflow.is_public) {
        return true;
      }

      return false;
    } catch (error) {
      logger.error('Failed to check workflow access', { error, userId, workflowId, action });
      return false;
    }
  }

  private async checkExecutionAccess(userId: string, executionId: string, action: 'read'): Promise<boolean> {
    try {
      const execution = await db
        .selectFrom('executions')
        .innerJoin('workflows', 'workflows.id', 'executions.workflow_id')
        .select(['workflows.owner_id', 'workflows.is_public'])
        .where('executions.id', '=', executionId)
        .where('executions.status', '!=', 'cancelled')
        .executeTakeFirst();

      if (!execution) {
        return false;
      }

      // Owner can always access
      if (execution.owner_id === userId) {
        return true;
      }

      // Public workflows allow read access
      if (action === 'read' && execution.is_public) {
        return true;
      }

      return false;
    } catch (error) {
      logger.error('Failed to check execution access', { error, userId, executionId, action });
      return false;
    }
  }

  // Rate limiting and security helpers
  private isRateLimited(key: string, type: 'connection' | 'message'): boolean {
    const limits = type === 'connection' ? this.connectionRateLimits : this.messageRateLimits;
    const now = Date.now();
    const window = type === 'connection' ? this.connectionRateLimitWindow : this.messageRateLimitWindow;
    const maxCount = type === 'connection' ? 10 : this.maxMessagesPerWindow;

    const entry = limits.get(key);
    if (!entry || now > entry.resetTime) {
      limits.set(key, { count: 1, resetTime: now + window });
      return false;
    }

    if (entry.count >= maxCount) {
      return true;
    }

    entry.count++;
    return false;
  }

  private recordConnection(ip: string): void {
    const now = Date.now();
    const entry = this.connectionRateLimits.get(ip);
    if (!entry || now > entry.resetTime) {
      this.connectionRateLimits.set(ip, { count: 1, resetTime: now + this.connectionRateLimitWindow });
    } else {
      entry.count++;
    }
  }

  private getIPConnectionCount(ip: string): number {
    let count = 0;
    for (const socket of this.connectedUsers.values()) {
      if (this.getClientIP(socket) === ip) {
        count++;
      }
    }
    return count;
  }

  private getUserConnectionCount(userId: string): number {
    let count = 0;
    for (const socket of this.connectedUsers.values()) {
      if (socket.userId === userId) {
        count++;
      }
    }
    return count;
  }

  private getClientIP(socket: Socket): string {
    return (socket.handshake.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || 
           socket.handshake.address || 
           'unknown';
  }

  private trackActivity(socket: AuthenticatedSocket): void {
    socket.on('any', () => {
      socket.lastActivity = new Date();
    });
  }

  private cleanupRateLimits(socketId: string): void {
    this.messageRateLimits.delete(socketId);
    // Connection rate limits are cleaned up by expiration
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      this.pingStaleConnections();
    }, this.heartbeatIntervalMs);
  }

  private pingStaleConnections(): void {
    if (!this.io) return;

    const now = Date.now();
    const staleThreshold = this.heartbeatIntervalMs * 2;

    for (const [socketId, socket] of this.connectedUsers.entries()) {
      if (now - socket.lastActivity.getTime() > staleThreshold) {
        logger.warn('Connection appears stale, sending ping', { 
          userId: socket.userId, 
          socketId,
          lastActivity: socket.lastActivity 
        });
        socket.emit('ping', { timestamp: now });
      }
    }
  }

  // Public notification methods with security checks
  notifyWorkflowUpdate(workflowId: string, update: any): void {
    if (!this.io) return;

    logger.debug('Broadcasting workflow update', { 
      workflowId, 
      updateType: update.type,
      authorizedSubscribers: this.getWorkflowSubscribers(workflowId).length
    });
    
    this.io.to(`workflow-${workflowId}`).emit('workflow-updated', {
      workflowId,
      ...update,
      timestamp: new Date().toISOString(),
    });
  }

  notifyExecutionUpdate(executionId: string, update: any): void {
    if (!this.io) return;

    logger.debug('Broadcasting execution update', { 
      executionId, 
      updateType: update.type,
      authorizedSubscribers: this.getExecutionSubscribers(executionId).length
    });
    
    this.io.to(`execution-${executionId}`).emit('execution-updated', {
      executionId,
      ...update,
      timestamp: new Date().toISOString(),
    });
  }

  // Utility methods
  getConnectedUsersCount(): number {
    return this.connectedUsers.size;
  }

  getWorkflowSubscribers(workflowId: string): string[] {
    if (!this.io) return [];

    const room = this.io.sockets.adapter.rooms.get(`workflow-${workflowId}`);
    if (!room) return [];

    return Array.from(room).map(socketId => {
      const socket = this.connectedUsers.get(socketId);
      return socket?.userId;
    }).filter(Boolean) as string[];
  }

  getExecutionSubscribers(executionId: string): string[] {
    if (!this.io) return [];

    const room = this.io.sockets.adapter.rooms.get(`execution-${executionId}`);
    if (!room) return [];

    return Array.from(room).map(socketId => {
      const socket = this.connectedUsers.get(socketId);
      return socket?.userId;
    }).filter(Boolean) as string[];
  }

  getSecurityMetrics(): any {
    const now = Date.now();
    return {
      connectedUsers: this.connectedUsers.size,
      activeConnections: Array.from(this.connectedUsers.values()).filter(s => s.connected).length,
      connectionRateLimits: this.connectionRateLimits.size,
      messageRateLimits: this.messageRateLimits.size,
      heartbeatInterval: this.heartbeatIntervalMs,
      connectionTimeout: this.connectionTimeoutMs,
      maxConnectionsPerIP: this.maxConnectionsPerIP,
      maxConnectionsPerUser: this.maxConnectionsPerUser,
      avgConnectionDuration: this.calculateAverageConnectionDuration(),
      securityLevel: 'enhanced'
    };
  }

  private calculateAverageConnectionDuration(): number {
    const connectedSockets = Array.from(this.connectedUsers.values());
    if (connectedSockets.length === 0) return 0;

    const now = Date.now();
    const totalDuration = connectedSockets.reduce((sum, socket) => {
      return sum + (now - socket.connectedAt.getTime());
    }, 0);

    return Math.round(totalDuration / connectedSockets.length);
  }

  // Graceful shutdown
  shutdown(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    // Notify all clients of shutdown
    if (this.io) {
      this.io.emit('system-shutdown', {
        message: 'Server is shutting down',
        timestamp: new Date().toISOString()
      });
    }

    logger.info('WebSocket security service shutdown complete');
  }
}

export const websocketSecurityService = new WebSocketSecurityService();