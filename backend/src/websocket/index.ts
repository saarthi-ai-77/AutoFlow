import { Server } from 'socket.io';
import { logger } from '@/utils/logger';
import jwt from 'jsonwebtoken';
import { jwtConfig } from '@/config/environment';

interface AuthenticatedSocket {
  userId: string;
  userRole: string;
  socketId: string;
}

class WebSocketService {
  private io: Server | null = null;
  private connectedUsers: Map<string, AuthenticatedSocket> = new Map();

  initialize(io: Server): void {
    this.io = io;
    
    // Authentication middleware
    io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
          return next(new Error('Authentication required'));
        }

        const payload = jwt.verify(token, jwtConfig.secret) as any;
        if (!payload || !payload.userId) {
          return next(new Error('Invalid token'));
        }

        // Attach user info to socket
        (socket as any).userId = payload.userId;
        (socket as any).userRole = payload.role;
        
        next();
      } catch (error) {
        logger.warn('WebSocket authentication failed', { error });
        next(new Error('Authentication failed'));
      }
    });

    io.on('connection', (socket) => {
      this.handleConnection(socket);
    });

    logger.info('WebSocket service initialized');
  }

  private handleConnection(socket: any): void {
    const userId = socket.userId;
    const socketId = socket.id;

    // Store connected user
    this.connectedUsers.set(socketId, {
      userId,
      userRole: socket.userRole,
      socketId,
    });

    logger.info('User connected via WebSocket', { userId, socketId });

    // Handle workflow subscription
    socket.on('subscribe-workflow', (workflowId: string) => {
      logger.debug('User subscribed to workflow', { userId, workflowId });
      socket.join(`workflow-${workflowId}`);
    });

    socket.on('unsubscribe-workflow', (workflowId: string) => {
      logger.debug('User unsubscribed from workflow', { userId, workflowId });
      socket.leave(`workflow-${workflowId}`);
    });

    // Handle execution subscription
    socket.on('subscribe-execution', (executionId: string) => {
      logger.debug('User subscribed to execution', { userId, executionId });
      socket.join(`execution-${executionId}`);
    });

    socket.on('unsubscribe-execution', (executionId: string) => {
      logger.debug('User unsubscribed from execution', { userId, executionId });
      socket.leave(`execution-${executionId}`);
    });

    // Handle disconnect
    socket.on('disconnect', (reason) => {
      logger.info('User disconnected from WebSocket', { userId, socketId, reason });
      this.connectedUsers.delete(socketId);
    });

    // Send connection success
    socket.emit('connected', {
      message: 'Connected to AutoFlow WebSocket',
      userId,
      timestamp: new Date().toISOString(),
    });
  }

  // Send workflow updates to subscribers
  notifyWorkflowUpdate(workflowId: string, update: any): void {
    if (!this.io) return;

    logger.debug('Broadcasting workflow update', { workflowId, updateType: update.type });
    
    this.io.to(`workflow-${workflowId}`).emit('workflow-updated', {
      workflowId,
      ...update,
      timestamp: new Date().toISOString(),
    });
  }

  // Send execution updates to subscribers
  notifyExecutionUpdate(executionId: string, update: any): void {
    if (!this.io) return;

    logger.debug('Broadcasting execution update', { executionId, updateType: update.type });
    
    this.io.to(`execution-${executionId}`).emit('execution-updated', {
      executionId,
      ...update,
      timestamp: new Date().toISOString(),
    });
  }

  // Send execution status updates
  notifyExecutionStatus(executionId: string, status: string, data?: any): void {
    this.notifyExecutionUpdate(executionId, {
      type: 'status-change',
      status,
      ...data,
    });
  }

  // Send node execution updates
  notifyNodeExecution(executionId: string, nodeId: string, update: any): void {
    this.notifyExecutionUpdate(executionId, {
      type: 'node-update',
      nodeId,
      ...update,
    });
  }

  // Send execution logs
  notifyExecutionLog(executionId: string, log: any): void {
    this.notifyExecutionUpdate(executionId, {
      type: 'log',
      log,
    });
  }

  // Send error notifications to specific user
  notifyUserError(userId: string, error: any): void {
    if (!this.io) return;

    // Find all sockets for this user
    for (const [socketId, user] of this.connectedUsers.entries()) {
      if (user.userId === userId) {
        this.io.to(socketId).emit('error-notification', {
          error,
          timestamp: new Date().toISOString(),
        });
      }
    }
  }

  // Send system-wide notifications
  notifyAllUsers(notification: any): void {
    if (!this.io) return;

    this.io.emit('system-notification', {
      ...notification,
      timestamp: new Date().toISOString(),
    });
  }

  // Get connected users count
  getConnectedUsersCount(): number {
    return this.connectedUsers.size;
  }

  // Get connected users for a specific workflow
  getWorkflowSubscribers(workflowId: string): string[] {
    if (!this.io) return [];

    const room = this.io.sockets.adapter.rooms.get(`workflow-${workflowId}`);
    if (!room) return [];

    return Array.from(room).map(socketId => {
      const user = this.connectedUsers.get(socketId);
      return user?.userId;
    }).filter(Boolean) as string[];
  }

  // Send workflow execution statistics
  notifyWorkflowStats(workflowId: string, stats: any): void {
    this.notifyWorkflowUpdate(workflowId, {
      type: 'stats-update',
      stats,
    });
  }

  // Send real-time node data
  notifyNodeData(executionId: string, nodeId: string, data: any): void {
    this.notifyExecutionUpdate(executionId, {
      type: 'node-data',
      nodeId,
      data,
    });
  }

  // Ping clients to check connection status
  pingConnectedClients(): void {
    if (!this.io) return;

    this.io.emit('ping', { timestamp: Date.now() });
  }
}

export const websocketService = new WebSocketService();