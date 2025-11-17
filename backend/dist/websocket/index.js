"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.websocketService = void 0;
const logger_1 = require("@/utils/logger");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const environment_1 = require("@/config/environment");
class WebSocketService {
    io = null;
    connectedUsers = new Map();
    initialize(io) {
        this.io = io;
        // Authentication middleware
        io.use(async (socket, next) => {
            try {
                const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.replace('Bearer ', '');
                if (!token) {
                    return next(new Error('Authentication required'));
                }
                const payload = jsonwebtoken_1.default.verify(token, environment_1.jwtConfig.secret);
                if (!payload || !payload.userId) {
                    return next(new Error('Invalid token'));
                }
                // Attach user info to socket
                socket.userId = payload.userId;
                socket.userRole = payload.role;
                next();
            }
            catch (error) {
                logger_1.logger.warn('WebSocket authentication failed', { error });
                next(new Error('Authentication failed'));
            }
        });
        io.on('connection', (socket) => {
            this.handleConnection(socket);
        });
        logger_1.logger.info('WebSocket service initialized');
    }
    handleConnection(socket) {
        const userId = socket.userId;
        const socketId = socket.id;
        // Store connected user
        this.connectedUsers.set(socketId, {
            userId,
            userRole: socket.userRole,
            socketId,
        });
        logger_1.logger.info('User connected via WebSocket', { userId, socketId });
        // Handle workflow subscription
        socket.on('subscribe-workflow', (workflowId) => {
            logger_1.logger.debug('User subscribed to workflow', { userId, workflowId });
            socket.join(`workflow-${workflowId}`);
        });
        socket.on('unsubscribe-workflow', (workflowId) => {
            logger_1.logger.debug('User unsubscribed from workflow', { userId, workflowId });
            socket.leave(`workflow-${workflowId}`);
        });
        // Handle execution subscription
        socket.on('subscribe-execution', (executionId) => {
            logger_1.logger.debug('User subscribed to execution', { userId, executionId });
            socket.join(`execution-${executionId}`);
        });
        socket.on('unsubscribe-execution', (executionId) => {
            logger_1.logger.debug('User unsubscribed from execution', { userId, executionId });
            socket.leave(`execution-${executionId}`);
        });
        // Handle disconnect
        socket.on('disconnect', (reason) => {
            logger_1.logger.info('User disconnected from WebSocket', { userId, socketId, reason });
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
    notifyWorkflowUpdate(workflowId, update) {
        if (!this.io)
            return;
        logger_1.logger.debug('Broadcasting workflow update', { workflowId, updateType: update.type });
        this.io.to(`workflow-${workflowId}`).emit('workflow-updated', {
            workflowId,
            ...update,
            timestamp: new Date().toISOString(),
        });
    }
    // Send execution updates to subscribers
    notifyExecutionUpdate(executionId, update) {
        if (!this.io)
            return;
        logger_1.logger.debug('Broadcasting execution update', { executionId, updateType: update.type });
        this.io.to(`execution-${executionId}`).emit('execution-updated', {
            executionId,
            ...update,
            timestamp: new Date().toISOString(),
        });
    }
    // Send execution status updates
    notifyExecutionStatus(executionId, status, data) {
        this.notifyExecutionUpdate(executionId, {
            type: 'status-change',
            status,
            ...data,
        });
    }
    // Send node execution updates
    notifyNodeExecution(executionId, nodeId, update) {
        this.notifyExecutionUpdate(executionId, {
            type: 'node-update',
            nodeId,
            ...update,
        });
    }
    // Send execution logs
    notifyExecutionLog(executionId, log) {
        this.notifyExecutionUpdate(executionId, {
            type: 'log',
            log,
        });
    }
    // Send error notifications to specific user
    notifyUserError(userId, error) {
        if (!this.io)
            return;
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
    notifyAllUsers(notification) {
        if (!this.io)
            return;
        this.io.emit('system-notification', {
            ...notification,
            timestamp: new Date().toISOString(),
        });
    }
    // Get connected users count
    getConnectedUsersCount() {
        return this.connectedUsers.size;
    }
    // Get connected users for a specific workflow
    getWorkflowSubscribers(workflowId) {
        if (!this.io)
            return [];
        const room = this.io.sockets.adapter.rooms.get(`workflow-${workflowId}`);
        if (!room)
            return [];
        return Array.from(room).map(socketId => {
            const user = this.connectedUsers.get(socketId);
            return user?.userId;
        }).filter(Boolean);
    }
    // Send workflow execution statistics
    notifyWorkflowStats(workflowId, stats) {
        this.notifyWorkflowUpdate(workflowId, {
            type: 'stats-update',
            stats,
        });
    }
    // Send real-time node data
    notifyNodeData(executionId, nodeId, data) {
        this.notifyExecutionUpdate(executionId, {
            type: 'node-data',
            nodeId,
            data,
        });
    }
    // Ping clients to check connection status
    pingConnectedClients() {
        if (!this.io)
            return;
        this.io.emit('ping', { timestamp: Date.now() });
    }
}
exports.websocketService = new WebSocketService();
//# sourceMappingURL=index.js.map