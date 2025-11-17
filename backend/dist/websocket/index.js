"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.websocketSecurityService = void 0;
const logger_1 = require("@/utils/logger");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const environment_1 = require("@/config/environment");
const auth_1 = require("@/services/auth");
const connection_1 = require("@/database/connection");
const security_1 = require("@/utils/security");
class WebSocketSecurityService {
    io = null;
    connectedUsers = new Map();
    connectionRateLimits = new Map();
    messageRateLimits = new Map();
    heartbeatInterval = null;
    maxConnectionsPerIP = 10;
    maxConnectionsPerUser = 5;
    connectionRateLimitWindow = 60000; // 1 minute
    messageRateLimitWindow = 30000; // 30 seconds
    maxMessagesPerWindow = 100;
    heartbeatIntervalMs = 30000; // 30 seconds
    connectionTimeoutMs = 300000; // 5 minutes
    initialize(io) {
        this.io = io;
        // Enhanced authentication middleware with comprehensive security checks
        io.use(async (socket, next) => {
            try {
                await this.authenticateSocket(socket, next);
            }
            catch (error) {
                logger_1.logger.warn('WebSocket authentication failed', {
                    error: error instanceof Error ? error.message : 'Unknown error',
                    socketId: socket.id,
                    ip: this.getClientIP(socket)
                });
                next(new Error('Authentication failed'));
            }
        });
        io.on('connection', (socket) => {
            this.handleSecureConnection(socket);
        });
        // Start heartbeat monitoring
        this.startHeartbeat();
        logger_1.logger.info('WebSocket security service initialized');
    }
    async authenticateSocket(socket, next) {
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
            logger_1.logger.warn('Too many connections from IP', {
                ip: clientIP,
                connections: ipConnectionCount
            });
            return next(new Error('Too many connections from this IP'));
        }
        try {
            // Enhanced JWT verification with token version checking
            const payload = jsonwebtoken_1.default.verify(token, environment_1.jwtConfig.secret);
            if (!payload || !payload.userId) {
                return next(new Error('Invalid token format'));
            }
            // Verify user still exists and is active using auth service
            const user = await auth_1.authService.getUserById(payload.userId);
            if (!user) {
                return next(new Error('User not found or inactive'));
            }
            // Verify token version hasn't been invalidated
            const tokenValid = await auth_1.authService.verifyToken(token);
            if (!tokenValid) {
                return next(new Error('Token has been invalidated'));
            }
            // Attach enhanced user info to socket
            socket.userId = payload.userId;
            socket.userRole = payload.role;
            socket.tokenVersion = payload.version;
            socket.socketId = socket.id;
            socket.connectedAt = new Date();
            socket.lastActivity = new Date();
            socket.subscriptionPermissions = new Set();
            // Record successful authentication
            this.recordConnection(clientIP);
            logger_1.logger.info('WebSocket authenticated successfully', {
                userId: payload.userId,
                socketId: socket.id,
                ip: clientIP,
                userAgent: socket.handshake.headers['user-agent']
            });
            next();
        }
        catch (error) {
            logger_1.logger.error('JWT verification failed', {
                error: error instanceof Error ? error.message : 'Unknown error',
                tokenPreview: token ? token.substring(0, 20) + '...' : 'none'
            });
            return next(new Error('Token verification failed'));
        }
    }
    handleSecureConnection(socket) {
        const userId = socket.userId;
        const socketId = socket.id;
        // Check user connection limits
        const userConnectionCount = this.getUserConnectionCount(userId);
        if (userConnectionCount >= this.maxConnectionsPerUser) {
            logger_1.logger.warn('User exceeded connection limit', {
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
        logger_1.logger.info('User connected via secure WebSocket', {
            userId,
            socketId,
            ip: this.getClientIP(socket),
            totalConnections: this.connectedUsers.size
        });
        // Set up connection timeout
        const timeoutId = setTimeout(() => {
            if (socket.connected) {
                logger_1.logger.warn('WebSocket connection timeout', { userId, socketId });
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
    setupSecureEventHandlers(socket) {
        const userId = socket.userId;
        // Heartbeat handler
        socket.on('pong', () => {
            socket.lastActivity = new Date();
            logger_1.logger.debug('Received pong from client', { userId, socketId: socket.id });
        });
        // Secure workflow subscription with authorization
        socket.on('subscribe-workflow', async (workflowId) => {
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
                security_1.UUIDSchema.parse(workflowId);
                // Check user authorization for this workflow
                const hasPermission = await this.checkWorkflowAccess(userId, workflowId, 'read');
                if (!hasPermission) {
                    logger_1.logger.warn('Unauthorized workflow subscription attempt', {
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
                logger_1.logger.debug('User subscribed to workflow', { userId, workflowId, socketId: socket.id });
                socket.emit('subscribed', { type: 'workflow', id: workflowId });
            }
            catch (error) {
                logger_1.logger.error('Workflow subscription error', {
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
        socket.on('unsubscribe-workflow', (workflowId) => {
            try {
                socket.leave(`workflow-${workflowId}`);
                socket.subscriptionPermissions.delete(`workflow-${workflowId}`);
                logger_1.logger.debug('User unsubscribed from workflow', { userId, workflowId, socketId: socket.id });
                socket.emit('unsubscribed', { type: 'workflow', id: workflowId });
            }
            catch (error) {
                logger_1.logger.error('Workflow unsubscription error', { error, userId, workflowId });
            }
        });
        // Secure execution subscription
        socket.on('subscribe-execution', async (executionId) => {
            try {
                if (this.isRateLimited(socket.id, 'message')) {
                    socket.emit('error', {
                        code: 'RATE_LIMIT_EXCEEDED',
                        message: 'Too many subscription attempts'
                    });
                    return;
                }
                security_1.UUIDSchema.parse(executionId);
                // Check execution access through workflow ownership
                const hasPermission = await this.checkExecutionAccess(userId, executionId, 'read');
                if (!hasPermission) {
                    logger_1.logger.warn('Unauthorized execution subscription attempt', {
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
                logger_1.logger.debug('User subscribed to execution', { userId, executionId, socketId: socket.id });
                socket.emit('subscribed', { type: 'execution', id: executionId });
            }
            catch (error) {
                logger_1.logger.error('Execution subscription error', {
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
        socket.on('unsubscribe-execution', (executionId) => {
            try {
                socket.leave(`execution-${executionId}`);
                socket.subscriptionPermissions.delete(`execution-${executionId}`);
                logger_1.logger.debug('User unsubscribed from execution', { userId, executionId, socketId: socket.id });
                socket.emit('unsubscribed', { type: 'execution', id: executionId });
            }
            catch (error) {
                logger_1.logger.error('Execution unsubscription error', { error, userId, executionId });
            }
        });
        // Secure ping handler
        socket.on('ping', () => {
            socket.lastActivity = new Date();
            socket.emit('pong', { timestamp: Date.now() });
        });
        // Handle disconnect with cleanup
        socket.on('disconnect', (reason) => {
            logger_1.logger.info('User disconnected from secure WebSocket', {
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
    async checkWorkflowAccess(userId, workflowId, action) {
        try {
            const workflow = await connection_1.db
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
        }
        catch (error) {
            logger_1.logger.error('Failed to check workflow access', { error, userId, workflowId, action });
            return false;
        }
    }
    async checkExecutionAccess(userId, executionId, action) {
        try {
            const execution = await connection_1.db
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
        }
        catch (error) {
            logger_1.logger.error('Failed to check execution access', { error, userId, executionId, action });
            return false;
        }
    }
    // Rate limiting and security helpers
    isRateLimited(key, type) {
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
    recordConnection(ip) {
        const now = Date.now();
        const entry = this.connectionRateLimits.get(ip);
        if (!entry || now > entry.resetTime) {
            this.connectionRateLimits.set(ip, { count: 1, resetTime: now + this.connectionRateLimitWindow });
        }
        else {
            entry.count++;
        }
    }
    getIPConnectionCount(ip) {
        let count = 0;
        for (const socket of this.connectedUsers.values()) {
            if (this.getClientIP(socket) === ip) {
                count++;
            }
        }
        return count;
    }
    getUserConnectionCount(userId) {
        let count = 0;
        for (const socket of this.connectedUsers.values()) {
            if (socket.userId === userId) {
                count++;
            }
        }
        return count;
    }
    getClientIP(socket) {
        return socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
            socket.handshake.address ||
            'unknown';
    }
    trackActivity(socket) {
        socket.on('any', () => {
            socket.lastActivity = new Date();
        });
    }
    cleanupRateLimits(socketId) {
        this.messageRateLimits.delete(socketId);
        // Connection rate limits are cleaned up by expiration
    }
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            this.pingStaleConnections();
        }, this.heartbeatIntervalMs);
    }
    pingStaleConnections() {
        if (!this.io)
            return;
        const now = Date.now();
        const staleThreshold = this.heartbeatIntervalMs * 2;
        for (const [socketId, socket] of this.connectedUsers.entries()) {
            if (now - socket.lastActivity.getTime() > staleThreshold) {
                logger_1.logger.warn('Connection appears stale, sending ping', {
                    userId: socket.userId,
                    socketId,
                    lastActivity: socket.lastActivity
                });
                socket.emit('ping', { timestamp: now });
            }
        }
    }
    // Public notification methods with security checks
    notifyWorkflowUpdate(workflowId, update) {
        if (!this.io)
            return;
        logger_1.logger.debug('Broadcasting workflow update', {
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
    notifyExecutionUpdate(executionId, update) {
        if (!this.io)
            return;
        logger_1.logger.debug('Broadcasting execution update', {
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
    getConnectedUsersCount() {
        return this.connectedUsers.size;
    }
    getWorkflowSubscribers(workflowId) {
        if (!this.io)
            return [];
        const room = this.io.sockets.adapter.rooms.get(`workflow-${workflowId}`);
        if (!room)
            return [];
        return Array.from(room).map(socketId => {
            const socket = this.connectedUsers.get(socketId);
            return socket?.userId;
        }).filter(Boolean);
    }
    getExecutionSubscribers(executionId) {
        if (!this.io)
            return [];
        const room = this.io.sockets.adapter.rooms.get(`execution-${executionId}`);
        if (!room)
            return [];
        return Array.from(room).map(socketId => {
            const socket = this.connectedUsers.get(socketId);
            return socket?.userId;
        }).filter(Boolean);
    }
    getSecurityMetrics() {
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
    calculateAverageConnectionDuration() {
        const connectedSockets = Array.from(this.connectedUsers.values());
        if (connectedSockets.length === 0)
            return 0;
        const now = Date.now();
        const totalDuration = connectedSockets.reduce((sum, socket) => {
            return sum + (now - socket.connectedAt.getTime());
        }, 0);
        return Math.round(totalDuration / connectedSockets.length);
    }
    // Graceful shutdown
    shutdown() {
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
        logger_1.logger.info('WebSocket security service shutdown complete');
    }
}
exports.websocketSecurityService = new WebSocketSecurityService();
//# sourceMappingURL=index.js.map