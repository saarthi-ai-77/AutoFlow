import { Server } from 'socket.io';
declare class WebSocketService {
    private io;
    private connectedUsers;
    initialize(io: Server): void;
    private handleConnection;
    notifyWorkflowUpdate(workflowId: string, update: any): void;
    notifyExecutionUpdate(executionId: string, update: any): void;
    notifyExecutionStatus(executionId: string, status: string, data?: any): void;
    notifyNodeExecution(executionId: string, nodeId: string, update: any): void;
    notifyExecutionLog(executionId: string, log: any): void;
    notifyUserError(userId: string, error: any): void;
    notifyAllUsers(notification: any): void;
    getConnectedUsersCount(): number;
    getWorkflowSubscribers(workflowId: string): string[];
    notifyWorkflowStats(workflowId: string, stats: any): void;
    notifyNodeData(executionId: string, nodeId: string, data: any): void;
    pingConnectedClients(): void;
}
export declare const websocketService: WebSocketService;
export {};
//# sourceMappingURL=index.d.ts.map