import { z } from 'zod';
import { Queue } from 'bullmq';
export declare const executionQueue: Queue<any, any, string>;
export declare const NodeExecutionContextSchema: z.ZodObject<{
    workflowId: z.ZodString;
    executionId: z.ZodString;
    nodeId: z.ZodString;
    inputs: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodAny>>;
    config: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodAny>>;
    previousResults: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodAny>>;
    webhooks: z.ZodOptional<z.ZodObject<{
        baseUrl: z.ZodString;
        executionId: z.ZodString;
        nodeId: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        executionId: string;
        nodeId: string;
        baseUrl: string;
    }, {
        executionId: string;
        nodeId: string;
        baseUrl: string;
    }>>;
}, "strip", z.ZodTypeAny, {
    executionId: string;
    workflowId: string;
    nodeId: string;
    inputs: Record<string, any>;
    config: Record<string, any>;
    previousResults: Record<string, any>;
    webhooks?: {
        executionId: string;
        nodeId: string;
        baseUrl: string;
    } | undefined;
}, {
    executionId: string;
    workflowId: string;
    nodeId: string;
    inputs?: Record<string, any> | undefined;
    config?: Record<string, any> | undefined;
    previousResults?: Record<string, any> | undefined;
    webhooks?: {
        executionId: string;
        nodeId: string;
        baseUrl: string;
    } | undefined;
}>;
export declare const NodeExecutionResultSchema: z.ZodObject<{
    success: z.ZodBoolean;
    outputs: z.ZodDefault<z.ZodRecord<z.ZodString, z.ZodAny>>;
    error: z.ZodOptional<z.ZodString>;
    executionTimeMs: z.ZodNumber;
    logs: z.ZodDefault<z.ZodArray<z.ZodObject<{
        level: z.ZodEnum<["debug", "info", "warn", "error"]>;
        message: z.ZodString;
        timestamp: z.ZodDate;
        data: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
    }, "strip", z.ZodTypeAny, {
        message: string;
        timestamp: Date;
        level: "error" | "warn" | "info" | "debug";
        data?: Record<string, any> | undefined;
    }, {
        message: string;
        timestamp: Date;
        level: "error" | "warn" | "info" | "debug";
        data?: Record<string, any> | undefined;
    }>, "many">>;
}, "strip", z.ZodTypeAny, {
    logs: {
        message: string;
        timestamp: Date;
        level: "error" | "warn" | "info" | "debug";
        data?: Record<string, any> | undefined;
    }[];
    success: boolean;
    outputs: Record<string, any>;
    executionTimeMs: number;
    error?: string | undefined;
}, {
    success: boolean;
    executionTimeMs: number;
    error?: string | undefined;
    logs?: {
        message: string;
        timestamp: Date;
        level: "error" | "warn" | "info" | "debug";
        data?: Record<string, any> | undefined;
    }[] | undefined;
    outputs?: Record<string, any> | undefined;
}>;
export interface NodeExecutionContext {
    workflowId: string;
    executionId: string;
    nodeId: string;
    inputs: Record<string, any>;
    config: Record<string, any>;
    previousResults: Record<string, any>;
    webhooks?: {
        baseUrl: string;
        executionId: string;
        nodeId: string;
    };
}
export interface NodeExecutionResult {
    success: boolean;
    outputs: Record<string, any>;
    error?: string;
    executionTimeMs: number;
    logs: Array<{
        level: 'debug' | 'info' | 'warn' | 'error';
        message: string;
        timestamp: Date;
        data?: Record<string, any>;
    }>;
}
export interface NodeDefinition {
    type: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    version: string;
    inputs: z.ZodTypeAny;
    outputs: z.ZodTypeAny;
    config: z.ZodTypeAny;
    execute: (context: NodeExecutionContext) => Promise<NodeExecutionResult>;
    validate?: (config: any) => boolean;
}
export declare class NodeRegistry {
    private nodes;
    register(node: NodeDefinition): void;
    get(type: string): NodeDefinition | undefined;
    getAll(): NodeDefinition[];
    getByCategory(category: string): NodeDefinition[];
    has(type: string): boolean;
}
export declare const nodeRegistry: NodeRegistry;
export declare class ExecutionService {
    enqueueExecution(workflowId: string, triggerData: Record<string, any>, userId: string): Promise<string>;
    getExecution(executionId: string, userId?: string): Promise<any>;
    getExecutions(workflowId?: string, userId?: string, options?: {
        status?: string;
        page?: number;
        limit?: number;
        startDate?: Date;
        endDate?: Date;
        cursor?: string;
    }): Promise<any>;
    retryExecution(executionId: string, userId: string): Promise<string>;
    cancelExecution(executionId: string, userId: string): Promise<void>;
}
export declare const executionService: ExecutionService;
//# sourceMappingURL=execution.d.ts.map