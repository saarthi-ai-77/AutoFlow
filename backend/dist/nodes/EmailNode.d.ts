import { z } from 'zod';
import { NodeExecutionContext, NodeExecutionResult, NodeDefinition } from '../services/execution';
export declare class EmailNode implements NodeDefinition {
    type: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    version: string;
    inputs: z.ZodObject<{
        to: z.ZodString;
        subject: z.ZodString;
        body: z.ZodString;
        from: z.ZodOptional<z.ZodString>;
        cc: z.ZodOptional<z.ZodString>;
        bcc: z.ZodOptional<z.ZodString>;
        attachments: z.ZodOptional<z.ZodArray<z.ZodObject<{
            filename: z.ZodString;
            content: z.ZodString;
            contentType: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            filename: string;
            content: string;
            contentType?: string | undefined;
        }, {
            filename: string;
            content: string;
            contentType?: string | undefined;
        }>, "many">>;
    }, "strip", z.ZodTypeAny, {
        body: string;
        to: string;
        subject: string;
        from?: string | undefined;
        cc?: string | undefined;
        bcc?: string | undefined;
        attachments?: {
            filename: string;
            content: string;
            contentType?: string | undefined;
        }[] | undefined;
    }, {
        body: string;
        to: string;
        subject: string;
        from?: string | undefined;
        cc?: string | undefined;
        bcc?: string | undefined;
        attachments?: {
            filename: string;
            content: string;
            contentType?: string | undefined;
        }[] | undefined;
    }>;
    outputs: z.ZodObject<{
        messageId: z.ZodString;
        status: z.ZodString;
        sentAt: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        status: string;
        messageId: string;
        sentAt: string;
    }, {
        status: string;
        messageId: string;
        sentAt: string;
    }>;
    config: z.ZodObject<{
        smtpHost: z.ZodString;
        smtpPort: z.ZodDefault<z.ZodNumber>;
        smtpSecure: z.ZodDefault<z.ZodBoolean>;
        smtpUser: z.ZodString;
        smtpPassword: z.ZodString;
        fromName: z.ZodDefault<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        smtpHost: string;
        smtpPort: number;
        smtpSecure: boolean;
        smtpUser: string;
        smtpPassword: string;
        fromName: string;
    }, {
        smtpHost: string;
        smtpUser: string;
        smtpPassword: string;
        smtpPort?: number | undefined;
        smtpSecure?: boolean | undefined;
        fromName?: string | undefined;
    }>;
    execute(context: NodeExecutionContext): Promise<NodeExecutionResult>;
    validate(config: any): boolean;
}
export declare class DebugNode implements NodeDefinition {
    type: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    version: string;
    inputs: z.ZodObject<{
        message: z.ZodOptional<z.ZodString>;
        data: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
        logLevel: z.ZodDefault<z.ZodEnum<["debug", "info", "warn", "error"]>>;
    }, "strip", z.ZodTypeAny, {
        logLevel: "error" | "warn" | "info" | "debug";
        message?: string | undefined;
        data?: Record<string, any> | undefined;
    }, {
        message?: string | undefined;
        data?: Record<string, any> | undefined;
        logLevel?: "error" | "warn" | "info" | "debug" | undefined;
    }>;
    outputs: z.ZodObject<{
        logged: z.ZodBoolean;
        loggedData: z.ZodRecord<z.ZodString, z.ZodAny>;
        timestamp: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        timestamp: string;
        logged: boolean;
        loggedData: Record<string, any>;
    }, {
        timestamp: string;
        logged: boolean;
        loggedData: Record<string, any>;
    }>;
    config: z.ZodObject<{
        includeTimestamp: z.ZodDefault<z.ZodBoolean>;
        includeExecutionId: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        includeTimestamp: boolean;
        includeExecutionId: boolean;
    }, {
        includeTimestamp?: boolean | undefined;
        includeExecutionId?: boolean | undefined;
    }>;
    execute(context: NodeExecutionContext): Promise<NodeExecutionResult>;
    validate(config: any): boolean;
}
export declare class DelayNode implements NodeDefinition {
    type: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    version: string;
    inputs: z.ZodObject<{
        duration: z.ZodNumber;
        unit: z.ZodDefault<z.ZodEnum<["ms", "s", "m", "h"]>>;
    }, "strip", z.ZodTypeAny, {
        duration: number;
        unit: "ms" | "s" | "m" | "h";
    }, {
        duration: number;
        unit?: "ms" | "s" | "m" | "h" | undefined;
    }>;
    outputs: z.ZodObject<{
        delayCompleted: z.ZodBoolean;
        startTime: z.ZodString;
        endTime: z.ZodString;
        actualDuration: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        delayCompleted: boolean;
        startTime: string;
        endTime: string;
        actualDuration: number;
    }, {
        delayCompleted: boolean;
        startTime: string;
        endTime: string;
        actualDuration: number;
    }>;
    config: z.ZodObject<{
        maxDuration: z.ZodDefault<z.ZodNumber>;
        allowInfinite: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        maxDuration: number;
        allowInfinite: boolean;
    }, {
        maxDuration?: number | undefined;
        allowInfinite?: boolean | undefined;
    }>;
    execute(context: NodeExecutionContext): Promise<NodeExecutionResult>;
    validate(config: any): boolean;
}
//# sourceMappingURL=EmailNode.d.ts.map