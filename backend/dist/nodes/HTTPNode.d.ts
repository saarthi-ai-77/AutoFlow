import { z } from 'zod';
import { NodeExecutionContext, NodeExecutionResult, NodeDefinition } from '../services/execution';
export declare class HTTPNode implements NodeDefinition {
    type: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    version: string;
    inputs: z.ZodObject<{
        url: z.ZodString;
        method: z.ZodEnum<["GET", "POST", "PUT", "DELETE", "PATCH"]>;
        headers: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodString>>;
        body: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
        timeout: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        url: string;
        method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
        headers?: Record<string, string> | undefined;
        body?: Record<string, any> | undefined;
        timeout?: number | undefined;
    }, {
        url: string;
        method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
        headers?: Record<string, string> | undefined;
        body?: Record<string, any> | undefined;
        timeout?: number | undefined;
    }>;
    outputs: z.ZodObject<{
        statusCode: z.ZodNumber;
        responseData: z.ZodRecord<z.ZodString, z.ZodAny>;
        headers: z.ZodRecord<z.ZodString, z.ZodString>;
        duration: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        headers: Record<string, string>;
        statusCode: number;
        responseData: Record<string, any>;
        duration: number;
    }, {
        headers: Record<string, string>;
        statusCode: number;
        responseData: Record<string, any>;
        duration: number;
    }>;
    config: z.ZodObject<{
        retryCount: z.ZodDefault<z.ZodNumber>;
        retryDelay: z.ZodDefault<z.ZodNumber>;
        followRedirects: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        retryCount: number;
        retryDelay: number;
        followRedirects: boolean;
    }, {
        retryCount?: number | undefined;
        retryDelay?: number | undefined;
        followRedirects?: boolean | undefined;
    }>;
    execute(context: NodeExecutionContext): Promise<NodeExecutionResult>;
    validate(config: any): boolean;
}
//# sourceMappingURL=HTTPNode.d.ts.map