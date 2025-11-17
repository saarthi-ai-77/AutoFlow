import { z } from 'zod';
import { NodeExecutionContext, NodeExecutionResult, NodeDefinition } from '../services/execution';
export declare class TriggerNode implements NodeDefinition {
    type: string;
    name: string;
    description: string;
    category: string;
    icon: string;
    version: string;
    inputs: z.ZodObject<{}, "strip", z.ZodTypeAny, {}, {}>;
    outputs: z.ZodObject<{
        triggerData: z.ZodRecord<z.ZodString, z.ZodAny>;
        timestamp: z.ZodString;
        executionId: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        timestamp: string;
        triggerData: Record<string, any>;
        executionId: string;
    }, {
        timestamp: string;
        triggerData: Record<string, any>;
        executionId: string;
    }>;
    config: z.ZodObject<{
        eventType: z.ZodOptional<z.ZodString>;
        webhookUrl: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        eventType?: string | undefined;
        webhookUrl?: string | undefined;
    }, {
        eventType?: string | undefined;
        webhookUrl?: string | undefined;
    }>;
    execute(context: NodeExecutionContext): Promise<NodeExecutionResult>;
    validate(config: any): boolean;
}
//# sourceMappingURL=TriggerNode.d.ts.map