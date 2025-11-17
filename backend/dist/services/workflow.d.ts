import { z } from 'zod';
export declare const WorkflowNodeSchema: z.ZodObject<{
    id: z.ZodString;
    type: z.ZodString;
    position: z.ZodObject<{
        x: z.ZodNumber;
        y: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        x: number;
        y: number;
    }, {
        x: number;
        y: number;
    }>;
    data: z.ZodRecord<z.ZodString, z.ZodAny>;
}, "strip", z.ZodTypeAny, {
    type: string;
    id: string;
    position: {
        x: number;
        y: number;
    };
    data: Record<string, any>;
}, {
    type: string;
    id: string;
    position: {
        x: number;
        y: number;
    };
    data: Record<string, any>;
}>;
export declare const WorkflowEdgeSchema: z.ZodObject<{
    id: z.ZodString;
    source: z.ZodString;
    target: z.ZodString;
    sourceHandle: z.ZodOptional<z.ZodString>;
    targetHandle: z.ZodOptional<z.ZodString>;
    label: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    id: string;
    source: string;
    target: string;
    sourceHandle?: string | undefined;
    targetHandle?: string | undefined;
    label?: string | undefined;
}, {
    id: string;
    source: string;
    target: string;
    sourceHandle?: string | undefined;
    targetHandle?: string | undefined;
    label?: string | undefined;
}>;
export declare const WorkflowGraphSchema: z.ZodObject<{
    nodes: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        type: z.ZodString;
        position: z.ZodObject<{
            x: z.ZodNumber;
            y: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            x: number;
            y: number;
        }, {
            x: number;
            y: number;
        }>;
        data: z.ZodRecord<z.ZodString, z.ZodAny>;
    }, "strip", z.ZodTypeAny, {
        type: string;
        id: string;
        position: {
            x: number;
            y: number;
        };
        data: Record<string, any>;
    }, {
        type: string;
        id: string;
        position: {
            x: number;
            y: number;
        };
        data: Record<string, any>;
    }>, "many">;
    edges: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        source: z.ZodString;
        target: z.ZodString;
        sourceHandle: z.ZodOptional<z.ZodString>;
        targetHandle: z.ZodOptional<z.ZodString>;
        label: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        id: string;
        source: string;
        target: string;
        sourceHandle?: string | undefined;
        targetHandle?: string | undefined;
        label?: string | undefined;
    }, {
        id: string;
        source: string;
        target: string;
        sourceHandle?: string | undefined;
        targetHandle?: string | undefined;
        label?: string | undefined;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    nodes: {
        type: string;
        id: string;
        position: {
            x: number;
            y: number;
        };
        data: Record<string, any>;
    }[];
    edges: {
        id: string;
        source: string;
        target: string;
        sourceHandle?: string | undefined;
        targetHandle?: string | undefined;
        label?: string | undefined;
    }[];
}, {
    nodes: {
        type: string;
        id: string;
        position: {
            x: number;
            y: number;
        };
        data: Record<string, any>;
    }[];
    edges: {
        id: string;
        source: string;
        target: string;
        sourceHandle?: string | undefined;
        targetHandle?: string | undefined;
        label?: string | undefined;
    }[];
}>;
export declare const CreateWorkflowSchema: z.ZodObject<{
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    graph: z.ZodObject<{
        nodes: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            type: z.ZodString;
            position: z.ZodObject<{
                x: z.ZodNumber;
                y: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                x: number;
                y: number;
            }, {
                x: number;
                y: number;
            }>;
            data: z.ZodRecord<z.ZodString, z.ZodAny>;
        }, "strip", z.ZodTypeAny, {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }, {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }>, "many">;
        edges: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            source: z.ZodString;
            target: z.ZodString;
            sourceHandle: z.ZodOptional<z.ZodString>;
            targetHandle: z.ZodOptional<z.ZodString>;
            label: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }, {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }>, "many">;
    }, "strip", z.ZodTypeAny, {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    }, {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    }>;
    isPublic: z.ZodDefault<z.ZodBoolean>;
    tags: z.ZodDefault<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    name: string;
    graph: {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    };
    isPublic: boolean;
    tags: string[];
    description?: string | undefined;
}, {
    name: string;
    graph: {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    };
    description?: string | undefined;
    isPublic?: boolean | undefined;
    tags?: string[] | undefined;
}>;
export declare const UpdateWorkflowSchema: z.ZodObject<{
    name: z.ZodOptional<z.ZodString>;
    description: z.ZodOptional<z.ZodString>;
    graph: z.ZodOptional<z.ZodObject<{
        nodes: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            type: z.ZodString;
            position: z.ZodObject<{
                x: z.ZodNumber;
                y: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                x: number;
                y: number;
            }, {
                x: number;
                y: number;
            }>;
            data: z.ZodRecord<z.ZodString, z.ZodAny>;
        }, "strip", z.ZodTypeAny, {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }, {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }>, "many">;
        edges: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            source: z.ZodString;
            target: z.ZodString;
            sourceHandle: z.ZodOptional<z.ZodString>;
            targetHandle: z.ZodOptional<z.ZodString>;
            label: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }, {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }>, "many">;
    }, "strip", z.ZodTypeAny, {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    }, {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    }>>;
    isPublic: z.ZodOptional<z.ZodBoolean>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    description?: string | undefined;
    name?: string | undefined;
    graph?: {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    } | undefined;
    isPublic?: boolean | undefined;
    tags?: string[] | undefined;
}, {
    description?: string | undefined;
    name?: string | undefined;
    graph?: {
        nodes: {
            type: string;
            id: string;
            position: {
                x: number;
                y: number;
            };
            data: Record<string, any>;
        }[];
        edges: {
            id: string;
            source: string;
            target: string;
            sourceHandle?: string | undefined;
            targetHandle?: string | undefined;
            label?: string | undefined;
        }[];
    } | undefined;
    isPublic?: boolean | undefined;
    tags?: string[] | undefined;
}>;
export interface WorkflowNode {
    id: string;
    type: string;
    position: {
        x: number;
        y: number;
    };
    data: Record<string, any>;
}
export interface WorkflowEdge {
    id: string;
    source: string;
    target: string;
    sourceHandle?: string;
    targetHandle?: string;
    label?: string;
}
export interface WorkflowGraph {
    nodes: WorkflowNode[];
    edges: WorkflowEdge[];
}
export interface Workflow {
    id: string;
    name: string;
    description?: string;
    graph: WorkflowGraph;
    version: number;
    ownerId: string;
    isActive: boolean;
    isPublic: boolean;
    tags: string[];
    executionCount: number;
    lastExecutedAt?: Date;
    avgExecutionTimeMs?: number;
    createdAt: Date;
    updatedAt: Date;
}
export interface WorkflowSummary {
    id: string;
    name: string;
    description?: string;
    version: number;
    ownerId: string;
    isActive: boolean;
    isPublic: boolean;
    tags: string[];
    executionCount: number;
    lastExecutedAt?: Date;
    createdAt: Date;
    updatedAt: Date;
}
export interface PaginatedWorkflows {
    workflows: WorkflowSummary[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
        hasNext: boolean;
        hasPrev: boolean;
    };
}
export declare class WorkflowService {
    createWorkflow(ownerId: string, data: z.infer<typeof CreateWorkflowSchema>): Promise<Workflow>;
    getWorkflows(ownerId: string, options?: {
        page?: number;
        limit?: number;
        search?: string;
        tags?: string[];
        isPublic?: boolean;
    }): Promise<PaginatedWorkflows>;
    getWorkflowById(id: string, userId?: string): Promise<Workflow | null>;
    updateWorkflow(id: string, userId: string, data: z.infer<typeof UpdateWorkflowSchema>): Promise<Workflow>;
    deleteWorkflow(id: string, userId: string): Promise<void>;
    duplicateWorkflow(id: string, userId: string, newName?: string): Promise<Workflow>;
    getWorkflowExecutionStats(workflowId: string, userId: string): Promise<{
        workflowId: string;
        totalExecutions: number;
        avgExecutionTime: number | null;
        firstExecution: Date | undefined;
        lastExecution: Date | undefined;
        statusBreakdown: any;
    }>;
    private validateWorkflowGraph;
}
export declare const workflowService: WorkflowService;
//# sourceMappingURL=workflow.d.ts.map