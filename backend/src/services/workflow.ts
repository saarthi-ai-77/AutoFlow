import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import { db } from '@/database/connection';
import { logger } from '@/utils/logger';
import { cacheService } from '@/utils/redis-cache';

// Workflow validation schemas
export const WorkflowNodeSchema = z.object({
  id: z.string(),
  type: z.string(),
  position: z.object({
    x: z.number(),
    y: z.number(),
  }),
  data: z.record(z.any()),
});

export const WorkflowEdgeSchema = z.object({
  id: z.string(),
  source: z.string(),
  target: z.string(),
  sourceHandle: z.string().optional(),
  targetHandle: z.string().optional(),
  label: z.string().optional(),
});

export const WorkflowGraphSchema = z.object({
  nodes: z.array(WorkflowNodeSchema),
  edges: z.array(WorkflowEdgeSchema),
});

export const CreateWorkflowSchema = z.object({
  name: z.string().min(1, 'Workflow name is required').max(255),
  description: z.string().optional(),
  graph: WorkflowGraphSchema,
  isPublic: z.boolean().default(false),
  tags: z.array(z.string()).default([]),
});

export const UpdateWorkflowSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  description: z.string().optional(),
  graph: WorkflowGraphSchema.optional(),
  isPublic: z.boolean().optional(),
  tags: z.array(z.string()).optional(),
});

export interface WorkflowNode {
  id: string;
  type: string;
  position: { x: number; y: number };
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

export class WorkflowService {
  async createWorkflow(ownerId: string, data: z.infer<typeof CreateWorkflowSchema>): Promise<Workflow> {
    try {
      // Validate workflow graph
      this.validateWorkflowGraph(data.graph);
      
      const workflowId = uuidv4();
      const now = new Date();
      
      await db
        .insertInto('workflows')
        .values({
          id: workflowId,
          name: data.name,
          description: data.description,
          graph: data.graph,
          version: 1,
          owner_id: ownerId,
          is_active: true,
          is_public: data.isPublic,
          tags: data.tags,
          execution_count: 0,
        })
        .execute();

      const workflow = await this.getWorkflowById(workflowId, ownerId);
      if (!workflow) {
        throw new Error('Failed to create workflow');
      }

      logger.info('Workflow created successfully', { workflowId, ownerId, name: data.name });
      return workflow;
    } catch (error) {
      logger.error('Failed to create workflow', { error, ownerId, data });
      throw error;
    }
  }

  async getWorkflows(
    ownerId: string,
    options: {
      page?: number;
      limit?: number;
      search?: string;
      tags?: string[];
      isPublic?: boolean;
    } = {}
  ): Promise<PaginatedWorkflows> {
    try {
      const {
        page = 1,
        limit = 10,
        search,
        tags,
        isPublic
      } = options;

      const offset = (page - 1) * limit;

      let query = db
        .selectFrom('workflows')
        .select([
          'id',
          'name',
          'description',
          'version',
          'owner_id',
          'is_active',
          'is_public',
          'tags',
          'execution_count',
          'last_executed_at',
          'created_at',
          'updated_at'
        ])
        .where('is_active', '=', true);

      // Filter by owner or public workflows
      query = query.where((eb) => 
        eb.or([
          eb('owner_id', '=', ownerId),
          eb('is_public', '=', true)
        ])
      );

      // Apply filters
      if (search) {
        query = query.where((eb) =>
          eb.or([
            eb('name', 'ilike', `%${search}%`),
            eb('description', 'ilike', `%${search}%`)
          ])
        );
      }

      if (tags && tags.length > 0) {
        query = query.where((eb) =>
          eb('tags', '&&', tags)
        );
      }

      if (typeof isPublic === 'boolean') {
        query = query.where('is_public', '=', isPublic);
      }

      // Get total count
      const countQuery = query.select(({ fn }) => fn.countAll().as('count'));
      const totalResult = await countQuery.executeTakeFirst();
      const total = parseInt((totalResult as any)?.count as string) || 0;

      // Apply pagination and ordering
      const workflows = await query
        .orderBy('updated_at', 'desc')
        .limit(limit)
        .offset(offset)
        .execute();

      const totalPages = Math.ceil(total / limit);

      return {
        workflows: workflows.map(w => ({
          id: w.id,
          name: w.name,
          description: w.description,
          version: w.version,
          ownerId: w.owner_id,
          isActive: w.is_active,
          isPublic: w.is_public,
          tags: w.tags || [],
          executionCount: w.execution_count || 0,
          lastExecutedAt: w.last_executed_at,
          createdAt: w.created_at,
          updatedAt: w.updated_at,
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages,
          hasNext: page < totalPages,
          hasPrev: page > 1,
        },
      };
    } catch (error) {
      logger.error('Failed to get workflows', { error, ownerId, options });
      throw error;
    }
  }

  async getWorkflowById(id: string, userId?: string): Promise<Workflow | null> {
    try {
      // Try cache first
      const cachedWorkflow = await cacheService.get(`workflow:${id}`);
      if (cachedWorkflow) {
        // Check access permissions for cached workflow
        if (!cachedWorkflow.isPublic && cachedWorkflow.ownerId !== userId) {
          throw new Error('Access denied');
        }
        return cachedWorkflow;
      }

      // Cache miss, fetch from database
      const workflow = await db
        .selectFrom('workflows')
        .selectAll()
        .where('id', '=', id)
        .where('is_active', '=', true)
        .executeTakeFirst();

      if (!workflow) {
        return null;
      }

      // Check access permissions
      if (!workflow.is_public && workflow.owner_id !== userId) {
        throw new Error('Access denied');
      }

      const workflowData = {
        id: workflow.id,
        name: workflow.name,
        description: workflow.description,
        graph: workflow.graph,
        version: workflow.version,
        ownerId: workflow.owner_id,
        isActive: workflow.is_active,
        isPublic: workflow.is_public,
        tags: workflow.tags || [],
        executionCount: workflow.execution_count || 0,
        lastExecutedAt: workflow.last_executed_at,
        avgExecutionTimeMs: workflow.avg_execution_time_ms,
        createdAt: workflow.created_at,
        updatedAt: workflow.updated_at,
      };

      // Cache the workflow for 5 minutes
      await cacheService.set(`workflow:${id}`, workflowData, 300);

      return workflowData;
    } catch (error) {
      logger.error('Failed to get workflow by ID', { error, id, userId });
      throw error;
    }
  }

  async updateWorkflow(
    id: string,
    userId: string,
    data: z.infer<typeof UpdateWorkflowSchema>
  ): Promise<Workflow> {
    try {
      const workflow = await this.getWorkflowById(id, userId);
      if (!workflow) {
        throw new Error('Workflow not found');
      }

      // Check ownership
      if (workflow.ownerId !== userId) {
        throw new Error('Access denied: Only owner can update workflow');
      }

      // If graph is being updated, validate it
      if (data.graph) {
        this.validateWorkflowGraph(data.graph);
      }

      // Build update object
      const updateData: any = {};
      if (data.name !== undefined) updateData.name = data.name;
      if (data.description !== undefined) updateData.description = data.description;
      if (data.graph !== undefined) updateData.graph = data.graph;
      if (data.isPublic !== undefined) updateData.is_public = data.isPublic;
      if (data.tags !== undefined) updateData.tags = data.tags;

      // Increment version if graph is being updated
      if (data.graph) {
        updateData.version = workflow.version + 1;
      }

      await db
        .updateTable('workflows')
        .set(updateData)
        .where('id', '=', id)
        .execute();

      const updatedWorkflow = await this.getWorkflowById(id, userId);
      if (!updatedWorkflow) {
        throw new Error('Failed to update workflow');
      }

      // Invalidate cache
      await cacheService.delete(`workflow:${id}`);

      logger.info('Workflow updated successfully', { workflowId: id, userId, version: updatedWorkflow.version });
      return updatedWorkflow;
    } catch (error) {
      logger.error('Failed to update workflow', { error, id, userId, data });
      throw error;
    }
  }

  async deleteWorkflow(id: string, userId: string): Promise<void> {
    try {
      const workflow = await this.getWorkflowById(id, userId);
      if (!workflow) {
        throw new Error('Workflow not found');
      }

      // Check ownership
      if (workflow.ownerId !== userId) {
        throw new Error('Access denied: Only owner can delete workflow');
      }

      // Soft delete
      await db
        .updateTable('workflows')
        .set({ is_active: false })
        .where('id', '=', id)
        .execute();

      // Invalidate cache
      await cacheService.delete(`workflow:${id}`);

      logger.info('Workflow deleted successfully', { workflowId: id, userId });
    } catch (error) {
      logger.error('Failed to delete workflow', { error, id, userId });
      throw error;
    }
  }

  async duplicateWorkflow(id: string, userId: string, newName?: string): Promise<Workflow> {
    try {
      const originalWorkflow = await this.getWorkflowById(id, userId);
      if (!originalWorkflow) {
        throw new Error('Workflow not found');
      }

      // Check access
      if (!originalWorkflow.isPublic && originalWorkflow.ownerId !== userId) {
        throw new Error('Access denied');
      }

      const duplicatedWorkflow = await this.createWorkflow(userId, {
        name: newName || `${originalWorkflow.name} (Copy)`,
        description: originalWorkflow.description,
        graph: originalWorkflow.graph,
        isPublic: false, // Duplicates are private by default
        tags: originalWorkflow.tags,
      });

      logger.info('Workflow duplicated successfully', {
        originalId: id,
        newId: duplicatedWorkflow.id,
        userId,
      });

      return duplicatedWorkflow;
    } catch (error) {
      logger.error('Failed to duplicate workflow', { error, id, userId });
      throw error;
    }
  }

  async getWorkflowExecutionStats(workflowId: string, userId: string) {
    try {
      const workflow = await this.getWorkflowById(workflowId, userId);
      if (!workflow) {
        throw new Error('Workflow not found');
      }

      // Get execution statistics
      const stats = await db
        .selectFrom('executions')
        .select(({ fn }) => [
          fn.countAll().as('total_executions'),
          fn.avg('execution_time_ms').as('avg_execution_time'),
          fn.min('created_at').as('first_execution'),
          fn.max('created_at').as('last_execution'),
        ])
        .where('workflow_id', '=', workflowId)
        .executeTakeFirst();

      const statusStats = await db
        .selectFrom('executions')
        .select('status' as any)
        .addSelect(({ fn }) => fn.countAll().as('count') as any)
        .where('workflow_id', '=', workflowId)
        .groupBy('status')
        .execute();

      return {
        workflowId,
        totalExecutions: parseInt(stats?.total_executions as string) || 0,
        avgExecutionTime: stats?.avg_execution_time ? Math.round(parseFloat(stats.avg_execution_time as string)) : null,
        firstExecution: stats?.first_execution,
        lastExecution: stats?.last_execution,
        statusBreakdown: statusStats.reduce((acc, stat) => {
          acc[stat.status] = parseInt(stat.count as string);
          return acc;
        }, {} as Record<string, number>),
      };
    } catch (error) {
      logger.error('Failed to get workflow execution stats', { error, workflowId, userId });
      throw error;
    }
  }

  private validateWorkflowGraph(graph: WorkflowGraph): void {
    // Check if graph has nodes and edges
    if (!graph.nodes || graph.nodes.length === 0) {
      throw new Error('Workflow must have at least one node');
    }

    // Check for isolated nodes
    const nodeIds = new Set(graph.nodes.map(node => node.id));
    const connectedNodes = new Set(graph.edges.flatMap(edge => [edge.source, edge.target]));
    
    const isolatedNodes = [...nodeIds].filter(id => !connectedNodes.has(id));
    if (isolatedNodes.length > 0 && graph.nodes.length > 1) {
      logger.warn('Found isolated nodes in workflow graph', { isolatedNodes });
    }

    // Check for duplicate edges
    const edgeKeys = new Set();
    for (const edge of graph.edges) {
      const key = `${edge.source}->${edge.target}`;
      if (edgeKeys.has(key)) {
        throw new Error(`Duplicate edge from ${edge.source} to ${edge.target}`);
      }
      edgeKeys.add(key);
    }

    // Validate node types (basic check)
    for (const node of graph.nodes) {
      if (!node.type) {
        throw new Error('Node must have a type');
      }
      if (!node.id) {
        throw new Error('Node must have an ID');
      }
    }

    logger.debug('Workflow graph validation passed', {
      nodeCount: graph.nodes.length,
      edgeCount: graph.edges.length,
    });
  }
}

export const workflowService = new WorkflowService();