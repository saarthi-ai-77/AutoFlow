import { z } from 'zod';
import { NodeExecutionContext, NodeExecutionResult, NodeDefinition } from '../services/execution';
import { logger } from '../utils/logger';

export class HTTPNode implements NodeDefinition {
  type = 'http';
  name = 'HTTP Request';
  description = 'Make HTTP requests to external APIs';
  category = 'Utilities';
  icon = '🌐';
  version = '1.0.0';

  inputs = z.object({
    url: z.string().url().max(2048, 'URL must be less than 2048 characters').describe('HTTP endpoint URL'),
    method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).describe('HTTP method'),
    headers: z.record(z.string()).optional().describe('HTTP headers'),
    body: z.record(z.any()).optional().describe('Request body (for POST/PUT/PATCH)'),
    timeout: z.number().optional().describe('Request timeout in milliseconds'),
  });

  outputs = z.object({
    statusCode: z.number().describe('HTTP status code'),
    responseData: z.record(z.any()).describe('Response data'),
    headers: z.record(z.string()).describe('Response headers'),
    duration: z.number().describe('Request duration in ms'),
  });

  config = z.object({
    retryCount: z.number().default(3).describe('Number of retries on failure'),
    retryDelay: z.number().default(1000).describe('Delay between retries in ms'),
    followRedirects: z.boolean().default(true).describe('Follow HTTP redirects'),
  });

  async execute(context: NodeExecutionContext): Promise<NodeExecutionResult> {
    const startTime = Date.now();
    const logs: Array<any> = [];

    try {
      const { url, method, headers, body, timeout } = context.inputs;
      
      logger.info('Executing HTTP request', { 
        executionId: context.executionId,
        nodeId: context.nodeId,
        method,
        url 
      });

      if (!url) {
        throw new Error('URL is required');
      }

      if (!method) {
        throw new Error('HTTP method is required');
      }

      logs.push({
        level: 'info',
        message: `Starting ${method} request to ${url}`,
        timestamp: new Date(),
        data: { method, url, timeout },
      });

      // Create fetch options
      const fetchOptions: RequestInit = {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...headers,
        },
        ...(body && { body: JSON.stringify(body) }),
        ...(timeout && { signal: AbortSignal.timeout(timeout) }),
      };

      // Make HTTP request with retries
      let lastError: Error | null = null;
      let response: Response | null = null;

      for (let attempt = 1; attempt <= context.config.retryCount; attempt++) {
        try {
          logs.push({
            level: 'debug',
            message: `HTTP request attempt ${attempt}/${context.config.retryCount}`,
            timestamp: new Date(),
          });

          response = await fetch(url, fetchOptions);
          break; // Success, exit retry loop
        } catch (error) {
          lastError = error instanceof Error ? error : new Error('Unknown error');
          logs.push({
            level: 'warn',
            message: `HTTP request attempt ${attempt} failed`,
            timestamp: new Date(),
            error: lastError.message,
          });

          if (attempt < context.config.retryCount) {
            const delay = context.config.retryDelay * Math.pow(2, attempt - 1); // Exponential backoff
            logs.push({
              level: 'info',
              message: `Retrying in ${delay}ms`,
              timestamp: new Date(),
            });
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }

      if (!response) {
        throw lastError || new Error('HTTP request failed after all retries');
      }

      const duration = Date.now() - startTime;
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      let responseData: any = null;
      const contentType = response.headers.get('content-type') || '';

      try {
        if (contentType.includes('application/json')) {
          responseData = await response.json();
        } else if (contentType.includes('text/')) {
          responseData = await response.text();
        } else {
          responseData = await response.arrayBuffer();
        }
      } catch (error) {
        logs.push({
          level: 'error',
          message: 'Failed to parse response body',
          timestamp: new Date(),
          error: error instanceof Error ? error.message : 'Unknown error',
        });
      }

      const success = response.ok;
      const logLevel = success ? 'info' : 'error';

      logs.push({
        level: logLevel,
        message: `HTTP ${method} request completed: ${response.status} ${response.statusText}`,
        timestamp: new Date(),
        data: {
          statusCode: response.status,
          statusText: response.statusText,
          duration,
          contentType,
        },
      });

      logger.info('HTTP request completed', { 
        executionId: context.executionId,
        nodeId: context.nodeId,
        method,
        url,
        status: response.status,
        duration 
      });

      return {
        success,
        outputs: {
          statusCode: response.status,
          responseData,
          headers: responseHeaders,
          duration,
        },
        executionTimeMs: duration,
        logs,
        ...(!success && { error: `${response.status}: ${response.statusText}` }),
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logs.push({
        level: 'error',
        message: `HTTP request failed: ${errorMessage}`,
        timestamp: new Date(),
        error,
      });

      logger.error('HTTP request failed', { 
        error, 
        executionId: context.executionId,
        nodeId: context.nodeId 
      });

      return {
        success: false,
        outputs: {
          statusCode: 0,
          responseData: null,
          headers: {},
          duration: Date.now() - startTime,
        },
        error: errorMessage,
        executionTimeMs: Date.now() - startTime,
        logs,
      };
    }
  }

  validate(config: any): boolean {
    const { retryCount, retryDelay, followRedirects } = config;
    
    if (retryCount !== undefined && (retryCount < 0 || retryCount > 10)) {
      return false;
    }
    
    if (retryDelay !== undefined && retryDelay < 100) {
      return false;
    }
    
    return true;
  }
}