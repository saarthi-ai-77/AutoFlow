import cors from 'cors';
import { Request, Response, NextFunction } from 'express';
declare const RATE_LIMIT_TIERS: {
    AUTH: {
        windowMs: number;
        max: number;
        message: {
            error: string;
            code: string;
            retryAfter: number;
        };
        skipSuccessfulRequests: boolean;
        skipFailedRequests: boolean;
        standardHeaders: boolean;
        legacyHeaders: boolean;
    };
    GENERAL: {
        windowMs: number;
        max: number;
        message: {
            error: string;
            code: string;
            retryAfter: number;
        };
        standardHeaders: boolean;
        legacyHeaders: boolean;
    };
    EXECUTION: {
        windowMs: number;
        max: number;
        message: {
            error: string;
            code: string;
            retryAfter: number;
        };
        standardHeaders: boolean;
        legacyHeaders: boolean;
    };
    WORKFLOW: {
        windowMs: number;
        max: number;
        message: {
            error: string;
            code: string;
            retryAfter: number;
        };
        standardHeaders: boolean;
        legacyHeaders: boolean;
    };
    SEARCH: {
        windowMs: number;
        max: number;
        message: {
            error: string;
            code: string;
            retryAfter: number;
        };
        standardHeaders: boolean;
        legacyHeaders: boolean;
    };
};
export declare const createTieredRateLimiter: (tier: keyof typeof RATE_LIMIT_TIERS, customKeyGenerator?: (req: Request) => string) => import("express-rate-limit").RateLimitRequestHandler;
export declare const createRateLimiter: (options?: Partial<{
    windowMs: number;
    maxRequests: number;
}>) => import("express-rate-limit").RateLimitRequestHandler;
export declare const authRateLimiter: import("express-rate-limit").RateLimitRequestHandler;
export declare const generalRateLimiter: import("express-rate-limit").RateLimitRequestHandler;
export declare const executionRateLimiter: import("express-rate-limit").RateLimitRequestHandler;
export declare const workflowRateLimiter: import("express-rate-limit").RateLimitRequestHandler;
export declare const searchRateLimiter: import("express-rate-limit").RateLimitRequestHandler;
export declare const corsOriginValidator: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => void;
export declare const corsMiddleware: (req: cors.CorsRequest, res: {
    statusCode?: number | undefined;
    setHeader(key: string, value: string): any;
    end(): any;
}, next: (err?: any) => any) => void;
export declare const helmetMiddleware: (req: import("http").IncomingMessage, res: import("http").ServerResponse, next: (err?: unknown) => void) => void;
export declare const compressionMiddleware: import("express").RequestHandler<import("express-serve-static-core").ParamsDictionary, any, any, import("qs").ParsedQs, Record<string, any>>;
export declare const requestLogger: (req: import("http").IncomingMessage, res: import("http").ServerResponse<import("http").IncomingMessage>, callback: (err?: Error) => void) => void;
export declare const securityHeaders: (req: Request, res: Response, next: NextFunction) => void;
export declare const validateApiKey: (req: Request, res: Response, next: NextFunction) => Promise<Response<any, Record<string, any>> | undefined>;
export declare const errorHandler: (error: Error, req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
export declare const notFoundHandler: (req: Request, res: Response) => void;
export {};
//# sourceMappingURL=security.d.ts.map