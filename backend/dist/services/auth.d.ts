import { z } from 'zod';
export declare const RegisterSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    firstName: z.ZodString;
    lastName: z.ZodString;
}, "strip", z.ZodTypeAny, {
    password: string;
    email: string;
    firstName: string;
    lastName: string;
}, {
    password: string;
    email: string;
    firstName: string;
    lastName: string;
}>;
export declare const LoginSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    password: string;
    email: string;
}, {
    password: string;
    email: string;
}>;
export declare const RefreshTokenSchema: z.ZodObject<{
    refreshToken: z.ZodString;
}, "strip", z.ZodTypeAny, {
    refreshToken: string;
}, {
    refreshToken: string;
}>;
export interface RegisterRequest {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
}
export interface LoginRequest {
    email: string;
    password: string;
}
export interface JWTPayload {
    userId: string;
    email: string;
    role: string;
    tokenId: string;
}
export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}
export declare class AuthService {
    private readonly JWT_SECRET;
    private readonly ACCESS_EXPIRES_IN;
    private readonly REFRESH_EXPIRES_IN;
    register(data: RegisterRequest): Promise<{
        user: {
            id: string;
            email: string;
            firstName: string;
            lastName: string;
            role: string;
        };
        tokens: AuthTokens;
    }>;
    login(data: LoginRequest): Promise<{
        user: {
            id: string;
            email: string;
            firstName: string | undefined;
            lastName: string | undefined;
            role: "user" | "admin";
        };
        tokens: AuthTokens;
    }>;
    refreshToken(refreshToken: string): Promise<AuthTokens>;
    getUserById(userId: string): Promise<{
        id: string;
        email: string;
        firstName: string | undefined;
        lastName: string | undefined;
        role: "user" | "admin";
        createdAt: Date;
        lastLoginAt: Date | undefined;
    }>;
    verifyToken(token: string): Promise<JWTPayload | null>;
    private generateTokens;
    private getExpirationTime;
    logout(userId: string, tokenId: string): Promise<boolean>;
}
export declare const authService: AuthService;
//# sourceMappingURL=auth.d.ts.map