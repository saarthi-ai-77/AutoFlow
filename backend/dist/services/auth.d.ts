export declare const RegisterSchema: import("zod").ZodObject<{
    email: import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodString, string, string>, string, string>;
    password: import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodString, string, string>, string, string>, string, string>, string, string>, string, string>, string, string>;
    firstName: import("zod").ZodEffects<import("zod").ZodString, string, string>;
    lastName: import("zod").ZodEffects<import("zod").ZodString, string, string>;
}, "strip", import("zod").ZodTypeAny, {
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
export declare const LoginSchema: import("zod").ZodObject<{
    email: import("zod").ZodEffects<import("zod").ZodEffects<import("zod").ZodString, string, string>, string, string>;
    password: import("zod").ZodString;
}, "strip", import("zod").ZodTypeAny, {
    password: string;
    email: string;
}, {
    password: string;
    email: string;
}>;
export declare const RefreshTokenSchema: import("zod").ZodObject<{
    refreshToken: import("zod").ZodString;
}, "strip", import("zod").ZodTypeAny, {
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
    version: number;
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
    getUserById(userId: string): Promise<any>;
    verifyToken(token: string): Promise<JWTPayload | null>;
    invalidateUserTokens(userId: string): Promise<void>;
    private generateTokens;
    private getExpirationTime;
    logout(userId: string, tokenId: string): Promise<boolean>;
    private checkLoginRateLimit;
    private recordFailedLoginAttempt;
    private resetFailedLoginAttempts;
    private isAccountLocked;
}
export declare const authService: AuthService;
//# sourceMappingURL=auth.d.ts.map