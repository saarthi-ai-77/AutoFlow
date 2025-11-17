"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.morganStream = exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const environment_1 = require("@/config/environment");
// Create logs directory if it doesn't exist
const logsDir = path_1.default.join(process.cwd(), 'logs');
if (!fs_1.default.existsSync(logsDir)) {
    fs_1.default.mkdirSync(logsDir, { recursive: true });
}
// Custom log format
const logFormatWinston = winston_1.default.format.combine(winston_1.default.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), winston_1.default.format.errors({ stack: true }), winston_1.default.format.printf(({ timestamp, level, message, service, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
    return `${timestamp} [${service}] ${level.toUpperCase()}: ${message} ${metaStr}`;
}));
// Create logger instance
const logger = winston_1.default.createLogger({
    level: environment_1.env.LOG_LEVEL,
    format: environment_1.env.LOG_FORMAT === 'json'
        ? winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.errors({ stack: true }), winston_1.default.format.json())
        : logFormatWinston,
    defaultMeta: { service: 'autoflow-backend' },
    transports: [
        // Write to stdout for container logs
        new winston_1.default.transports.Console({
            format: environment_1.isDevelopment
                ? winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple())
                : winston_1.default.format.json()
        })
    ],
});
exports.logger = logger;
// Add file transports in production
if (environment_1.isProduction) {
    logger.add(new winston_1.default.transports.File({
        filename: 'logs/error.log',
        level: 'error',
        maxsize: 5242880, // 5MB
        maxFiles: 5,
    }));
    logger.add(new winston_1.default.transports.File({
        filename: 'logs/combined.log',
        maxsize: 5242880, // 5MB
        maxFiles: 5,
    }));
}
// Export a stream for morgan
exports.morganStream = {
    write: (message) => {
        logger.info(message.trim());
    }
};
//# sourceMappingURL=logger.js.map