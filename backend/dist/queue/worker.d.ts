import { Worker } from 'bullmq';
export declare const executionWorker: Worker<any, {
    executionId: any;
    status: string;
    executionTime: number;
    nodeResults: Record<string, any>;
}, string>;
export default executionWorker;
//# sourceMappingURL=worker.d.ts.map