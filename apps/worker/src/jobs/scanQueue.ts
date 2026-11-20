import { Queue, Worker, type Job } from "bullmq";
import { Redis } from "ioredis";
import type { ScanProcessorDependencies } from "../processors/scanProcessor.js";
import { executeScanPipeline } from "../processors/scanProcessor.js";

export const SCAN_QUEUE_NAME = "indicative-security-scans";

export interface ScanJobPayload {
  scanId: string;
  organizationId: string;
  projectId: string;
  correlationId?: string;
}

export interface ScanJobEnqueuer {
  enqueue(payload: ScanJobPayload): Promise<{ jobId: string }>;
  cancel(scanId: string): Promise<void>;
  getQueueDepth(): Promise<number>;
  close(): Promise<void>;
}

export function createBullMqEnqueuer(redisUrl: string): ScanJobEnqueuer {
  const connection = new Redis(redisUrl, { maxRetriesPerRequest: null });
  const queue = new Queue<ScanJobPayload>(SCAN_QUEUE_NAME, {
    connection,
    defaultJobOptions: {
      attempts: 2,
      backoff: { type: "exponential", delay: 3000 },
      removeOnComplete: { count: 200 },
      removeOnFail: { count: 500 }
    }
  });

  return {
    async enqueue(payload) {
      // Idempotent jobId tied to scanId prevents duplicate concurrent execution
      const job = await queue.add("execute-scan", payload, {
        jobId: `scan-${payload.scanId}`
      });
      return { jobId: job.id ?? payload.scanId };
    },
    async cancel(scanId) {
      const job = await queue.getJob(`scan-${scanId}`);
      if (job) {
        const state = await job.getState();
        if (state === "waiting" || state === "delayed") {
          await job.remove();
        }
      }
    },
    async getQueueDepth() {
      const counts = await queue.getJobCounts("waiting", "active", "delayed");
      return (counts.waiting ?? 0) + (counts.active ?? 0) + (counts.delayed ?? 0);
    },
    async close() {
      await queue.close();
      await connection.quit();
    }
  };
}

/**
 * In-process async queue fallback for self-contained automated integration/E2E tests
 * or local evaluation when Redis is not running. Executes the exact same scan pipeline.
 */
export function createInlineAsyncEnqueuer(
  depsProvider: () => ScanProcessorDependencies
): ScanJobEnqueuer & { drain(): Promise<void> } {
  const pending = new Set<Promise<unknown>>();

  return {
    async enqueue(payload) {
      const p = executeScanPipeline(payload.scanId, depsProvider()).finally(() => {
        pending.delete(p);
      });
      pending.add(p);
      return { jobId: `inline-${payload.scanId}` };
    },
    async cancel() {
      // Scan cancellation is persisted in DB and respected between pipeline stages
    },
    async getQueueDepth() {
      return pending.size;
    },
    async drain() {
      await Promise.allSettled([...pending]);
    },
    async close() {
      await Promise.allSettled([...pending]);
    }
  };
}

export function startBullMqWorker(
  redisUrl: string,
  concurrency: number,
  deps: ScanProcessorDependencies
): { worker: Worker<ScanJobPayload>; close(): Promise<void> } {
  const connection = new Redis(redisUrl, { maxRetriesPerRequest: null });
  const worker = new Worker<ScanJobPayload>(
    SCAN_QUEUE_NAME,
    async (job: Job<ScanJobPayload>) => {
      return executeScanPipeline(job.data.scanId, deps);
    },
    {
      connection,
      concurrency
    }
  );

  return {
    worker,
    async close() {
      await worker.close();
      await connection.quit();
    }
  };
}
