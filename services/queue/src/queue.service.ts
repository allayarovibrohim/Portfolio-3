import { analyticsQueue, cleanupQueue, emailQueue, imageQueue, notificationQueue } from "../../../core/queue/bullmq";

export class QueueService {
  enqueueEmail(payload: Record<string, unknown>) {
    return emailQueue.add("send-email", payload, { attempts: 5, backoff: { type: "exponential", delay: 5000 } });
  }

  enqueueNotification(payload: Record<string, unknown>) {
    return notificationQueue.add("dispatch-notification", payload, { attempts: 5 });
  }

  enqueueImageProcessing(payload: Record<string, unknown>) {
    return imageQueue.add("process-image", payload, { attempts: 3 });
  }

  enqueueAnalytics(payload: Record<string, unknown>) {
    return analyticsQueue.add("write-analytics", payload, { attempts: 5 });
  }

  enqueueCleanup(payload: Record<string, unknown> & { repeat?: unknown; jobId?: string }) {
    return cleanupQueue.add("cleanup", payload, {
      repeat: payload.repeat as never,
      jobId: typeof payload.jobId === "string" ? payload.jobId : undefined,
    });
  }

  getQueues() {
    return {
      emailQueue,
      notificationQueue,
      imageQueue,
      analyticsQueue,
      cleanupQueue,
    };
  }
}
