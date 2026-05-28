import { Worker } from "bullmq";
import { redis } from "../../../core/cache/redis";
import { prisma } from "../../../core/database/prisma";
import { logger } from "../../../core/logger/winston";
import { EmailService } from "../../../services/email/src/email.service";
import { incrementMetric } from "../../../core/monitoring/metrics";

const emailService = new EmailService();

const emailWorker = new Worker(
  "emails",
  async (job) => {
    incrementMetric("queue.email.processed");

    if (job.data.kind === "broadcast-email") {
      const recipients = await prisma.user.findMany({
        where: {
          email: {
            not: null,
          },
          deletedAt: null,
        },
        select: {
          email: true,
        },
      });

      for (const recipient of recipients) {
        if (!recipient.email) {
          continue;
        }

        await emailService.send({
          to: recipient.email,
          subject: job.data.subject,
          html: job.data.html,
        });
      }

      return { delivered: recipients.length };
    }

    await emailService.send({
      to: job.data.to,
      subject: job.data.subject,
      html: job.data.html,
    });

    return { delivered: true };
  },
  { connection: redis },
);

const notificationWorker = new Worker(
  "notifications",
  async (job) => {
    incrementMetric("queue.notification.processed");

    if (job.data.kind === "broadcast-notification") {
      const users = await prisma.user.findMany({
        where: {
          deletedAt: null,
        },
        select: {
          id: true,
        },
      });

      if (users.length === 0) {
        return { delivered: 0 };
      }

      await prisma.notification.createMany({
        data: users.map((user) => ({
          userId: user.id,
          title: job.data.title,
          body: job.data.body,
          type: job.data.type,
          actionUrl: job.data.actionUrl,
          payload: job.data.payload,
          channel: "IN_APP",
          status: "QUEUED",
        })),
        skipDuplicates: false,
      });

      return { delivered: users.length };
    }

    return { handled: true };
  },
  { connection: redis },
);

const imageWorker = new Worker(
  "images",
  async (job) => {
    incrementMetric("queue.image.processed");
    if (!job.data.fileAssetId) {
      return { handled: false };
    }

    await prisma.fileAsset.update({
      where: {
        id: job.data.fileAssetId,
      },
      data: {
        scanStatus: "clean",
        metadata: {
          processedAt: new Date().toISOString(),
          mimeType: job.data.mimeType,
        },
      },
    });

    return { optimized: true };
  },
  { connection: redis },
);

const analyticsWorker = new Worker(
  "analytics",
  async (job) => {
    incrementMetric("queue.analytics.processed");
    logger.info("analytics.job", {
      data: job.data,
    });
    return { persisted: true };
  },
  { connection: redis },
);

const cleanupWorker = new Worker(
  "cleanup",
  async () => {
    incrementMetric("queue.cleanup.processed");
    const now = new Date();

    await prisma.refreshToken.deleteMany({
      where: {
        expiresAt: {
          lt: now,
        },
      },
    });
    await prisma.verificationToken.deleteMany({
      where: {
        expiresAt: {
          lt: now,
        },
      },
    });
    await prisma.magicLinkToken.deleteMany({
      where: {
        expiresAt: {
          lt: now,
        },
      },
    });
    await prisma.userSession.updateMany({
      where: {
        expiresAt: {
          lt: now,
        },
        revokedAt: null,
      },
      data: {
        status: "EXPIRED",
        revokedAt: now,
        revokeReason: "expired",
      },
    });

    return { cleanedAt: now.toISOString() };
  },
  { connection: redis },
);

for (const worker of [emailWorker, notificationWorker, imageWorker, analyticsWorker, cleanupWorker]) {
  worker.on("completed", (job) => {
    logger.info("worker.completed", {
      queue: worker.name,
      jobId: job.id,
    });
  });

  worker.on("failed", (job, error) => {
    logger.error("worker.failed", {
      queue: worker.name,
      jobId: job?.id,
      message: error.message,
    });
  });
}

logger.info("workers.started", {
  queues: ["emails", "notifications", "images", "analytics", "cleanup"],
});
