import type { PrismaClient } from "@prisma/client";
import { RealtimeService } from "../../../services/realtime/src/realtime.service";
import { QueueService } from "../../../services/queue/src/queue.service";

export interface NotificationInput {
  userId: string;
  title: string;
  body: string;
  type: string;
  actionUrl?: string;
  channel?: "IN_APP" | "EMAIL" | "PUSH" | "SMS";
  payload?: Record<string, unknown>;
}

export class NotificationService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly realtime: RealtimeService,
    private readonly queueService: QueueService,
  ) {}

  async createNotification(input: NotificationInput) {
    const notification = await this.prisma.notification.create({
      data: {
        userId: input.userId,
        title: input.title,
        body: input.body,
        type: input.type,
        channel: input.channel || "IN_APP",
        actionUrl: input.actionUrl,
        payload: input.payload,
      },
    });

    this.realtime.emitUserNotification(input.userId, notification);
    return notification;
  }

  async queueEmailNotification(input: NotificationInput & { to: string; subject: string; html: string }) {
    await this.queueService.enqueueEmail({
      to: input.to,
      subject: input.subject,
      html: input.html,
      notificationType: input.type,
    });

    return this.createNotification({
      userId: input.userId,
      title: input.title,
      body: input.body,
      type: input.type,
      actionUrl: input.actionUrl,
      channel: "EMAIL",
      payload: input.payload,
    });
  }

  listForUser(userId: string, limit = 50) {
    return this.prisma.notification.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
  }

  markAllRead(userId: string) {
    return this.prisma.notification.updateMany({
      where: { userId, readAt: null },
      data: { readAt: new Date(), status: "READ" },
    });
  }
}
