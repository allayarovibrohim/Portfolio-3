import type { PrismaClient } from "@prisma/client";
import type Redis from "ioredis";
import type { Logger } from "winston";
import { EventBus } from "../events/event-bus";
import { QueueService } from "../../services/queue/src/queue.service";
import { EmailService } from "../../services/email/src/email.service";
import { RealtimeService } from "../../services/realtime/src/realtime.service";
import { StorageService } from "../../core/storage/storage.service";

export interface AppContext {
  prisma: PrismaClient;
  redis: Redis;
  logger: Logger;
  eventBus: EventBus;
  queueService: QueueService;
  emailService: EmailService;
  realtimeService: RealtimeService;
  storageService: StorageService;
}
