import { prisma } from "../../../core/database/prisma";
import { redis } from "../../../core/cache/redis";
import { logger } from "../../../core/logger/winston";
import { eventBus } from "../../../shared/events/event-bus";
import { QueueService } from "../../../services/queue/src/queue.service";
import { EmailService } from "../../../services/email/src/email.service";
import { RealtimeService } from "../../../services/realtime/src/realtime.service";
import { StorageService } from "../../../core/storage/storage.service";
import { AuditService } from "../../../modules/audit/application/audit.service";
import { NotificationService } from "../../../modules/notifications/application/notification.service";
import { FileService } from "../../../modules/files/application/file.service";
import { AuthRepository } from "../../../modules/auth/infrastructure/auth.repository";
import { AuthService } from "../../../modules/auth/application/auth.service";
import { UserRepository } from "../../../modules/users/infrastructure/user.repository";
import { UserService } from "../../../modules/users/application/user.service";

export const buildContainer = () => {
  const queueService = new QueueService();
  const emailService = new EmailService();
  const realtimeService = new RealtimeService();
  const storageService = new StorageService();

  const auditService = new AuditService(prisma);
  const notificationService = new NotificationService(prisma, realtimeService, queueService);
  const fileService = new FileService(prisma, storageService, queueService);

  const authRepository = new AuthRepository(prisma);
  const authService = new AuthService(authRepository, auditService, notificationService, emailService);

  const userRepository = new UserRepository(prisma);
  const userService = new UserService(userRepository, auditService, queueService);

  return {
    prisma,
    redis,
    logger,
    eventBus,
    queueService,
    emailService,
    realtimeService,
    storageService,
    auditService,
    notificationService,
    fileService,
    authRepository,
    authService,
    userRepository,
    userService,
  };
};

export type ServiceContainer = ReturnType<typeof buildContainer>;
