import { AuditService } from "../../audit/application/audit.service";
import { QueueService } from "../../../services/queue/src/queue.service";
import { ConflictError, NotFoundError } from "../../../shared/http/errors";
import { UserRepository } from "../infrastructure/user.repository";

export class UserService {
  constructor(
    private readonly repository: UserRepository,
    private readonly auditService: AuditService,
    private readonly queueService: QueueService,
  ) {}

  async getMe(userId: string) {
    const user = await this.repository.findPrivateProfile(userId);
    if (!user) {
      throw new NotFoundError("User not found");
    }

    return user;
  }

  async getPublicProfile(username: string) {
    const user = await this.repository.findPublicProfile(username);
    if (!user) {
      throw new NotFoundError("Public profile not found");
    }

    if (user.privacySettings?.profileVisibility === "private") {
      throw new NotFoundError("Public profile not found");
    }

    return user;
  }

  async updateProfile(userId: string, input: Parameters<UserRepository["updateProfile"]>[1]) {
    const updated = await this.repository.updateProfile(userId, input);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.profile.update",
      resourceType: "user",
      resourceId: userId,
      targetUserId: userId,
      changes: input as Record<string, unknown>,
    });
    return updated;
  }

  async updatePrivacy(userId: string, input: Parameters<UserRepository["updatePrivacySettings"]>[1]) {
    await this.repository.updatePrivacySettings(userId, input);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.privacy.update",
      resourceType: "user_privacy_settings",
      resourceId: userId,
      targetUserId: userId,
      changes: input as Record<string, unknown>,
    });
    return this.getMe(userId);
  }

  async updateSecurity(userId: string, input: Parameters<UserRepository["updateSecuritySettings"]>[1]) {
    await this.repository.updateSecuritySettings(userId, input);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.security.update",
      resourceType: "user_security_settings",
      resourceId: userId,
      targetUserId: userId,
      changes: input as Record<string, unknown>,
    });
    return this.getMe(userId);
  }

  async updateNotifications(userId: string, input: Parameters<UserRepository["updateNotificationSettings"]>[1]) {
    await this.repository.updateNotificationSettings(userId, input);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.notifications.update",
      resourceType: "user_notification_settings",
      resourceId: userId,
      targetUserId: userId,
      changes: input as Record<string, unknown>,
    });
    return this.getMe(userId);
  }

  async updateTheme(userId: string, input: Parameters<UserRepository["updateThemeSettings"]>[1]) {
    await this.repository.updateThemeSettings(userId, input);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.theme.update",
      resourceType: "user_theme_settings",
      resourceId: userId,
      targetUserId: userId,
      changes: input as Record<string, unknown>,
    });
    return this.getMe(userId);
  }

  async updateEmail(userId: string, email: string) {
    const me = await this.repository.findPrivateProfile(userId);
    if (me?.email?.toLowerCase() === email.toLowerCase()) {
      throw new ConflictError("Email is already set to this value");
    }

    await this.repository.updateEmail(userId, email);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.email.update",
      resourceType: "user",
      resourceId: userId,
      targetUserId: userId,
      changes: { email },
    });
    return this.getMe(userId);
  }

  async updatePhone(userId: string, phone: string) {
    const me = await this.repository.findPrivateProfile(userId);
    if (me?.phone === phone) {
      throw new ConflictError("Phone is already set to this value");
    }

    await this.repository.updatePhone(userId, phone);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.phone.update",
      resourceType: "user",
      resourceId: userId,
      targetUserId: userId,
      changes: { phone },
    });
    return this.getMe(userId);
  }

  async requestArchive(userId: string) {
    const job = await this.repository.createArchiveJob(userId);
    await this.queueService.enqueueAnalytics({
      type: "account-archive-requested",
      userId,
      archiveJobId: job.id,
    });
    await this.auditService.log({
      actorUserId: userId,
      action: "user.archive.request",
      resourceType: "account_archive_job",
      resourceId: job.id,
      targetUserId: userId,
    });
    return job;
  }

  listArchiveJobs(userId: string) {
    return this.repository.listArchiveJobs(userId);
  }

  async scheduleDeletion(userId: string, reason?: string) {
    const request = await this.repository.createDeletionRequest(userId, reason);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.deletion.schedule",
      resourceType: "account_deletion_request",
      resourceId: request.id,
      targetUserId: userId,
      changes: { reason, scheduledFor: request.scheduledFor },
    });
    return request;
  }

  async recoverAccount(userId: string) {
    await this.repository.cancelDeletionRequest(userId);
    await this.auditService.log({
      actorUserId: userId,
      action: "user.deletion.cancel",
      resourceType: "account_deletion_request",
      resourceId: userId,
      targetUserId: userId,
    });
    return this.getMe(userId);
  }

  exportUserData(userId: string) {
    return this.repository.exportUserData(userId);
  }

  listActivity(userId: string, limit?: number) {
    return this.repository.listActivityLogs(userId, limit || 50);
  }

  listLoginHistory(userId: string, limit?: number) {
    return this.repository.listLoginHistory(userId, limit || 50);
  }
}
