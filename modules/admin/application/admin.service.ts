import { getMetricsSnapshot } from "../../../core/monitoring/metrics";
import { AuditService } from "../../audit/application/audit.service";
import { NotificationService } from "../../notifications/application/notification.service";
import { QueueService } from "../../../services/queue/src/queue.service";
import { RealtimeService } from "../../../services/realtime/src/realtime.service";
import { AdminRepository } from "../infrastructure/admin.repository";
import { generateToken, hashValue } from "../../../shared/utils/crypto";

export class AdminService {
  constructor(
    private readonly repository: AdminRepository,
    private readonly auditService: AuditService,
    private readonly notificationService: NotificationService,
    private readonly queueService: QueueService,
    private readonly realtimeService: RealtimeService,
  ) {}

  async getDashboard() {
    const [core, queues, auditLogs, securityEvents, files] = await Promise.all([
      this.repository.getDashboardCore(),
      this.getQueueOverview(),
      this.repository.listAuditLogs(10),
      this.repository.listSecurityEvents(10),
      this.repository.latestFiles(10),
    ]);

    return {
      ...core,
      metrics: getMetricsSnapshot(),
      queues,
      recentAuditLogs: auditLogs,
      recentSecurityEvents: securityEvents,
      recentFiles: files,
    };
  }

  listUsers(filters: Parameters<AdminRepository["listUsers"]>[0]) {
    return this.repository.listUsers(filters);
  }

  getUserDetail(userId: string) {
    return this.repository.getUserDetail(userId);
  }

  async banUser(
    actorUserId: string,
    input: Parameters<AdminRepository["createBan"]>[0],
  ) {
    const ban = await this.repository.createBan({
      ...input,
      issuedById: actorUserId,
    });

    await this.auditService.log({
      actorUserId,
      action: "admin.user.ban",
      resourceType: "ban",
      resourceId: ban.id,
      targetUserId: input.userId,
      changes: {
        type: input.type,
        reason: input.reason,
        endsAt: input.endsAt,
      },
    });

    this.realtimeService.emitAdminDashboard({
      event: "user-ban-created",
      banId: ban.id,
      userId: input.userId,
    });

    return ban;
  }

  async assignRoles(actorUserId: string, userId: string, roleIds: string[]) {
    const roles = await this.repository.replaceUserRoles(userId, roleIds, actorUserId);
    await this.auditService.log({
      actorUserId,
      action: "admin.user.roles.update",
      resourceType: "user_role",
      resourceId: userId,
      targetUserId: userId,
      changes: {
        roleIds,
      },
    });
    return roles;
  }

  async createRole(actorUserId: string, input: Parameters<AdminRepository["upsertRole"]>[0]) {
    const role = await this.repository.upsertRole(input);
    await this.auditService.log({
      actorUserId,
      action: "admin.role.upsert",
      resourceType: "role",
      resourceId: role.id,
      changes: input as Record<string, unknown>,
    });
    return role;
  }

  async setRolePermissions(actorUserId: string, roleId: string, permissionKeys: string[]) {
    const role = await this.repository.setRolePermissions(roleId, permissionKeys);
    await this.auditService.log({
      actorUserId,
      action: "admin.role.permissions.update",
      resourceType: "role_permission",
      resourceId: roleId,
      changes: {
        permissionKeys,
      },
    });
    return role;
  }

  async listRbac() {
    const [roles, permissions] = await Promise.all([
      this.repository.listRoles(),
      this.repository.listPermissions(),
    ]);

    return { roles, permissions };
  }

  listFeatureFlags() {
    return this.repository.listFeatureFlags();
  }

  async updateFeatureFlag(
    actorUserId: string,
    key: string,
    enabled: boolean,
    payload?: Record<string, unknown>,
    description?: string,
  ) {
    const flag = await this.repository.upsertFeatureFlag(key, enabled, payload, description);
    await this.auditService.log({
      actorUserId,
      action: "admin.feature_flag.update",
      resourceType: "feature_flag",
      resourceId: flag.id,
      changes: {
        key,
        enabled,
        payload,
        description,
      },
    });
    this.realtimeService.emitAdminDashboard({
      event: "feature-flag-updated",
      key,
      enabled,
    });
    return flag;
  }

  listSettings() {
    return this.repository.listSettings();
  }

  async updateSetting(actorUserId: string, key: string, value: unknown, description?: string) {
    // 1. Asosiy tekshiruv: null yoki undefined bo'lmasligi kerak
    if (value === undefined || value === null) {
      throw new Error(`Setting value for ${key} cannot be empty`);
    }

    // 2. Kuchaytirilgan xavfsizlik (Data Wipe Protection):
    // Agar bazada ma'lumot bo'lsa-yu, yangi kelgan ma'lumot "bo'sh" bo'lsa, rad etamiz.
    const existingSettings = await this.repository.listSettings();
    const current = existingSettings.find(s => s.key === key);

    if (current) {
      // Qiymat haqiqatdan ham "bo'sh" yoki "nol" ekanligini tekshirish (resurs yuklanmagan holat uchun)
      const isEffectivelyEmpty = (val: any) => {
        if (val === null || val === undefined) return true;
        if (Array.isArray(val)) return val.length === 0;
        if (typeof val === 'string') return val.trim() === '' || val.trim() === '0';
        if (typeof val === 'number') return val === 0;
        if (typeof val === 'object') return Object.keys(val).length === 0;
        return false;
      };

      // Bazada haqiqiy ma'lumot borligini tekshirish
      const hasMeaningfulContent = (val: any) => {
        if (val === null || val === undefined) return false;
        if (Array.isArray(val)) return val.length > 0;
        if (typeof val === 'string') return val.trim() !== '' && val.trim() !== '0';
        if (typeof val === 'number') return val > 0;
        if (typeof val === 'object') return Object.keys(val).length > 0;
        return true;
      };

      // Agar brauzerda ma'lumot yuklanmagan bo'lsa va foydalanuvchi "Saqlash"ni bossa, 
      // bazadagi ma'lumotni o'chirib tashlashiga yo'l qo'ymaymiz.
      if (isEffectivelyEmpty(value) && hasMeaningfulContent(current.value)) {
        // Xatolik xabarini aniqroq qilamiz
        const error = new Error(`Xavfsizlik: Ma'lumotlar yuklanmagan! ${key} bazadan o'chib ketishi oldi olindi.`);
        (error as any).statusCode = 400;
        throw error;
      }
    }

    const setting = await this.repository.upsertSetting(key, value, description);
    await this.auditService.log({
      actorUserId,
      action: "admin.setting.update",
      resourceType: "app_setting",
      resourceId: setting.id,
      changes: { key, value, description },
    });
    return setting;
  }

  async getSecurityOverview() {
    const [events, auditLogs, loginFailures] = await Promise.all([
      this.repository.listSecurityEvents(100),
      this.repository.listAuditLogs(50),
      this.repository.listUsers({
        page: 1,
        pageSize: 20,
        status: "LOCKED",
      }),
    ]);

    return {
      events,
      auditLogs,
      lockedAccounts: loginFailures,
      metrics: getMetricsSnapshot(),
    };
  }

  async getQueueOverview() {
    const queues = this.queueService.getQueues();
    const keys = Object.keys(queues) as Array<keyof typeof queues>;
    const result: Record<string, unknown> = {};

    for (const key of keys) {
      result[key] = await queues[key].getJobCounts(
        "waiting",
        "active",
        "completed",
        "failed",
        "delayed",
      );
    }

    return result;
  }

  async broadcastNotification(
    actorUserId: string,
    input: {
      title: string;
      body: string;
      type: string;
      actionUrl?: string;
      payload?: Record<string, unknown>;
    },
  ) {
    await this.queueService.enqueueNotification({
      kind: "broadcast-notification",
      initiatedBy: actorUserId,
      ...input,
    });

    await this.auditService.log({
      actorUserId,
      action: "admin.notification.broadcast",
      resourceType: "notification",
      changes: input as Record<string, unknown>,
    });

    return { queued: true };
  }

  async broadcastEmail(
    actorUserId: string,
    input: {
      subject: string;
      html: string;
      segment?: string;
    },
  ) {
    await this.queueService.enqueueEmail({
      kind: "broadcast-email",
      initiatedBy: actorUserId,
      ...input,
    });

    await this.auditService.log({
      actorUserId,
      action: "admin.email.broadcast",
      resourceType: "email",
      changes: input as Record<string, unknown>,
    });

    return { queued: true };
  }

  listAuditLogs(limit?: number) {
    return this.repository.listAuditLogs(limit || 100);
  }

  listSecurityEvents(limit?: number) {
    return this.repository.listSecurityEvents(limit || 100);
  }

  listApiKeys(limit?: number) {
    return this.repository.listApiKeys(limit || 100);
  }

  async createApiKey(
    actorUserId: string,
    input: {
      userId: string;
      name: string;
      type: "INTERNAL" | "PUBLIC" | "PRIVATE" | "ADMIN";
      expiresAt?: Date;
    },
  ) {
    const prefix = `lnx_${generateToken(4)}`;
    const rawSecret = generateToken(24);
    const stored = await this.repository.createApiKey({
      userId: input.userId,
      name: input.name,
      type: input.type,
      prefix,
      hashedSecret: hashValue(rawSecret),
      expiresAt: input.expiresAt,
    });

    await this.auditService.log({
      actorUserId,
      action: "admin.api_key.create",
      resourceType: "api_key",
      resourceId: stored.id,
      targetUserId: input.userId,
      changes: {
        type: input.type,
        name: input.name,
      },
    });

    return {
      id: stored.id,
      name: stored.name,
      type: stored.type,
      prefix: stored.prefix,
      secret: `${prefix}.${rawSecret}`,
      expiresAt: stored.expiresAt,
      createdAt: stored.createdAt,
    };
  }

  async revokeApiKey(actorUserId: string, apiKeyId: string) {
    const apiKey = await this.repository.revokeApiKey(apiKeyId);
    await this.auditService.log({
      actorUserId,
      action: "admin.api_key.revoke",
      resourceType: "api_key",
      resourceId: apiKey.id,
      targetUserId: apiKey.userId,
    });
    return apiKey;
  }

  listFiles(limit?: number) {
    return this.repository.latestFiles(limit || 100);
  }
}
