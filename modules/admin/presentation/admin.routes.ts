import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { requirePermissions } from "../../../shared/http/guards";

export const registerAdminRoutes = async (
  app: FastifyInstance,
  dependencies: {
    adminService: {
      getDashboard: (...args: never[]) => Promise<any>;
      listUsers: (...args: never[]) => Promise<any>;
      getUserDetail: (...args: never[]) => Promise<any>;
      banUser: (...args: never[]) => Promise<any>;
      assignRoles: (...args: never[]) => Promise<any>;
      createRole: (...args: never[]) => Promise<any>;
      setRolePermissions: (...args: never[]) => Promise<any>;
      listRbac: (...args: never[]) => Promise<any>;
      listFeatureFlags: (...args: never[]) => Promise<any>;
      updateFeatureFlag: (...args: never[]) => Promise<any>;
      listSettings: (...args: never[]) => Promise<any>;
      updateSetting: (...args: never[]) => Promise<any>;
      getSecurityOverview: (...args: never[]) => Promise<any>;
      getQueueOverview: (...args: never[]) => Promise<any>;
      broadcastNotification: (...args: never[]) => Promise<any>;
      broadcastEmail: (...args: never[]) => Promise<any>;
      listAuditLogs: (...args: never[]) => Promise<any>;
      listSecurityEvents: (...args: never[]) => Promise<any>;
      listApiKeys: (...args: never[]) => Promise<any>;
      createApiKey: (...args: never[]) => Promise<any>;
      revokeApiKey: (...args: never[]) => Promise<any>;
      listFiles: (...args: never[]) => Promise<any>;
    };
  },
) => {
  app.get("/v1/admin/dashboard", async (request) => {
    requirePermissions(request, ["admin.dashboard.read"]);
    return { data: await dependencies.adminService.getDashboard() };
  });

  app.get("/v1/admin/users", async (request) => {
    requirePermissions(request, ["admin.users.read"]);
    const query = z.object({
      page: z.coerce.number().int().positive().default(1),
      pageSize: z.coerce.number().int().positive().max(100).default(20),
      q: z.string().optional(),
      status: z.string().optional(),
    }).parse(request.query);
    return { data: await dependencies.adminService.listUsers(query) };
  });

  app.get("/v1/admin/users/:userId", async (request) => {
    requirePermissions(request, ["admin.users.read"]);
    const params = z.object({ userId: z.string().uuid() }).parse(request.params);
    return { data: await dependencies.adminService.getUserDetail(params.userId) };
  });

  app.post("/v1/admin/users/:userId/ban", async (request) => {
    const currentUser = requirePermissions(request, ["admin.users.write"]);
    const params = z.object({ userId: z.string().uuid() }).parse(request.params);
    const body = z.object({
      type: z.enum(["HARD", "SHADOW", "MUTE", "RESTRICT"]),
      reason: z.string().min(3),
      endsAt: z.coerce.date().optional(),
    }).parse(request.body);
    return {
      data: await dependencies.adminService.banUser(currentUser.id, {
        userId: params.userId,
        type: body.type,
        reason: body.reason,
        endsAt: body.endsAt,
      }),
    };
  });

  app.post("/v1/admin/users/:userId/roles", async (request) => {
    const currentUser = requirePermissions(request, ["admin.roles.write"]);
    const params = z.object({ userId: z.string().uuid() }).parse(request.params);
    const body = z.object({ roleIds: z.array(z.string().uuid()).default([]) }).parse(request.body);
    return { data: await dependencies.adminService.assignRoles(currentUser.id, params.userId, body.roleIds) };
  });

  app.get("/v1/admin/rbac", async (request) => {
    requirePermissions(request, ["admin.roles.read"]);
    return { data: await dependencies.adminService.listRbac() };
  });

  app.post("/v1/admin/roles", async (request) => {
    const currentUser = requirePermissions(request, ["admin.roles.write"]);
    const body = z.object({
      name: z.string().min(2),
      description: z.string().optional(),
      system: z.boolean().optional(),
    }).parse(request.body);
    return { data: await dependencies.adminService.createRole(currentUser.id, body) };
  });

  app.post("/v1/admin/roles/:roleId/permissions", async (request) => {
    const currentUser = requirePermissions(request, ["admin.roles.write"]);
    const params = z.object({ roleId: z.string().uuid() }).parse(request.params);
    const body = z.object({ permissionKeys: z.array(z.string().min(2)).default([]) }).parse(request.body);
    return {
      data: await dependencies.adminService.setRolePermissions(
        currentUser.id,
        params.roleId,
        body.permissionKeys,
      ),
    };
  });

  app.get("/v1/admin/feature-flags", async (request) => {
    requirePermissions(request, ["admin.settings.read"]);
    return { data: await dependencies.adminService.listFeatureFlags() };
  });

  app.patch("/v1/admin/feature-flags/:key", async (request) => {
    const currentUser = requirePermissions(request, ["admin.settings.write"]);
    const params = z.object({ key: z.string().min(1) }).parse(request.params);
    const body = z.object({
      enabled: z.boolean(),
      payload: z.record(z.string(), z.unknown()).optional(),
      description: z.string().optional(),
    }).parse(request.body);
    return {
      data: await dependencies.adminService.updateFeatureFlag(
        currentUser.id,
        params.key,
        body.enabled,
        body.payload,
        body.description,
      ),
    };
  });

  app.get("/v1/admin/settings", async (request) => {
    requirePermissions(request, ["admin.settings.read"]);
    return { data: await dependencies.adminService.listSettings() };
  });

  app.put("/v1/admin/settings/:key", async (request) => {
    const currentUser = requirePermissions(request, ["admin.settings.write"]);
    const params = z.object({ key: z.string().min(1) }).parse(request.params);
    const body = z.object({
      value: z.unknown(),
      description: z.string().optional(),
    }).parse(request.body);
    return {
      data: await dependencies.adminService.updateSetting(
        currentUser.id,
        params.key,
        body.value,
        body.description,
      ),
    };
  });

  app.get("/v1/admin/security/overview", async (request) => {
    requirePermissions(request, ["security.read"]);
    return { data: await dependencies.adminService.getSecurityOverview() };
  });

  app.get("/v1/admin/queues", async (request) => {
    requirePermissions(request, ["queue.read"]);
    return { data: await dependencies.adminService.getQueueOverview() };
  });

  app.post("/v1/admin/broadcast/notification", async (request) => {
    const currentUser = requirePermissions(request, ["notifications.broadcast"]);
    const body = z.object({
      title: z.string().min(1),
      body: z.string().min(1),
      type: z.string().min(1),
      actionUrl: z.string().url().optional(),
      payload: z.record(z.string(), z.unknown()).optional(),
    }).parse(request.body);
    return { data: await dependencies.adminService.broadcastNotification(currentUser.id, body) };
  });

  app.post("/v1/admin/broadcast/email", async (request) => {
    const currentUser = requirePermissions(request, ["emails.broadcast"]);
    const body = z.object({
      subject: z.string().min(1),
      html: z.string().min(1),
      segment: z.string().optional(),
    }).parse(request.body);
    return { data: await dependencies.adminService.broadcastEmail(currentUser.id, body) };
  });

  app.get("/v1/admin/audit-logs", async (request) => {
    requirePermissions(request, ["audit.read"]);
    const query = z.object({ limit: z.coerce.number().int().positive().max(500).default(100) }).parse(request.query);
    return { data: await dependencies.adminService.listAuditLogs(query.limit) };
  });

  app.get("/v1/admin/security-events", async (request) => {
    requirePermissions(request, ["security.read"]);
    const query = z.object({ limit: z.coerce.number().int().positive().max(500).default(100) }).parse(request.query);
    return { data: await dependencies.adminService.listSecurityEvents(query.limit) };
  });

  app.get("/v1/admin/api-keys", async (request) => {
    requirePermissions(request, ["api_keys.read"]);
    const query = z.object({ limit: z.coerce.number().int().positive().max(500).default(100) }).parse(request.query);
    return { data: await dependencies.adminService.listApiKeys(query.limit) };
  });

  app.post("/v1/admin/api-keys", async (request) => {
    const currentUser = requirePermissions(request, ["api_keys.write"]);
    const body = z.object({
      userId: z.string().uuid(),
      name: z.string().min(1),
      type: z.enum(["INTERNAL", "PUBLIC", "PRIVATE", "ADMIN"]),
      expiresAt: z.coerce.date().optional(),
    }).parse(request.body);
    return { data: await dependencies.adminService.createApiKey(currentUser.id, body) };
  });

  app.post("/v1/admin/api-keys/:apiKeyId/revoke", async (request) => {
    const currentUser = requirePermissions(request, ["api_keys.write"]);
    const params = z.object({ apiKeyId: z.string().uuid() }).parse(request.params);
    return { data: await dependencies.adminService.revokeApiKey(currentUser.id, params.apiKeyId) };
  });

  app.get("/v1/admin/files", async (request) => {
    requirePermissions(request, ["files.read"]);
    const query = z.object({ limit: z.coerce.number().int().positive().max(500).default(100) }).parse(request.query);
    return { data: await dependencies.adminService.listFiles(query.limit) };
  });
};
