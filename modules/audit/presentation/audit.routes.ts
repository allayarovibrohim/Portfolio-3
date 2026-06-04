import type { FastifyInstance } from "fastify";
import { assertPermission } from "../../../shared/security/rbac";

export const registerAuditRoutes = async (
  app: FastifyInstance,
  dependencies: { auditService: { list?: (...args: never[]) => Promise<unknown> } },
) => {
  app.get("/v1/audit/logs", {
    preHandler: async (request) => {
      assertPermission(request.currentUser?.permissions || [], ["audit.read"]);
    },
  }, async (request) => {
    const logs = await app.prisma.auditLog.findMany({
      orderBy: { createdAt: "desc" },
      take: Number((request.query as { limit?: string }).limit || 100),
    });

    return { data: logs };
  });
};
