import type { FastifyInstance } from "fastify";
import { getMetricsSnapshot } from "../../../core/monitoring/metrics";

export const registerSystemRoutes = async (app: FastifyInstance) => {
  app.get("/v1/health/live", async () => ({
    status: "ok",
    service: "lunex-enterprise-api",
    ts: new Date().toISOString(),
  }));

  app.get("/v1/health/ready", async () => {
    await app.prisma.$queryRaw`SELECT 1`;
    await app.redis.ping();

    return {
      status: "ready",
      checks: {
        database: "ok",
        redis: "ok",
      },
    };
  });

  app.get("/v1/metrics", async () => ({
    data: getMetricsSnapshot(),
  }));

  app.get("/v1/security/csrf-token", async (_request, reply) => ({
    data: {
      csrfToken: (reply as typeof reply & { generateCsrf: () => string }).generateCsrf(),
    },
  }));
};
