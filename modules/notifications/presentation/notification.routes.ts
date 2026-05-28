import type { FastifyInstance } from "fastify";
import { UnauthorizedError } from "../../../shared/http/errors";

export const registerNotificationRoutes = async (
  app: FastifyInstance,
  dependencies: { notificationService: { listForUser: (userId: string) => Promise<unknown>; markAllRead: (userId: string) => Promise<unknown> } },
) => {
  app.get("/v1/notifications", async (request) => {
    if (!request.currentUser) {
      throw new UnauthorizedError();
    }

    return {
      data: await dependencies.notificationService.listForUser(request.currentUser.id),
    };
  });

  app.post("/v1/notifications/read-all", async (request) => {
    if (!request.currentUser) {
      throw new UnauthorizedError();
    }

    await dependencies.notificationService.markAllRead(request.currentUser.id);
    return { ok: true };
  });
};
