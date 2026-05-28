import { env } from "../../../config/env";
import { buildSocketServer } from "../../../core/socket/socket.server";
import { buildApp } from "./app";

const start = async () => {
  const app = buildApp();

  try {
    await app.ready();
    buildSocketServer(app.server);
    await app.container.queueService.enqueueCleanup({
      jobId: "system-cleanup-hourly",
      repeat: {
        every: 60 * 60 * 1000,
      },
    });
    await app.listen({
      host: env.HOST,
      port: env.PORT,
    });

    app.container.logger.info("server.started", {
      host: env.HOST,
      port: env.PORT,
      apiPrefix: env.API_PREFIX,
    });
  } catch (error) {
    app.container.logger.error("server.failed", {
      error,
    });
    process.exit(1);
  }
};

void start();
