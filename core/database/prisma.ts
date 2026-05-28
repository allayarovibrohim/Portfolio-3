import { PrismaClient } from "@prisma/client";
import { logger } from "../logger/winston";

const globalForPrisma = globalThis as unknown as {
  prisma?: PrismaClient;
};

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: [
      { emit: "event", level: "query" },
      { emit: "event", level: "error" },
      { emit: "stdout", level: "warn" },
    ],
  });

prisma.$on("query", (event) => {
  logger.debug("prisma.query", {
    query: event.query,
    durationMs: event.duration,
  });
});

prisma.$on("error", (event) => {
  logger.error("prisma.error", {
    message: event.message,
    target: event.target,
  });
});

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}
