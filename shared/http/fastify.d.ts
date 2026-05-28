import "fastify";
import type Redis from "ioredis";
import type { PrismaClient } from "@prisma/client";
import type { AppContext } from "../contracts/app-context";
import type { RequestUser } from "./request-context";

declare module "fastify" {
  interface FastifyInstance {
    container: AppContext & Record<string, unknown>;
    prisma: PrismaClient;
    redis: Redis;
  }

  interface FastifyRequest {
    currentUser?: RequestUser;
    requestContext: {
      requestId: string;
    };
  }
}
