import { randomUUID } from "crypto";
import type { FastifyReply, FastifyRequest } from "fastify";

export interface RequestUser {
  id: string;
  sessionId?: string;
  deviceId?: string;
  roles: string[];
  permissions: string[];
  fingerprint?: string;
}

export const attachRequestContext = async (request: FastifyRequest, reply: FastifyReply) => {
  const requestId = (request.headers["x-request-id"] as string | undefined) || randomUUID();
  request.requestContext = { requestId };
  reply.header("x-request-id", requestId);
};
