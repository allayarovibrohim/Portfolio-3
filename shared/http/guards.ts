import type { FastifyRequest } from "fastify";
import { UnauthorizedError } from "./errors";
import { assertPermission } from "../security/rbac";

export const requireCurrentUser = (request: FastifyRequest) => {
  if (!request.currentUser) {
    throw new UnauthorizedError();
  }

  return request.currentUser;
};

export const requirePermissions = (request: FastifyRequest, permissions: string[]) => {
  const currentUser = requireCurrentUser(request);
  assertPermission(currentUser.permissions, permissions);
  return currentUser;
};
