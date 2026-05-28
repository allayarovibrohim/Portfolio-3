import type { PrismaClient } from "@prisma/client";

export interface AuditLogInput {
  actorUserId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  targetUserId?: string;
  ipAddress?: string;
  requestId?: string;
  changes?: Record<string, unknown>;
  context?: Record<string, unknown>;
}

export class AuditService {
  constructor(private readonly prisma: PrismaClient) {}

  log(input: AuditLogInput) {
    return this.prisma.auditLog.create({
      data: {
        actorUserId: input.actorUserId,
        action: input.action,
        resourceType: input.resourceType,
        resourceId: input.resourceId,
        targetUserId: input.targetUserId,
        ipAddress: input.ipAddress,
        requestId: input.requestId,
        changes: input.changes,
        context: input.context,
      },
    });
  }
}
