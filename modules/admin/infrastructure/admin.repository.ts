import type { PrismaClient } from "@prisma/client";

export interface UserListFilters {
  page: number;
  pageSize: number;
  q?: string;
  status?: string;
}

export class AdminRepository {
  constructor(private readonly prisma: PrismaClient) {}

  private readonly adminUserSelect = {
    id: true,
    email: true,
    phone: true,
    username: true,
    displayName: true,
    status: true,
    verifiedBadge: true,
    emailVerifiedAt: true,
    phoneVerifiedAt: true,
    lastLoginAt: true,
    failedLoginCount: true,
    lockUntil: true,
    deletedAt: true,
    createdAt: true,
    updatedAt: true,
    profile: true,
    privacySettings: true,
    securitySettings: true,
    notificationSettings: true,
    themeSettings: true,
  } as const;

  async getDashboardCore() {
    const [
      totalUsers,
      activeUsers,
      activeSessions,
      onlineUsers,
      totalFiles,
      totalNotifications,
      totalApiKeys,
      failedLogins24h,
      suspiciousEvents24h,
      queuedArchives,
      paidInvoices,
      activeSubscriptions,
    ] = await Promise.all([
      this.prisma.user.count({
        where: {
          deletedAt: null,
        },
      }),
      this.prisma.user.count({
        where: {
          status: "ACTIVE",
          deletedAt: null,
        },
      }),
      this.prisma.userSession.count({
        where: {
          revokedAt: null,
          status: "ACTIVE",
        },
      }),
      this.prisma.userSession.count({
        where: {
          revokedAt: null,
          status: "ACTIVE",
          lastActivityAt: {
            gte: new Date(Date.now() - 5 * 60 * 1000),
          },
        },
      }),
      this.prisma.fileAsset.count(),
      this.prisma.notification.count(),
      this.prisma.apiKey.count({
        where: {
          revokedAt: null,
        },
      }),
      this.prisma.loginAttempt.count({
        where: {
          success: false,
          createdAt: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
          },
        },
      }),
      this.prisma.securityEvent.count({
        where: {
          severity: {
            in: ["HIGH", "CRITICAL"],
          },
          createdAt: {
            gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
          },
        },
      }),
      this.prisma.accountArchiveJob.count({
        where: {
          status: "queued",
        },
      }),
      this.prisma.invoice.aggregate({
        where: {
          paid: true,
        },
        _sum: {
          amount: true,
        },
      }),
      this.prisma.subscription.count({
        where: {
          status: "ACTIVE",
        },
      }),
    ]);

    const recentSessions = await this.prisma.userSession.findMany({
      where: {
        revokedAt: null,
        country: {
          not: null,
        },
      },
      select: {
        country: true,
      },
      take: 1000,
      orderBy: {
        lastActivityAt: "desc",
      },
    });

    const countryCounts = recentSessions.reduce<Record<string, number>>((acc, item) => {
      if (!item.country) {
        return acc;
      }

      acc[item.country] = (acc[item.country] || 0) + 1;
      return acc;
    }, {});

    return {
      totalUsers,
      activeUsers,
      activeSessions,
      onlineUsers,
      totalFiles,
      totalNotifications,
      totalApiKeys,
      failedLogins24h,
      suspiciousEvents24h,
      queuedArchives,
      activeSubscriptions,
      revenueTotal: paidInvoices._sum.amount,
      topCountries: Object.entries(countryCounts)
        .sort((left, right) => right[1] - left[1])
        .slice(0, 10)
        .map(([country, count]) => ({ country, count })),
    };
  }

  async listUsers(filters: UserListFilters) {
    const where = {
      ...(filters.status ? { status: filters.status as any } : {}),
      ...(filters.q
        ? {
            OR: [
              { username: { contains: filters.q, mode: "insensitive" as const } },
              { displayName: { contains: filters.q, mode: "insensitive" as const } },
              { email: { contains: filters.q, mode: "insensitive" as const } },
              { phone: { contains: filters.q } },
            ],
          }
        : {}),
    };

    const [items, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        select: {
          ...this.adminUserSelect,
          userRoles: {
            include: {
              role: true,
            },
          },
          sessions: {
            where: {
              revokedAt: null,
            },
            take: 3,
            orderBy: {
              lastActivityAt: "desc",
            },
          },
        },
        orderBy: {
          createdAt: "desc",
        },
        take: filters.pageSize,
        skip: (filters.page - 1) * filters.pageSize,
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      items,
      total,
      page: filters.page,
      pageSize: filters.pageSize,
    };
  }

  getUserDetail(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        ...this.adminUserSelect,
        devices: true,
        sessions: {
          select: {
            id: true,
            status: true,
            ipAddress: true,
            country: true,
            city: true,
            region: true,
            fingerprint: true,
            rememberMe: true,
            lastActivityAt: true,
            expiresAt: true,
            revokedAt: true,
            revokeReason: true,
            createdAt: true,
            updatedAt: true,
            device: true,
            refreshTokens: {
              select: {
                id: true,
                tokenId: true,
                fingerprint: true,
                ipAddress: true,
                expiresAt: true,
                createdAt: true,
                rotatedAt: true,
                revokedAt: true,
              },
            },
          },
          orderBy: {
            lastActivityAt: "desc",
          },
        },
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
        bans: true,
        notifications: {
          take: 20,
          orderBy: {
            createdAt: "desc",
          },
        },
        fileAssets: {
          take: 20,
          orderBy: {
            createdAt: "desc",
          },
        },
      },
    });
  }

  createBan(input: {
    userId: string;
    issuedById?: string;
    type: "HARD" | "SHADOW" | "MUTE" | "RESTRICT";
    reason: string;
    endsAt?: Date;
  }) {
    return this.prisma.ban.create({
      data: {
        userId: input.userId,
        issuedById: input.issuedById,
        type: input.type,
        reason: input.reason,
        endsAt: input.endsAt,
      },
    });
  }

  async replaceUserRoles(userId: string, roleIds: string[], assignedById?: string) {
    await this.prisma.userRole.deleteMany({
      where: { userId },
    });

    if (roleIds.length === 0) {
      return [];
    }

    await this.prisma.userRole.createMany({
      data: roleIds.map((roleId) => ({
        userId,
        roleId,
        assignedById,
      })),
      skipDuplicates: true,
    });

    return this.prisma.userRole.findMany({
      where: { userId },
      include: {
        role: {
          include: {
            permissions: {
              include: {
                permission: true,
              },
            },
          },
        },
      },
    });
  }

  listRoles() {
    return this.prisma.role.findMany({
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
        users: true,
      },
      orderBy: {
        name: "asc",
      },
    });
  }

  listPermissions() {
    return this.prisma.permission.findMany({
      orderBy: [{ group: "asc" }, { key: "asc" }],
    });
  }

  upsertRole(input: { name: string; description?: string; system?: boolean }) {
    return this.prisma.role.upsert({
      where: { name: input.name },
      update: {
        description: input.description,
        system: input.system,
      },
      create: {
        name: input.name,
        description: input.description,
        system: input.system || false,
      },
    });
  }

  async setRolePermissions(roleId: string, permissionKeys: string[]) {
    const permissions = await Promise.all(
      permissionKeys.map((key) =>
        this.prisma.permission.upsert({
          where: { key },
          update: {},
          create: {
            key,
            group: key.includes(".") ? key.split(".")[0] : "custom",
            description: key,
          },
        }),
      ),
    );

    await this.prisma.rolePermission.deleteMany({
      where: { roleId },
    });

    if (permissions.length > 0) {
      await this.prisma.rolePermission.createMany({
        data: permissions.map((permission) => ({
          roleId,
          permissionId: permission.id,
        })),
        skipDuplicates: true,
      });
    }

    return this.prisma.role.findUnique({
      where: { id: roleId },
      include: {
        permissions: {
          include: {
            permission: true,
          },
        },
      },
    });
  }

  listFeatureFlags() {
    return this.prisma.featureFlag.findMany({
      orderBy: {
        key: "asc",
      },
    });
  }

  upsertFeatureFlag(key: string, enabled: boolean, payload?: Record<string, unknown>, description?: string) {
    return this.prisma.featureFlag.upsert({
      where: { key },
      update: {
        enabled,
        payload,
        description,
      },
      create: {
        key,
        enabled,
        payload,
        description,
      },
    });
  }

  listSettings() {
    return this.prisma.appSetting.findMany({
      orderBy: {
        key: "asc",
      },
    });
  }

  upsertSetting(key: string, value: unknown, description?: string) {
    return this.prisma.appSetting.upsert({
      where: { key },
      update: {
        value: value as never,
        description,
      },
      create: {
        key,
        value: value as never,
        description,
      },
    });
  }

  listAuditLogs(limit = 100) {
    return this.prisma.auditLog.findMany({
      include: {
        actor: {
          select: {
            id: true,
            username: true,
            displayName: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });
  }

  listSecurityEvents(limit = 100) {
    return this.prisma.securityEvent.findMany({
      include: {
        user: {
          select: {
            id: true,
            username: true,
            email: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });
  }

  listApiKeys(limit = 100) {
    return this.prisma.apiKey.findMany({
      include: {
        user: {
          select: {
            id: true,
            username: true,
            email: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });
  }

  createApiKey(input: {
    userId: string;
    name: string;
    type: "INTERNAL" | "PUBLIC" | "PRIVATE" | "ADMIN";
    prefix: string;
    hashedSecret: string;
    expiresAt?: Date;
  }) {
    return this.prisma.apiKey.create({
      data: {
        userId: input.userId,
        name: input.name,
        type: input.type,
        prefix: input.prefix,
        hashedSecret: input.hashedSecret,
        expiresAt: input.expiresAt,
      },
    });
  }

  revokeApiKey(id: string) {
    return this.prisma.apiKey.update({
      where: { id },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  latestFiles(limit = 100) {
    return this.prisma.fileAsset.findMany({
      include: {
        user: {
          select: {
            id: true,
            username: true,
          },
        },
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });
  }
}
