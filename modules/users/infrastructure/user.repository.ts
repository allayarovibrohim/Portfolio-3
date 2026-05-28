import type { PrismaClient } from "@prisma/client";
import { addDays } from "../../../shared/utils/time";

const privateUserSelect = {
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
  createdAt: true,
  updatedAt: true,
  profile: true,
  privacySettings: true,
  securitySettings: true,
  notificationSettings: true,
  themeSettings: true,
  oauthAccounts: {
    select: {
      id: true,
      provider: true,
      providerAccountId: true,
      email: true,
      expiresAt: true,
      scope: true,
      createdAt: true,
      updatedAt: true,
    },
  },
  devices: {
    orderBy: {
      lastSeenAt: "desc" as const,
    },
  },
  sessions: {
    where: {
      revokedAt: null,
    },
    select: {
      id: true,
      status: true,
      ipAddress: true,
      country: true,
      city: true,
      region: true,
      userAgent: true,
      fingerprint: true,
      rememberMe: true,
      mfaPassedAt: true,
      lastActivityAt: true,
      expiresAt: true,
      revokedAt: true,
      revokeReason: true,
      createdAt: true,
      updatedAt: true,
      device: true,
      refreshTokens: {
        where: {
          revokedAt: null,
        },
        select: {
          id: true,
          tokenId: true,
          fingerprint: true,
          ipAddress: true,
          expiresAt: true,
          createdAt: true,
          rotatedAt: true,
        },
      },
    },
    orderBy: {
      lastActivityAt: "desc" as const,
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
  accountDeletion: true,
  archiveJobs: {
    orderBy: {
      requestedAt: "desc" as const,
    },
  },
} as const;

export class UserRepository {
  constructor(private readonly prisma: PrismaClient) {}

  findPrivateProfile(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: privateUserSelect,
    });
  }

  findPublicProfile(username: string) {
    return this.prisma.user.findUnique({
      where: {
        username: username.toLowerCase(),
      },
      select: {
        id: true,
        username: true,
        displayName: true,
        verifiedBadge: true,
        createdAt: true,
        profile: {
          select: {
            avatarUrl: true,
            bannerUrl: true,
            bio: true,
            website: true,
            socialLinks: true,
            country: true,
            language: true,
            timezone: true,
          },
        },
        privacySettings: {
          select: {
            profileVisibility: true,
            showBirthday: true,
            showEmail: true,
            showPhone: true,
          },
        },
      },
    });
  }

  updateProfile(
    userId: string,
    input: {
      displayName?: string;
      avatarUrl?: string;
      bannerUrl?: string;
      bio?: string;
      website?: string;
      socialLinks?: Record<string, unknown>;
      addressLine1?: string;
      addressLine2?: string;
      city?: string;
      state?: string;
      postalCode?: string;
      country?: string;
      language?: string;
      timezone?: string;
      gender?: "MALE" | "FEMALE" | "NON_BINARY" | "OTHER" | "PREFER_NOT_TO_SAY";
      birthday?: Date;
    },
  ) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        displayName: input.displayName,
        profile: {
          upsert: {
            update: {
              avatarUrl: input.avatarUrl,
              bannerUrl: input.bannerUrl,
              bio: input.bio,
              website: input.website,
              socialLinks: input.socialLinks,
              addressLine1: input.addressLine1,
              addressLine2: input.addressLine2,
              city: input.city,
              state: input.state,
              postalCode: input.postalCode,
              country: input.country,
              language: input.language,
              timezone: input.timezone,
              gender: input.gender,
              birthday: input.birthday,
            },
            create: {
              avatarUrl: input.avatarUrl,
              bannerUrl: input.bannerUrl,
              bio: input.bio,
              website: input.website,
              socialLinks: input.socialLinks,
              addressLine1: input.addressLine1,
              addressLine2: input.addressLine2,
              city: input.city,
              state: input.state,
              postalCode: input.postalCode,
              country: input.country,
              language: input.language,
              timezone: input.timezone,
              gender: input.gender,
              birthday: input.birthday,
            },
          },
        },
      },
      include: privateUserInclude,
    });
  }

  updatePrivacySettings(
    userId: string,
    input: {
      profileVisibility?: string;
      showBirthday?: boolean;
      showEmail?: boolean;
      showPhone?: boolean;
      allowMagicLinkLogin?: boolean;
      allowSearchByEmail?: boolean;
      allowSearchByPhone?: boolean;
      allowPresenceVisibility?: boolean;
      allowDataExport?: boolean;
    },
  ) {
    return this.prisma.userPrivacySettings.upsert({
      where: { userId },
      update: input,
      create: {
        userId,
        ...input,
      },
    });
  }

  updateSecuritySettings(
    userId: string,
    input: {
      magicLinkEnabled?: boolean;
      rememberMeEnabled?: boolean;
      deviceTrustDays?: number;
      suspiciousLoginAlerts?: boolean;
      passwordRotationDays?: number | null;
      sessionAbsoluteTtlDays?: number;
      sessionIdleTimeoutMins?: number;
      requireCaptchaAfterFails?: number;
    },
  ) {
    return this.prisma.userSecuritySettings.upsert({
      where: { userId },
      update: input,
      create: {
        userId,
        ...input,
      },
    });
  }

  updateNotificationSettings(
    userId: string,
    input: {
      marketingEmails?: boolean;
      productEmails?: boolean;
      securityEmails?: boolean;
      loginAlerts?: boolean;
      mentionNotifications?: boolean;
      pushEnabled?: boolean;
      smsEnabled?: boolean;
      digestFrequency?: string;
    },
  ) {
    return this.prisma.userNotificationSettings.upsert({
      where: { userId },
      update: input,
      create: {
        userId,
        ...input,
      },
    });
  }

  updateThemeSettings(
    userId: string,
    input: {
      theme?: string;
      accentColor?: string;
      density?: string;
      reducedMotion?: boolean;
    },
  ) {
    return this.prisma.userThemeSettings.upsert({
      where: { userId },
      update: input,
      create: {
        userId,
        ...input,
      },
    });
  }

  updateEmail(userId: string, email: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        email: email.toLowerCase(),
        emailVerifiedAt: null,
        status: "PENDING_VERIFICATION",
      },
    });
  }

  updatePhone(userId: string, phone: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        phone,
        phoneVerifiedAt: null,
      },
    });
  }

  createArchiveJob(userId: string) {
    return this.prisma.accountArchiveJob.create({
      data: {
        userId,
        status: "queued",
      },
    });
  }

  listArchiveJobs(userId: string) {
    return this.prisma.accountArchiveJob.findMany({
      where: { userId },
      orderBy: {
        requestedAt: "desc",
      },
    });
  }

  createDeletionRequest(userId: string, reason?: string) {
    return this.prisma.accountDeletionRequest.upsert({
      where: { userId },
      update: {
        reason,
        scheduledFor: addDays(new Date(), 14),
        canceledAt: null,
      },
      create: {
        userId,
        reason,
        scheduledFor: addDays(new Date(), 14),
      },
    });
  }

  cancelDeletionRequest(userId: string) {
    return this.prisma.accountDeletionRequest.updateMany({
      where: {
        userId,
        canceledAt: null,
      },
      data: {
        canceledAt: new Date(),
      },
    });
  }

  listLoginHistory(userId: string, limit = 50) {
    return this.prisma.loginAttempt.findMany({
      where: { userId },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });
  }

  listActivityLogs(userId: string, limit = 50) {
    return this.prisma.activityLog.findMany({
      where: { userId },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });
  }

  exportUserData(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        ...privateUserSelect,
        notifications: true,
        activityLogs: true,
        fileAssets: true,
        loginAttempts: true,
        securityEvents: true,
        subscriptions: {
          include: {
            plan: true,
            tenant: true,
            invoices: true,
          },
        },
        apiKeys: {
          select: {
            id: true,
            name: true,
            type: true,
            prefix: true,
            lastUsedAt: true,
            expiresAt: true,
            createdAt: true,
            revokedAt: true,
          },
        },
      },
    });
  }
}
