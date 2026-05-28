import type { PrismaClient } from "@prisma/client";
import { addDays, addMinutes } from "../../../shared/utils/time";

const authUserInclude = {
  profile: true,
  privacySettings: true,
  securitySettings: true,
  notificationSettings: true,
  themeSettings: true,
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
  bans: {
    where: {
      active: true,
      OR: [{ endsAt: null }, { endsAt: { gt: new Date() } }],
    },
    orderBy: {
      createdAt: "desc" as const,
    },
  },
} as const;

export interface CreateUserInput {
  email?: string | null;
  phone?: string | null;
  username: string;
  displayName: string;
  passwordHash?: string | null;
  emailVerifiedAt?: Date | null;
  phoneVerifiedAt?: Date | null;
  status?: "ACTIVE" | "PENDING_VERIFICATION";
}

export interface LoginAttemptInput {
  userId?: string;
  email?: string;
  phone?: string;
  username?: string;
  ipAddress?: string;
  userAgent?: string;
  fingerprint?: string;
  success: boolean;
  captchaRequired?: boolean;
  blocked?: boolean;
  country?: string;
  city?: string;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface SecurityEventInput {
  userId?: string;
  type: string;
  description: string;
  severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  ipAddress?: string;
  fingerprint?: string;
  country?: string;
  city?: string;
  meta?: Record<string, unknown>;
}

export class AuthRepository {
  constructor(private readonly prisma: PrismaClient) {}

  findUserByIdentifier(identifier: string) {
    const normalized = identifier.trim().toLowerCase();

    return this.prisma.user.findFirst({
      where: {
        OR: [{ email: normalized }, { username: normalized }, { phone: identifier.trim() }],
      },
      include: authUserInclude,
    });
  }

  findUserByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
      include: authUserInclude,
    });
  }

  findUserById(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      include: authUserInclude,
    });
  }

  async usernameExists(username: string) {
    const result = await this.prisma.user.count({
      where: { username: username.toLowerCase() },
    });

    return result > 0;
  }

  async createUser(input: CreateUserInput) {
    const role = await this.prisma.role.upsert({
      where: { name: "user" },
      update: {},
      create: {
        name: "user",
        description: "Default end-user role",
        system: true,
      },
    });

    return this.prisma.user.create({
      data: {
        email: input.email?.toLowerCase() || null,
        phone: input.phone || null,
        username: input.username.toLowerCase(),
        displayName: input.displayName,
        passwordHash: input.passwordHash || null,
        status: input.status || "PENDING_VERIFICATION",
        emailVerifiedAt: input.emailVerifiedAt || null,
        phoneVerifiedAt: input.phoneVerifiedAt || null,
        profile: {
          create: {},
        },
        privacySettings: {
          create: {},
        },
        securitySettings: {
          create: {},
        },
        notificationSettings: {
          create: {},
        },
        themeSettings: {
          create: {},
        },
        userRoles: {
          create: {
            roleId: role.id,
          },
        },
      },
      include: authUserInclude,
    });
  }

  appendPasswordHistory(userId: string, passwordHash: string) {
    return this.prisma.passwordHistory.create({
      data: {
        userId,
        passwordHash,
      },
    });
  }

  async getRecentPasswordHashes(userId: string, limit = 5) {
    const entries = await this.prisma.passwordHistory.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      take: limit,
    });

    return entries.map((entry) => entry.passwordHash);
  }

  recordLoginAttempt(input: LoginAttemptInput) {
    return this.prisma.loginAttempt.create({
      data: {
        userId: input.userId,
        email: input.email,
        phone: input.phone,
        username: input.username,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
        fingerprint: input.fingerprint,
        success: input.success,
        captchaRequired: input.captchaRequired || false,
        blocked: input.blocked || false,
        country: input.country,
        city: input.city,
        severity: input.severity || "LOW",
      },
    });
  }

  createSecurityEvent(input: SecurityEventInput) {
    return this.prisma.securityEvent.create({
      data: {
        userId: input.userId,
        type: input.type,
        description: input.description,
        severity: input.severity || "MEDIUM",
        ipAddress: input.ipAddress,
        fingerprint: input.fingerprint,
        country: input.country,
        city: input.city,
        meta: input.meta,
      },
    });
  }

  createActivityLog(userId: string, type: string, description: string, metadata?: Record<string, unknown>) {
    return this.prisma.activityLog.create({
      data: {
        userId,
        type,
        description,
        metadata,
      },
    });
  }

  updateUserAfterSuccessfulLogin(userId: string, now: Date) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginCount: 0,
        lockUntil: null,
        lastLoginAt: now,
        status: "ACTIVE",
      },
    });
  }

  updateUserAfterFailedLogin(userId: string, failedLoginCount: number, lockUntil?: Date | null) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginCount,
        lockUntil: lockUntil || null,
        status: lockUntil ? "LOCKED" : undefined,
      },
    });
  }

  async markEmailVerified(userId: string, email?: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        email: email ? email.toLowerCase() : undefined,
        emailVerifiedAt: new Date(),
        status: "ACTIVE",
      },
    });
  }

  async markPhoneVerified(userId: string, phone?: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        phone: phone || undefined,
        phoneVerifiedAt: new Date(),
        status: "ACTIVE",
      },
    });
  }

  async updatePassword(userId: string, passwordHash: string) {
    return this.prisma.user.update({
      where: { id: userId },
      data: {
        passwordHash,
        passwordChangedAt: new Date(),
      },
    });
  }

  findDeviceByFingerprint(userId: string, fingerprint: string) {
    return this.prisma.device.findUnique({
      where: {
        userId_fingerprint: {
          userId,
          fingerprint,
        },
      },
    });
  }

  upsertDevice(
    userId: string,
    fingerprint: string,
    input: {
      name?: string;
      type?: string;
      userAgent?: string;
      platform?: string;
      browser?: string;
      lastIp?: string;
      lastCountry?: string;
    },
  ) {
    return this.prisma.device.upsert({
      where: {
        userId_fingerprint: {
          userId,
          fingerprint,
        },
      },
      update: {
        name: input.name,
        type: input.type,
        userAgent: input.userAgent,
        platform: input.platform,
        browser: input.browser,
        lastIp: input.lastIp,
        lastCountry: input.lastCountry,
        lastSeenAt: new Date(),
      },
      create: {
        userId,
        fingerprint,
        name: input.name,
        type: input.type,
        userAgent: input.userAgent,
        platform: input.platform,
        browser: input.browser,
        lastIp: input.lastIp,
        lastCountry: input.lastCountry,
        lastSeenAt: new Date(),
      },
    });
  }

  createSession(input: {
    userId: string;
    deviceId?: string;
    fingerprint: string;
    ipAddress?: string;
    userAgent?: string;
    country?: string;
    city?: string;
    region?: string;
    latitude?: number;
    longitude?: number;
    rememberMe?: boolean;
    expiresAt: Date;
  }) {
    return this.prisma.userSession.create({
      data: {
        userId: input.userId,
        deviceId: input.deviceId,
        fingerprint: input.fingerprint,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
        country: input.country,
        city: input.city,
        region: input.region,
        latitude: input.latitude,
        longitude: input.longitude,
        rememberMe: input.rememberMe || false,
        expiresAt: input.expiresAt,
        lastActivityAt: new Date(),
      },
    });
  }

  touchSession(sessionId: string) {
    return this.prisma.userSession.update({
      where: { id: sessionId },
      data: {
        lastActivityAt: new Date(),
      },
    });
  }

  listUserSessions(userId: string) {
    return this.prisma.userSession.findMany({
      where: {
        userId,
        revokedAt: null,
      },
      include: {
        device: true,
      },
      orderBy: {
        lastActivityAt: "desc",
      },
    });
  }

  revokeSession(sessionId: string, revokeReason: string) {
    return this.prisma.userSession.updateMany({
      where: {
        id: sessionId,
      },
      data: {
        status: "REVOKED",
        revokedAt: new Date(),
        revokeReason,
      },
    });
  }

  revokeAllSessions(userId: string, exceptSessionId?: string) {
    return this.prisma.userSession.updateMany({
      where: {
        userId,
        revokedAt: null,
        ...(exceptSessionId
          ? {
              id: {
                not: exceptSessionId,
              },
            }
          : {}),
      },
      data: {
        status: "REVOKED",
        revokedAt: new Date(),
        revokeReason: "logout-all",
      },
    });
  }

  createRefreshToken(input: {
    userId: string;
    sessionId: string;
    tokenId: string;
    tokenHash: string;
    fingerprint: string;
    ipAddress?: string;
    expiresAt: Date;
  }) {
    return this.prisma.refreshToken.create({
      data: {
        userId: input.userId,
        sessionId: input.sessionId,
        tokenId: input.tokenId,
        tokenHash: input.tokenHash,
        fingerprint: input.fingerprint,
        ipAddress: input.ipAddress,
        expiresAt: input.expiresAt,
      },
    });
  }

  findRefreshTokenByHash(tokenHash: string) {
    return this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: {
        session: true,
        user: {
          include: authUserInclude,
        },
      },
    });
  }

  rotateRefreshToken(id: string, replacedByToken: string) {
    return this.prisma.refreshToken.update({
      where: { id },
      data: {
        revokedAt: new Date(),
        rotatedAt: new Date(),
        replacedByToken,
      },
    });
  }

  revokeRefreshTokenByHash(tokenHash: string) {
    return this.prisma.refreshToken.updateMany({
      where: {
        tokenHash,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  revokeRefreshTokensForSession(sessionId: string) {
    return this.prisma.refreshToken.updateMany({
      where: {
        sessionId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  revokeRefreshTokensForUser(userId: string) {
    return this.prisma.refreshToken.updateMany({
      where: {
        userId,
        revokedAt: null,
      },
      data: {
        revokedAt: new Date(),
      },
    });
  }

  createMagicLinkToken(userId: string, email: string, tokenHash: string, redirectTo?: string) {
    return this.prisma.magicLinkToken.create({
      data: {
        userId,
        email: email.toLowerCase(),
        tokenHash,
        redirectTo,
        expiresAt: addMinutes(new Date(), 15),
      },
    });
  }

  findMagicLinkToken(tokenHash: string) {
    return this.prisma.magicLinkToken.findUnique({
      where: { tokenHash },
      include: {
        user: {
          include: authUserInclude,
        },
      },
    });
  }

  consumeMagicLinkToken(id: string) {
    return this.prisma.magicLinkToken.update({
      where: { id },
      data: {
        consumedAt: new Date(),
      },
    });
  }

  createVerificationToken(userId: string, type: string, tokenHash: string, ttlMinutes = 30) {
    return this.prisma.verificationToken.create({
      data: {
        userId,
        type,
        tokenHash,
        expiresAt: addMinutes(new Date(), ttlMinutes),
      },
    });
  }

  findVerificationToken(tokenHash: string, type?: string) {
    return this.prisma.verificationToken.findFirst({
      where: {
        tokenHash,
        ...(type ? { type } : {}),
      },
      include: {
        user: {
          include: authUserInclude,
        },
      },
    });
  }

  consumeVerificationToken(id: string) {
    return this.prisma.verificationToken.update({
      where: { id },
      data: {
        consumedAt: new Date(),
      },
    });
  }

  upsertTotpMethod(userId: string, secret: string, issuer: string, label: string) {
    return this.prisma.totpMethod.create({
      data: {
        userId,
        secret,
        issuer,
        label,
      },
    });
  }

  findLatestTotpMethod(userId: string) {
    return this.prisma.totpMethod.findFirst({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
  }

  findEnabledTotpMethod(userId: string) {
    return this.prisma.totpMethod.findFirst({
      where: {
        userId,
        enabled: true,
      },
      orderBy: { createdAt: "desc" },
    });
  }

  enableTotpMethod(id: string, backupCodes: string[]) {
    return this.prisma.totpMethod.update({
      where: { id },
      data: {
        enabled: true,
        verifiedAt: new Date(),
        backupCodes,
      },
    });
  }

  disableTotp(userId: string) {
    return this.prisma.totpMethod.updateMany({
      where: { userId },
      data: {
        enabled: false,
      },
    });
  }

  updateTotpBackupCodes(id: string, backupCodes: string[]) {
    return this.prisma.totpMethod.update({
      where: { id },
      data: {
        backupCodes,
      },
    });
  }

  updateUserTwoFactor(userId: string, enabled: boolean) {
    return this.prisma.userSecuritySettings.upsert({
      where: { userId },
      update: {
        twoFactorEnabled: enabled,
      },
      create: {
        userId,
        twoFactorEnabled: enabled,
      },
    });
  }

  listDevices(userId: string) {
    return this.prisma.device.findMany({
      where: { userId },
      orderBy: { lastSeenAt: "desc" },
    });
  }

  trustDevice(userId: string, deviceId: string) {
    return this.prisma.device.updateMany({
      where: {
        id: deviceId,
        userId,
      },
      data: {
        trusted: true,
      },
    });
  }

  findOAuthAccount(provider: "GOOGLE" | "GITHUB" | "DISCORD" | "APPLE", providerAccountId: string) {
    return this.prisma.oAuthAccount.findUnique({
      where: {
        provider_providerAccountId: {
          provider,
          providerAccountId,
        },
      },
      include: {
        user: {
          include: authUserInclude,
        },
      },
    });
  }

  linkOAuthAccount(
    userId: string,
    provider: "GOOGLE" | "GITHUB" | "DISCORD" | "APPLE",
    providerAccountId: string,
    input: {
      email?: string;
      accessToken?: string;
      refreshToken?: string;
      scope?: string;
      expiresAt?: Date;
    },
  ) {
    return this.prisma.oAuthAccount.upsert({
      where: {
        provider_providerAccountId: {
          provider,
          providerAccountId,
        },
      },
      update: {
        userId,
        email: input.email?.toLowerCase(),
        accessToken: input.accessToken,
        refreshToken: input.refreshToken,
        scope: input.scope,
        expiresAt: input.expiresAt,
      },
      create: {
        userId,
        provider,
        providerAccountId,
        email: input.email?.toLowerCase(),
        accessToken: input.accessToken,
        refreshToken: input.refreshToken,
        scope: input.scope,
        expiresAt: input.expiresAt,
      },
    });
  }

  async getKnownCountries(userId: string) {
    const sessions = await this.prisma.userSession.findMany({
      where: {
        userId,
        country: {
          not: null,
        },
      },
      distinct: ["country"],
      select: {
        country: true,
      },
    });

    return new Set(sessions.map((entry) => entry.country).filter(Boolean));
  }

  async buildSessionExpiry(userId: string, rememberMe = false) {
    const securitySettings = await this.prisma.userSecuritySettings.findUnique({
      where: { userId },
    });

    const now = new Date();
    if (rememberMe) {
      return addDays(now, securitySettings?.sessionAbsoluteTtlDays || 30);
    }

    return addMinutes(now, securitySettings?.sessionIdleTimeoutMins || 60);
  }
}
