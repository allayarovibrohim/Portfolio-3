import jwt from "jsonwebtoken";
import QRCode from "qrcode";
import speakeasy from "speakeasy";
import { createPrivateKey } from "crypto";
import { env } from "../../../config/env";
import { AuditService } from "../../audit/application/audit.service";
import { NotificationService } from "../../notifications/application/notification.service";
import { AuthRepository } from "../infrastructure/auth.repository";
import { ConflictError, NotFoundError, UnauthorizedError, ValidationError } from "../../../shared/http/errors";
import { flattenRolePermissions } from "../../../shared/security/rbac";
import { assertPasswordNotBreached } from "../../../shared/security/password-breach";
import { enforcePasswordPolicy, hashPassword, verifyPassword } from "../../../shared/security/password-policy";
import { generateToken, hashValue, constantTimeEqual, signHmac } from "../../../shared/utils/crypto";
import { addMinutes, isExpired } from "../../../shared/utils/time";
import { signAccessToken, signRefreshToken } from "../../../shared/security/jwt";
import { EmailService } from "../../../services/email/src/email.service";
import type { RequestMetaSnapshot } from "../../../shared/http/request-meta";
import type { RequestUser } from "../../../shared/http/request-context";
import { verifyCaptchaToken } from "../../../shared/security/captcha";

type SupportedOAuthProvider = "google" | "github" | "discord" | "apple";
type PrismaOAuthProvider = "GOOGLE" | "GITHUB" | "DISCORD" | "APPLE";

export interface RegisterInput {
  email?: string;
  phone?: string;
  username: string;
  displayName?: string;
  password: string;
  captchaToken?: string;
  rememberMe?: boolean;
}

export interface LoginInput {
  identifier: string;
  password: string;
  captchaToken?: string;
  totpCode?: string;
  rememberMe?: boolean;
}

export interface PasswordResetInput {
  token: string;
  password: string;
}

const oauthProviderMap: Record<SupportedOAuthProvider, PrismaOAuthProvider> = {
  google: "GOOGLE",
  github: "GITHUB",
  discord: "DISCORD",
  apple: "APPLE",
};

interface OAuthTokenPayload {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
  id_token?: string;
}

interface OAuthIdentity {
  providerAccountId: string;
  email?: string;
  displayName: string;
  usernameHint: string;
  avatarUrl?: string;
  accessToken?: string;
  refreshToken?: string;
  scope?: string;
  expiresAt?: Date;
}

export class AuthService {
  constructor(
    private readonly repository: AuthRepository,
    private readonly auditService: AuditService,
    private readonly notificationService: NotificationService,
    private readonly emailService: EmailService,
  ) {}

  async register(input: RegisterInput, meta: RequestMetaSnapshot) {
    await verifyCaptchaToken(input.captchaToken);

    if (!input.email && !input.phone) {
      throw new ValidationError("Email or phone is required");
    }

    const email = input.email?.trim().toLowerCase();
    const phone = input.phone?.trim();
    const username = this.normalizeUsername(input.username);
    const displayName = input.displayName?.trim() || username;

    if (email && (await this.repository.findUserByEmail(email))) {
      throw new ConflictError("Email is already registered");
    }

    if (await this.repository.usernameExists(username)) {
      throw new ConflictError("Username is already taken");
    }

    await assertPasswordNotBreached(input.password);
    await enforcePasswordPolicy(input.password, []);

    const passwordHash = await hashPassword(input.password);
    const user = await this.repository.createUser({
      email,
      phone,
      username,
      displayName,
      passwordHash,
      status: email ? "PENDING_VERIFICATION" : "ACTIVE",
      phoneVerifiedAt: phone ? new Date() : null,
    });

    await this.repository.appendPasswordHistory(user.id, passwordHash);
    await this.repository.createSecurityEvent({
      userId: user.id,
      type: "auth.registered",
      description: "New account registration completed",
      severity: "LOW",
      ipAddress: meta.ipAddress,
      fingerprint: meta.fingerprint,
      country: meta.country,
      city: meta.city,
      meta: {
        email,
        phone,
      },
    });

    await this.auditService.log({
      actorUserId: user.id,
      action: "auth.register",
      resourceType: "user",
      resourceId: user.id,
      targetUserId: user.id,
      ipAddress: meta.ipAddress,
      requestId: meta.requestId,
    });

    if (email) {
      await this.sendVerificationEmail(user.id, email, user.displayName);
    }

    return this.issueAuthenticatedSession(user, meta, {
      reason: "register",
      rememberMe: input.rememberMe,
    });
  }

  async login(input: LoginInput, meta: RequestMetaSnapshot) {
    const user = await this.repository.findUserByIdentifier(input.identifier);

    if (!user || !user.passwordHash) {
      await this.repository.recordLoginAttempt({
        email: input.identifier.includes("@") ? input.identifier.toLowerCase() : undefined,
        phone: input.identifier.startsWith("+") ? input.identifier : undefined,
        username: !input.identifier.includes("@") ? input.identifier.toLowerCase() : undefined,
        ipAddress: meta.ipAddress,
        userAgent: meta.userAgent,
        fingerprint: meta.fingerprint,
        success: false,
        country: meta.country,
        city: meta.city,
        severity: "MEDIUM",
      });
      throw new UnauthorizedError("Invalid credentials");
    }

    if (user.deletedAt || user.status === "DELETED" || user.status === "DISABLED") {
      throw new UnauthorizedError("Account is not available");
    }

    if (user.lockUntil && user.lockUntil.getTime() > Date.now()) {
      throw new UnauthorizedError("Account is temporarily locked");
    }

    const needsCaptcha = user.failedLoginCount >= (user.securitySettings?.requireCaptchaAfterFails || 3);
    if (needsCaptcha) {
      await verifyCaptchaToken(input.captchaToken);
    }

    const validPassword = await verifyPassword(user.passwordHash, input.password);
    if (!validPassword) {
      await this.handleFailedLogin(user.id, meta, input.identifier, needsCaptcha);
      throw new UnauthorizedError("Invalid credentials");
    }

    if (user.bans.length > 0) {
      throw new UnauthorizedError(`Account access is restricted: ${user.bans[0].type.toLowerCase()}`);
    }

    if (user.securitySettings?.twoFactorEnabled) {
      if (!input.totpCode) {
        return {
          requiresTwoFactor: true as const,
          method: "totp",
        };
      }

      await this.assertTotpCode(user.id, input.totpCode);
    }

    await this.repository.recordLoginAttempt({
      userId: user.id,
      email: user.email || undefined,
      phone: user.phone || undefined,
      username: user.username,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      fingerprint: meta.fingerprint,
      success: true,
      captchaRequired: needsCaptcha,
      country: meta.country,
      city: meta.city,
      severity: "LOW",
    });

    return this.issueAuthenticatedSession(user, meta, {
      reason: "login",
      rememberMe: input.rememberMe,
    });
  }

  async refreshSession(refreshToken: string, meta: RequestMetaSnapshot) {
    const payload = jwt.verify(refreshToken, env.JWT_REFRESH_SECRET, {
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
    }) as {
      sub: string;
      jti?: string;
      sessionId?: string;
      fingerprint?: string;
      deviceId?: string;
    };

    const stored = await this.repository.findRefreshTokenByHash(hashValue(refreshToken));
    if (!stored || stored.revokedAt || isExpired(stored.expiresAt)) {
      throw new UnauthorizedError("Refresh token is invalid");
    }

    if (stored.session.revokedAt || stored.session.status !== "ACTIVE") {
      throw new UnauthorizedError("Session is no longer active");
    }

    if (payload.fingerprint && payload.fingerprint !== meta.fingerprint) {
      await this.repository.createSecurityEvent({
        userId: stored.userId,
        type: "auth.refresh_fingerprint_mismatch",
        description: "Refresh token fingerprint mismatch detected",
        severity: "HIGH",
        ipAddress: meta.ipAddress,
        fingerprint: meta.fingerprint,
        country: meta.country,
        city: meta.city,
      });
      throw new UnauthorizedError("Refresh token fingerprint mismatch");
    }

    const sessionUser = stored.user;
    const next = await this.issueTokensForSession(sessionUser, stored.session.id, stored.session.deviceId || undefined, meta, {
      rememberMe: stored.session.rememberMe,
    });

    await this.repository.rotateRefreshToken(stored.id, next.refreshTokenId);
    await this.repository.touchSession(stored.session.id);

    return next;
  }

  async logout(refreshToken?: string, currentUser?: RequestUser) {
    if (refreshToken) {
      await this.repository.revokeRefreshTokenByHash(hashValue(refreshToken));
    }

    if (currentUser?.sessionId) {
      await this.repository.revokeSession(currentUser.sessionId, "logout");
      await this.repository.revokeRefreshTokensForSession(currentUser.sessionId);
    }
  }

  async logoutAll(currentUser: RequestUser) {
    await this.repository.revokeAllSessions(currentUser.id, currentUser.sessionId);
    await this.repository.revokeRefreshTokensForUser(currentUser.id);

    await this.auditService.log({
      actorUserId: currentUser.id,
      action: "auth.logout_all",
      resourceType: "session",
      resourceId: currentUser.sessionId,
    });
  }

  listSessions(userId: string) {
    return this.repository.listUserSessions(userId);
  }

  async revokeSession(userId: string, sessionId: string) {
    await this.repository.revokeSession(sessionId, "user-revoked");
    await this.repository.revokeRefreshTokensForSession(sessionId);
    await this.auditService.log({
      actorUserId: userId,
      action: "auth.session.revoke",
      resourceType: "session",
      resourceId: sessionId,
      targetUserId: userId,
    });
  }

  listDevices(userId: string) {
    return this.repository.listDevices(userId);
  }

  async trustDevice(userId: string, deviceId: string) {
    await this.repository.trustDevice(userId, deviceId);
    await this.auditService.log({
      actorUserId: userId,
      action: "auth.device.trust",
      resourceType: "device",
      resourceId: deviceId,
      targetUserId: userId,
    });
  }

  async requestMagicLink(email: string, redirectTo?: string) {
    const user = await this.repository.findUserByEmail(email.toLowerCase());
    if (!user || !user.email) {
      return { accepted: true };
    }

    const rawToken = generateToken(24);
    const tokenHash = hashValue(rawToken);
    await this.repository.createMagicLinkToken(user.id, user.email, tokenHash, redirectTo);

    const link = `${env.PUBLIC_BASE_URL}${env.API_PREFIX}/v1/auth/magic-link/consume?token=${rawToken}`;
    await this.notificationService.queueEmailNotification({
      userId: user.id,
      to: user.email,
      subject: "Your secure magic sign-in link",
      html: this.emailService.magicLink(link),
      title: "Magic sign-in link requested",
      body: "A secure sign-in link was requested for your account.",
      type: "auth.magic_link.requested",
      channel: "EMAIL",
      actionUrl: link,
    });

    return { accepted: true };
  }

  async consumeMagicLink(rawToken: string, meta: RequestMetaSnapshot) {
    const token = await this.repository.findMagicLinkToken(hashValue(rawToken));
    if (!token || token.consumedAt || isExpired(token.expiresAt)) {
      throw new UnauthorizedError("Magic link is invalid or expired");
    }

    await this.repository.consumeMagicLinkToken(token.id);
    return this.issueAuthenticatedSession(token.user, meta, {
      reason: "magic-link",
      rememberMe: true,
    });
  }

  async setupTotp(userId: string) {
    const user = await this.repository.findUserById(userId);
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const secret = speakeasy.generateSecret({
      issuer: env.APP_NAME,
      name: `${env.APP_NAME}:${user.username}`,
      length: 32,
    });

    const method = await this.repository.upsertTotpMethod(
      user.id,
      secret.base32,
      env.APP_NAME,
      `${env.APP_NAME}:${user.username}`,
    );

    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url || "");

    return {
      secret: secret.base32,
      otpauthUrl: secret.otpauth_url,
      qrDataUrl,
      methodId: method.id,
    };
  }

  async verifyTotpSetup(userId: string, code: string) {
    const method = await this.repository.findLatestTotpMethod(userId);
    if (!method) {
      throw new NotFoundError("No pending TOTP method found");
    }

    const verified = speakeasy.totp.verify({
      secret: method.secret,
      encoding: "base32",
      token: code,
      window: 1,
    });

    if (!verified) {
      throw new UnauthorizedError("Invalid TOTP code");
    }

    const backupCodes = Array.from({ length: 8 }, () => generateToken(4).toUpperCase());
    await this.repository.enableTotpMethod(method.id, backupCodes.map((entry) => hashValue(entry)));
    await this.repository.updateUserTwoFactor(userId, true);

    return {
      enabled: true,
      backupCodes,
    };
  }

  async disableTotp(userId: string, input: { code?: string; password?: string }) {
    const user = await this.repository.findUserById(userId);
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const method = await this.repository.findEnabledTotpMethod(userId);
    if (!method) {
      return { enabled: false };
    }

    if (input.code) {
      await this.assertTotpCode(userId, input.code);
    } else if (input.password && user.passwordHash) {
      const valid = await verifyPassword(user.passwordHash, input.password);
      if (!valid) {
        throw new UnauthorizedError("Current password is invalid");
      }
    } else {
      throw new ValidationError("TOTP code or password is required");
    }

    await this.repository.disableTotp(userId);
    await this.repository.updateUserTwoFactor(userId, false);

    return { enabled: false };
  }

  async changePassword(userId: string, currentPassword: string, newPassword: string) {
    const user = await this.repository.findUserById(userId);
    if (!user || !user.passwordHash) {
      throw new UnauthorizedError("Password login is not available for this account");
    }

    const currentOk = await verifyPassword(user.passwordHash, currentPassword);
    if (!currentOk) {
      throw new UnauthorizedError("Current password is invalid");
    }

    await assertPasswordNotBreached(newPassword);
    const historical = await this.repository.getRecentPasswordHashes(userId);
    await enforcePasswordPolicy(newPassword, historical);

    const passwordHash = await hashPassword(newPassword);
    await this.repository.updatePassword(userId, passwordHash);
    await this.repository.appendPasswordHistory(userId, passwordHash);
    await this.repository.revokeAllSessions(userId);
    await this.repository.revokeRefreshTokensForUser(userId);

    await this.auditService.log({
      actorUserId: userId,
      action: "auth.password.change",
      resourceType: "user",
      resourceId: userId,
    });

    return { changed: true };
  }

  async requestPasswordReset(identifier: string) {
    const user = await this.repository.findUserByIdentifier(identifier);
    if (!user?.email) {
      return { accepted: true };
    }

    const rawToken = generateToken(24);
    await this.repository.createVerificationToken(user.id, "password_reset", hashValue(rawToken), 30);

    const link = `${env.PUBLIC_BASE_URL}${env.API_PREFIX}/v1/auth/password/reset/confirm?token=${rawToken}`;
    await this.notificationService.queueEmailNotification({
      userId: user.id,
      to: user.email,
      subject: "Reset your password",
      html: this.emailService.securityAlert("Password reset requested", `Reset your password here: <a href="${link}">${link}</a>`),
      title: "Password reset requested",
      body: "A password reset link was generated for your account.",
      type: "auth.password_reset.requested",
      channel: "EMAIL",
      actionUrl: link,
    });

    return { accepted: true };
  }

  async resetPassword(input: PasswordResetInput) {
    const token = await this.repository.findVerificationToken(hashValue(input.token), "password_reset");
    if (!token || token.consumedAt || isExpired(token.expiresAt)) {
      throw new UnauthorizedError("Password reset token is invalid or expired");
    }

    const historical = await this.repository.getRecentPasswordHashes(token.userId);
    await assertPasswordNotBreached(input.password);
    await enforcePasswordPolicy(input.password, historical);

    const passwordHash = await hashPassword(input.password);
    await this.repository.updatePassword(token.userId, passwordHash);
    await this.repository.appendPasswordHistory(token.userId, passwordHash);
    await this.repository.consumeVerificationToken(token.id);
    await this.repository.revokeAllSessions(token.userId);
    await this.repository.revokeRefreshTokensForUser(token.userId);

    return { reset: true };
  }

  async sendVerificationEmail(userId: string, email: string, displayName: string) {
    const rawToken = generateToken(24);
    await this.repository.createVerificationToken(userId, "email_verify", hashValue(rawToken), 60);
    const link = `${env.PUBLIC_BASE_URL}${env.API_PREFIX}/v1/auth/verify/email/confirm?token=${rawToken}`;

    await this.notificationService.queueEmailNotification({
      userId,
      to: email,
      subject: "Verify your email address",
      html: this.emailService.securityAlert(
        "Verify your email",
        `Hello ${displayName}, confirm your email here: <a href="${link}">${link}</a>`,
      ),
      title: "Email verification requested",
      body: "A verification link was sent to your email address.",
      type: "auth.email_verification.requested",
      channel: "EMAIL",
      actionUrl: link,
    });

    return { accepted: true };
  }

  async requestEmailVerification(userId: string) {
    const user = await this.repository.findUserById(userId);
    if (!user?.email) {
      throw new ValidationError("No email address is configured for this account");
    }

    return this.sendVerificationEmail(userId, user.email, user.displayName);
  }

  async verifyEmail(rawToken: string) {
    const token = await this.repository.findVerificationToken(hashValue(rawToken), "email_verify");
    if (!token || token.consumedAt || isExpired(token.expiresAt)) {
      throw new UnauthorizedError("Verification token is invalid or expired");
    }

    await this.repository.markEmailVerified(token.userId);
    await this.repository.consumeVerificationToken(token.id);

    return { verified: true };
  }

  getOAuthAuthorizationUrl(provider: SupportedOAuthProvider, redirectUri: string) {
    this.assertOAuthRedirect(redirectUri);
    const state = this.createOAuthState(provider, redirectUri);
    const url = this.buildOAuthAuthorizationUrl(provider, redirectUri, state);

    return {
      provider,
      state,
      url,
    };
  }

  async handleOAuthCallback(
    provider: SupportedOAuthProvider,
    input: {
      code: string;
      redirectUri: string;
      state: string;
      rememberMe?: boolean;
    },
    meta: RequestMetaSnapshot,
  ) {
    const parsedState = this.verifyOAuthState(input.state);
    if (parsedState.provider !== provider || parsedState.redirectUri !== input.redirectUri) {
      throw new UnauthorizedError("OAuth state validation failed");
    }

    const identity = await this.exchangeOAuthCode(provider, input.code, input.redirectUri);
    const providerName = oauthProviderMap[provider];
    const existingAccount = await this.repository.findOAuthAccount(providerName, identity.providerAccountId);

    let user = existingAccount?.user;
    if (!user && identity.email) {
      user = await this.repository.findUserByEmail(identity.email);
    }

    if (!user) {
      const username = await this.generateAvailableUsername(identity.usernameHint);
      user = await this.repository.createUser({
        email: identity.email?.toLowerCase(),
        username,
        displayName: identity.displayName,
        status: "ACTIVE",
        emailVerifiedAt: identity.email ? new Date() : null,
      });
    }

    await this.repository.linkOAuthAccount(user.id, providerName, identity.providerAccountId, {
      email: identity.email,
      accessToken: identity.accessToken,
      refreshToken: identity.refreshToken,
      scope: identity.scope,
      expiresAt: identity.expiresAt,
    });

    if (identity.email) {
      await this.repository.markEmailVerified(user.id, identity.email);
      user = await this.repository.findUserById(user.id);
    }

    if (!user) {
      throw new NotFoundError("OAuth user could not be resolved");
    }

    return this.issueAuthenticatedSession(user, meta, {
      reason: `oauth:${provider}`,
      rememberMe: input.rememberMe,
    });
  }

  private async handleFailedLogin(
    userId: string,
    meta: RequestMetaSnapshot,
    identifier: string,
    captchaRequired: boolean,
  ) {
    const user = await this.repository.findUserById(userId);
    if (!user) {
      return;
    }

    const nextFailedCount = user.failedLoginCount + 1;
    const lockUntil = nextFailedCount >= 5 ? addMinutes(new Date(), 15) : null;

    await this.repository.updateUserAfterFailedLogin(userId, nextFailedCount, lockUntil);
    await this.repository.recordLoginAttempt({
      userId,
      email: user.email || undefined,
      phone: user.phone || undefined,
      username: user.username,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      fingerprint: meta.fingerprint,
      success: false,
      captchaRequired,
      blocked: !!lockUntil,
      country: meta.country,
      city: meta.city,
      severity: lockUntil ? "HIGH" : "MEDIUM",
    });

    await this.repository.createSecurityEvent({
      userId,
      type: "auth.login_failed",
      description: `Failed login attempt for ${identifier}`,
      severity: lockUntil ? "HIGH" : "MEDIUM",
      ipAddress: meta.ipAddress,
      fingerprint: meta.fingerprint,
      country: meta.country,
      city: meta.city,
      meta: {
        lockUntil,
      },
    });
  }

  private async issueAuthenticatedSession(
    user: Awaited<ReturnType<AuthRepository["findUserById"]>>,
    meta: RequestMetaSnapshot,
    options: {
      reason: string;
      rememberMe?: boolean;
    },
  ) {
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const priorDevice = await this.repository.findDeviceByFingerprint(user.id, meta.fingerprint);
    const knownCountries = await this.repository.getKnownCountries(user.id);

    const device = await this.repository.upsertDevice(user.id, meta.fingerprint, {
      userAgent: meta.userAgent,
      browser: this.parseBrowser(meta.userAgent),
      platform: this.parsePlatform(meta.userAgent),
      lastIp: meta.ipAddress,
      lastCountry: meta.country,
      type: "browser",
      name: priorDevice?.name || this.describeDevice(meta.userAgent),
    });

    const expiresAt = await this.repository.buildSessionExpiry(user.id, options.rememberMe);
    const session = await this.repository.createSession({
      userId: user.id,
      deviceId: device.id,
      fingerprint: meta.fingerprint,
      ipAddress: meta.ipAddress,
      userAgent: meta.userAgent,
      country: meta.country,
      city: meta.city,
      region: meta.region,
      latitude: meta.latitude,
      longitude: meta.longitude,
      rememberMe: options.rememberMe,
      expiresAt,
    });

    const tokens = await this.issueTokensForSession(user, session.id, device.id, meta, {
      rememberMe: options.rememberMe,
    });

    await this.repository.updateUserAfterSuccessfulLogin(user.id, new Date());
    await this.repository.createActivityLog(user.id, "auth.session.created", `Session created via ${options.reason}`, {
      sessionId: session.id,
      deviceId: device.id,
      country: meta.country,
    });

    const isNewDevice = !priorDevice;
    const isNewCountry = meta.country ? !knownCountries.has(meta.country) : false;
    if (isNewDevice || isNewCountry) {
      await this.repository.createSecurityEvent({
        userId: user.id,
        type: "auth.suspicious_login",
        description: "Login from a new device or location detected",
        severity: "HIGH",
        ipAddress: meta.ipAddress,
        fingerprint: meta.fingerprint,
        country: meta.country,
        city: meta.city,
        meta: {
          isNewDevice,
          isNewCountry,
        },
      });

      if (user.notificationSettings?.loginAlerts && user.email) {
        await this.notificationService.queueEmailNotification({
          userId: user.id,
          to: user.email,
          subject: "Security alert: new login detected",
          html: this.emailService.securityAlert(
            "New login detected",
            `We noticed a sign-in from ${meta.city || "an unknown city"}, ${meta.country || "unknown country"}.`,
          ),
          title: "New login detected",
          body: "A new device or location accessed your account.",
          type: "auth.login_alert",
          channel: "EMAIL",
        });
      }
    }

    await this.auditService.log({
      actorUserId: user.id,
      action: "auth.session.create",
      resourceType: "session",
      resourceId: session.id,
      targetUserId: user.id,
      ipAddress: meta.ipAddress,
      requestId: meta.requestId,
      context: {
        reason: options.reason,
        deviceId: device.id,
      },
    });

    return {
      ...tokens,
      session,
      user: this.serializeUser(user, session.id, device.id, meta.fingerprint),
    };
  }

  private async issueTokensForSession(
    user: Awaited<ReturnType<AuthRepository["findUserById"]>>,
    sessionId: string,
    deviceId: string | undefined,
    meta: RequestMetaSnapshot,
    options: {
      rememberMe?: boolean;
    },
  ) {
    if (!user) {
      throw new NotFoundError("User not found");
    }

    const roles = user.userRoles.map((assignment) => assignment.role.name);
    const permissions = flattenRolePermissions(user.userRoles);

    const accessToken = signAccessToken({
      sub: user.id,
      type: "access",
      sessionId,
      deviceId,
      roles,
      permissions,
      fingerprint: meta.fingerprint,
    });

    const refreshTokenId = generateToken(16);
    const refreshTokenExpiry = await this.repository.buildSessionExpiry(user.id, options.rememberMe);
    const refreshToken = signRefreshToken({
      sub: user.id,
      type: "refresh",
      sessionId,
      deviceId,
      roles,
      permissions,
      fingerprint: meta.fingerprint,
      jti: refreshTokenId,
    });

    await this.repository.createRefreshToken({
      userId: user.id,
      sessionId,
      tokenId: refreshTokenId,
      tokenHash: hashValue(refreshToken),
      fingerprint: meta.fingerprint,
      ipAddress: meta.ipAddress,
      expiresAt: refreshTokenExpiry,
    });

    return {
      accessToken,
      refreshToken,
      refreshTokenId,
    };
  }

  private serializeUser(
    user: Awaited<ReturnType<AuthRepository["findUserById"]>>,
    sessionId: string,
    deviceId: string | undefined,
    fingerprint: string,
  ) {
    if (!user) {
      return null;
    }

    const roles = user.userRoles.map((assignment) => assignment.role.name);
    const permissions = flattenRolePermissions(user.userRoles);

    return {
      id: user.id,
      email: user.email,
      phone: user.phone,
      username: user.username,
      displayName: user.displayName,
      verifiedBadge: user.verifiedBadge,
      status: user.status,
      roles,
      permissions,
      sessionId,
      deviceId,
      fingerprint,
      profile: user.profile,
      settings: {
        privacy: user.privacySettings,
        security: user.securitySettings,
        notifications: user.notificationSettings,
        theme: user.themeSettings,
      },
    };
  }

  private async assertTotpCode(userId: string, code: string) {
    const method = await this.repository.findEnabledTotpMethod(userId);
    if (!method) {
      throw new UnauthorizedError("Two-factor authentication is not enabled");
    }

    const verified = speakeasy.totp.verify({
      secret: method.secret,
      encoding: "base32",
      token: code,
      window: 1,
    });

    if (verified) {
      return;
    }

    const backupCodes = Array.isArray(method.backupCodes) ? method.backupCodes.map(String) : [];
    const matchingIndex = backupCodes.findIndex((entry) => constantTimeEqual(entry, hashValue(code)));
    if (matchingIndex === -1) {
      throw new UnauthorizedError("Two-factor code is invalid");
    }

    backupCodes.splice(matchingIndex, 1);
    await this.repository.updateTotpBackupCodes(method.id, backupCodes);
  }

  private normalizeUsername(input: string) {
    const normalized = input.trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
    if (normalized.length < 3) {
      throw new ValidationError("Username must be at least 3 characters");
    }

    return normalized;
  }

  private async generateAvailableUsername(seed: string) {
    const base = this.normalizeUsername(seed || "user");
    if (!(await this.repository.usernameExists(base))) {
      return base;
    }

    for (let index = 1; index < 1000; index += 1) {
      const candidate = `${base}${index}`;
      if (!(await this.repository.usernameExists(candidate))) {
        return candidate;
      }
    }

    return `${base}${Date.now().toString().slice(-6)}`;
  }

  private createOAuthState(provider: SupportedOAuthProvider, redirectUri: string) {
    const encoded = Buffer.from(
      JSON.stringify({
        provider,
        redirectUri,
        ts: Date.now(),
      }),
    ).toString("base64url");

    return `${encoded}.${signHmac(encoded, env.JWT_ACCESS_SECRET)}`;
  }

  private verifyOAuthState(state: string) {
    const [payload, signature] = state.split(".");
    if (!payload || !signature) {
      throw new UnauthorizedError("OAuth state is malformed");
    }

    const expected = signHmac(payload, env.JWT_ACCESS_SECRET);
    if (!constantTimeEqual(expected, signature)) {
      throw new UnauthorizedError("OAuth state signature is invalid");
    }

    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf-8")) as {
      provider: SupportedOAuthProvider;
      redirectUri: string;
      ts: number;
    };

    if (Date.now() - decoded.ts > 10 * 60 * 1000) {
      throw new UnauthorizedError("OAuth state has expired");
    }

    return decoded;
  }

  private buildOAuthAuthorizationUrl(provider: SupportedOAuthProvider, redirectUri: string, state: string) {
    const config = this.getOAuthConfig(provider);
    const params = new URLSearchParams({
      client_id: config.clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      state,
      scope: config.scopes.join(" "),
    });

    if (provider === "google") {
      params.set("access_type", "offline");
      params.set("prompt", "consent");
    }

    if (provider === "apple") {
      params.set("response_mode", "form_post");
    }

    return `${config.authorizationUrl}?${params.toString()}`;
  }

  private async exchangeOAuthCode(provider: SupportedOAuthProvider, code: string, redirectUri: string): Promise<OAuthIdentity> {
    const config = this.getOAuthConfig(provider);
    const tokenPayload = await this.fetchOAuthToken(provider, code, redirectUri, config);

    switch (provider) {
      case "google":
        return this.resolveGoogleIdentity(tokenPayload);
      case "github":
        return this.resolveGithubIdentity(tokenPayload);
      case "discord":
        return this.resolveDiscordIdentity(tokenPayload);
      case "apple":
        return this.resolveAppleIdentity(tokenPayload);
      default:
        throw new ValidationError("Unsupported OAuth provider");
    }
  }

  private getOAuthConfig(provider: SupportedOAuthProvider) {
    const configs = {
      google: {
        clientId: env.GOOGLE_CLIENT_ID || "",
        clientSecret: env.GOOGLE_CLIENT_SECRET || "",
        authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: "https://oauth2.googleapis.com/token",
        scopes: ["openid", "email", "profile"],
      },
      github: {
        clientId: env.GITHUB_CLIENT_ID || "",
        clientSecret: env.GITHUB_CLIENT_SECRET || "",
        authorizationUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: "https://github.com/login/oauth/access_token",
        scopes: ["read:user", "user:email"],
      },
      discord: {
        clientId: env.DISCORD_CLIENT_ID || "",
        clientSecret: env.DISCORD_CLIENT_SECRET || "",
        authorizationUrl: "https://discord.com/api/oauth2/authorize",
        tokenUrl: "https://discord.com/api/oauth2/token",
        scopes: ["identify", "email"],
      },
      apple: {
        clientId: env.APPLE_CLIENT_ID || "",
        clientSecret: this.buildAppleClientSecret(),
        authorizationUrl: "https://appleid.apple.com/auth/authorize",
        tokenUrl: "https://appleid.apple.com/auth/token",
        scopes: ["name", "email"],
      },
    }[provider];

    if (!configs.clientId || !configs.clientSecret) {
      throw new ValidationError(`OAuth for ${provider} is not configured`);
    }

    return configs;
  }

  private async fetchOAuthToken(
    provider: SupportedOAuthProvider,
    code: string,
    redirectUri: string,
    config: {
      clientId: string;
      clientSecret: string;
      tokenUrl: string;
    },
  ) {
    const body = new URLSearchParams({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
    });

    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body,
    });

    if (!response.ok) {
      throw new UnauthorizedError(`OAuth token exchange failed for ${provider}`);
    }

    return (await response.json()) as OAuthTokenPayload;
  }

  private async resolveGoogleIdentity(tokenPayload: OAuthTokenPayload): Promise<OAuthIdentity> {
    const response = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
      },
    });

    const profile = (await response.json()) as {
      sub: string;
      email?: string;
      name?: string;
      picture?: string;
    };

    return {
      providerAccountId: profile.sub,
      email: profile.email,
      displayName: profile.name || profile.email || "Google User",
      usernameHint: (profile.email || profile.name || "google").split("@")[0],
      avatarUrl: profile.picture,
      accessToken: tokenPayload.access_token,
      refreshToken: tokenPayload.refresh_token,
      scope: tokenPayload.scope,
      expiresAt: tokenPayload.expires_in ? addMinutes(new Date(), Math.floor(tokenPayload.expires_in / 60)) : undefined,
    };
  }

  private async resolveGithubIdentity(tokenPayload: OAuthTokenPayload): Promise<OAuthIdentity> {
    const profileResponse = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
        Accept: "application/vnd.github+json",
      },
    });
    const profile = (await profileResponse.json()) as {
      id: number;
      login: string;
      name?: string;
      avatar_url?: string;
      email?: string;
    };

    let email = profile.email;
    if (!email) {
      const emailResponse = await fetch("https://api.github.com/user/emails", {
        headers: {
          Authorization: `Bearer ${tokenPayload.access_token}`,
          Accept: "application/vnd.github+json",
        },
      });
      const emails = (await emailResponse.json()) as Array<{
        email: string;
        primary: boolean;
        verified: boolean;
      }>;
      email = emails.find((entry) => entry.primary && entry.verified)?.email || emails[0]?.email;
    }

    return {
      providerAccountId: String(profile.id),
      email,
      displayName: profile.name || profile.login,
      usernameHint: profile.login,
      avatarUrl: profile.avatar_url,
      accessToken: tokenPayload.access_token,
      refreshToken: tokenPayload.refresh_token,
      scope: tokenPayload.scope,
      expiresAt: tokenPayload.expires_in ? addMinutes(new Date(), Math.floor(tokenPayload.expires_in / 60)) : undefined,
    };
  }

  private async resolveDiscordIdentity(tokenPayload: OAuthTokenPayload): Promise<OAuthIdentity> {
    const response = await fetch("https://discord.com/api/users/@me", {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
      },
    });
    const profile = (await response.json()) as {
      id: string;
      email?: string;
      username: string;
      global_name?: string;
      avatar?: string;
    };

    return {
      providerAccountId: profile.id,
      email: profile.email,
      displayName: profile.global_name || profile.username,
      usernameHint: profile.username,
      avatarUrl: profile.avatar
        ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`
        : undefined,
      accessToken: tokenPayload.access_token,
      refreshToken: tokenPayload.refresh_token,
      scope: tokenPayload.scope,
      expiresAt: tokenPayload.expires_in ? addMinutes(new Date(), Math.floor(tokenPayload.expires_in / 60)) : undefined,
    };
  }

  private async resolveAppleIdentity(tokenPayload: OAuthTokenPayload): Promise<OAuthIdentity> {
    const decoded = jwt.decode(tokenPayload.id_token || "") as {
      sub?: string;
      email?: string;
    } | null;

    if (!decoded?.sub) {
      throw new UnauthorizedError("Apple identity token is invalid");
    }

    return {
      providerAccountId: decoded.sub,
      email: decoded.email,
      displayName: decoded.email?.split("@")[0] || "Apple User",
      usernameHint: decoded.email?.split("@")[0] || "appleuser",
      accessToken: tokenPayload.access_token,
      refreshToken: tokenPayload.refresh_token,
      scope: tokenPayload.scope,
      expiresAt: tokenPayload.expires_in ? addMinutes(new Date(), Math.floor(tokenPayload.expires_in / 60)) : undefined,
    };
  }

  private buildAppleClientSecret() {
    if (!env.APPLE_PRIVATE_KEY || !env.APPLE_TEAM_ID || !env.APPLE_KEY_ID || !env.APPLE_CLIENT_ID) {
      return "";
    }

    return jwt.sign({}, createPrivateKey(env.APPLE_PRIVATE_KEY.replace(/\\n/g, "\n")), {
      algorithm: "ES256",
      issuer: env.APPLE_TEAM_ID,
      audience: "https://appleid.apple.com",
      subject: env.APPLE_CLIENT_ID,
      keyid: env.APPLE_KEY_ID,
      expiresIn: "1h",
    });
  }

  private assertOAuthRedirect(redirectUri: string) {
    if (
      !redirectUri.startsWith(env.FRONTEND_ORIGIN) &&
      !redirectUri.startsWith(env.PUBLIC_BASE_URL)
    ) {
      throw new ValidationError("OAuth redirect URI is not allowed");
    }
  }

  private parseBrowser(userAgent?: string) {
    if (!userAgent) {
      return "unknown";
    }
    if (userAgent.includes("Edg/")) {
      return "edge";
    }
    if (userAgent.includes("Chrome/")) {
      return "chrome";
    }
    if (userAgent.includes("Firefox/")) {
      return "firefox";
    }
    if (userAgent.includes("Safari/") && !userAgent.includes("Chrome/")) {
      return "safari";
    }

    return "browser";
  }

  private parsePlatform(userAgent?: string) {
    if (!userAgent) {
      return "unknown";
    }
    if (userAgent.includes("Windows")) {
      return "windows";
    }
    if (userAgent.includes("Mac OS")) {
      return "macos";
    }
    if (userAgent.includes("Android")) {
      return "android";
    }
    if (userAgent.includes("iPhone") || userAgent.includes("iPad")) {
      return "ios";
    }
    if (userAgent.includes("Linux")) {
      return "linux";
    }

    return "unknown";
  }

  private describeDevice(userAgent?: string) {
    const platform = this.parsePlatform(userAgent);
    const browser = this.parseBrowser(userAgent);
    return `${platform} / ${browser}`;
  }
}
