import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { clearAuthCookies, setAccessTokenCookie, setRefreshTokenCookie } from "../../../shared/http/cookies";
import { requireCurrentUser } from "../../../shared/http/guards";
import { buildRequestMeta } from "../../../shared/http/request-meta";

const registerSchema = z.object({
  email: z.string().email().optional(),
  phone: z.string().min(7).optional(),
  username: z.string().min(3),
  displayName: z.string().min(1).optional(),
  password: z.string().min(12),
  captchaToken: z.string().optional(),
  rememberMe: z.boolean().optional(),
});

const loginSchema = z.object({
  identifier: z.string().min(1),
  password: z.string().min(1),
  captchaToken: z.string().optional(),
  totpCode: z.string().optional(),
  rememberMe: z.boolean().optional(),
});

const refreshSchema = z.object({
  refreshToken: z.string().optional(),
});

const magicLinkRequestSchema = z.object({
  email: z.string().email(),
  redirectTo: z.string().url().optional(),
});

const magicLinkConsumeSchema = z.object({
  token: z.string().min(1),
  rememberMe: z.coerce.boolean().optional(),
});

const totpVerifySchema = z.object({
  code: z.string().min(6),
});

const disableTotpSchema = z.object({
  code: z.string().optional(),
  password: z.string().optional(),
});

const passwordChangeSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(12),
});

const passwordResetRequestSchema = z.object({
  identifier: z.string().min(1),
});

const passwordResetConfirmSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(12),
});

const oauthCallbackSchema = z.object({
  code: z.string().min(1),
  redirectUri: z.string().url(),
  state: z.string().min(1),
  rememberMe: z.boolean().optional(),
});

const oauthParamsSchema = z.object({
  provider: z.enum(["google", "github", "discord", "apple"]),
});

export const registerAuthRoutes = async (
  app: FastifyInstance,
  dependencies: {
    authService: {
      register: (...args: never[]) => Promise<any>;
      login: (...args: never[]) => Promise<any>;
      refreshSession: (...args: never[]) => Promise<any>;
      logout: (...args: never[]) => Promise<any>;
      logoutAll: (...args: never[]) => Promise<any>;
      listSessions: (...args: never[]) => Promise<any>;
      revokeSession: (...args: never[]) => Promise<any>;
      listDevices: (...args: never[]) => Promise<any>;
      trustDevice: (...args: never[]) => Promise<any>;
      requestMagicLink: (...args: never[]) => Promise<any>;
      consumeMagicLink: (...args: never[]) => Promise<any>;
      setupTotp: (...args: never[]) => Promise<any>;
      verifyTotpSetup: (...args: never[]) => Promise<any>;
      disableTotp: (...args: never[]) => Promise<any>;
      changePassword: (...args: never[]) => Promise<any>;
      requestPasswordReset: (...args: never[]) => Promise<any>;
      resetPassword: (...args: never[]) => Promise<any>;
      sendVerificationEmail: (...args: never[]) => Promise<any>;
      requestEmailVerification: (...args: never[]) => Promise<any>;
      verifyEmail: (...args: never[]) => Promise<any>;
      getOAuthAuthorizationUrl: (...args: never[]) => any;
      handleOAuthCallback: (...args: never[]) => Promise<any>;
    };
  },
) => {
  app.post("/v1/auth/register", async (request, reply) => {
    const body = registerSchema.parse(request.body);
    const result = await dependencies.authService.register(body, buildRequestMeta(request, { rememberMe: body.rememberMe }));
    setAccessTokenCookie(reply, result.accessToken);
    setRefreshTokenCookie(reply, result.refreshToken);
    return { data: result };
  });

  app.post("/v1/auth/login", async (request, reply) => {
    const body = loginSchema.parse(request.body);
    const result = await dependencies.authService.login(body, buildRequestMeta(request, { rememberMe: body.rememberMe }));

    if (result.requiresTwoFactor) {
      return { data: result };
    }

    setAccessTokenCookie(reply, result.accessToken);
    setRefreshTokenCookie(reply, result.refreshToken);
    return { data: result };
  });

  app.post("/v1/auth/refresh", async (request, reply) => {
    const body = refreshSchema.parse(request.body || {});
    const refreshToken = body.refreshToken || request.cookies.refresh_token;
    if (!refreshToken) {
      return reply.status(401).send({ error: "Refresh token is required" });
    }

    const result = await dependencies.authService.refreshSession(refreshToken, buildRequestMeta(request));
    setAccessTokenCookie(reply, result.accessToken);
    setRefreshTokenCookie(reply, result.refreshToken);
    return { data: result };
  });

  app.post("/v1/auth/logout", async (request, reply) => {
    await dependencies.authService.logout(request.cookies.refresh_token, request.currentUser);
    clearAuthCookies(reply);
    return { ok: true };
  });

  app.post("/v1/auth/logout-all", async (request, reply) => {
    const currentUser = requireCurrentUser(request);
    await dependencies.authService.logoutAll(currentUser);
    clearAuthCookies(reply);
    return { ok: true };
  });

  app.get("/v1/auth/sessions", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.authService.listSessions(currentUser.id) };
  });

  app.post("/v1/auth/sessions/:sessionId/revoke", async (request) => {
    const currentUser = requireCurrentUser(request);
    const params = z.object({ sessionId: z.string().uuid() }).parse(request.params);
    await dependencies.authService.revokeSession(currentUser.id, params.sessionId);
    return { ok: true };
  });

  app.get("/v1/auth/devices", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.authService.listDevices(currentUser.id) };
  });

  app.post("/v1/auth/devices/:deviceId/trust", async (request) => {
    const currentUser = requireCurrentUser(request);
    const params = z.object({ deviceId: z.string().uuid() }).parse(request.params);
    await dependencies.authService.trustDevice(currentUser.id, params.deviceId);
    return { ok: true };
  });

  app.post("/v1/auth/magic-link/request", async (request) => {
    const body = magicLinkRequestSchema.parse(request.body);
    return { data: await dependencies.authService.requestMagicLink(body.email, body.redirectTo) };
  });

  app.post("/v1/auth/magic-link/consume", async (request, reply) => {
    const body = magicLinkConsumeSchema.parse(request.body);
    const result = await dependencies.authService.consumeMagicLink(
      body.token,
      buildRequestMeta(request, { rememberMe: body.rememberMe }),
    );
    setAccessTokenCookie(reply, result.accessToken);
    setRefreshTokenCookie(reply, result.refreshToken);
    return { data: result };
  });

  app.get("/v1/auth/magic-link/consume", async (request, reply) => {
    const query = magicLinkConsumeSchema.parse(request.query);
    const result = await dependencies.authService.consumeMagicLink(
      query.token,
      buildRequestMeta(request, { rememberMe: query.rememberMe }),
    );
    setAccessTokenCookie(reply, result.accessToken);
    setRefreshTokenCookie(reply, result.refreshToken);
    return { data: result };
  });

  app.post("/v1/auth/2fa/setup", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.authService.setupTotp(currentUser.id) };
  });

  app.post("/v1/auth/2fa/verify", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = totpVerifySchema.parse(request.body);
    return { data: await dependencies.authService.verifyTotpSetup(currentUser.id, body.code) };
  });

  app.post("/v1/auth/2fa/disable", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = disableTotpSchema.parse(request.body);
    return { data: await dependencies.authService.disableTotp(currentUser.id, body) };
  });

  app.post("/v1/auth/password/change", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = passwordChangeSchema.parse(request.body);
    return {
      data: await dependencies.authService.changePassword(
        currentUser.id,
        body.currentPassword,
        body.newPassword,
      ),
    };
  });

  app.post("/v1/auth/password/reset/request", async (request) => {
    const body = passwordResetRequestSchema.parse(request.body);
    return { data: await dependencies.authService.requestPasswordReset(body.identifier) };
  });

  app.post("/v1/auth/password/reset/confirm", async (request) => {
    const body = passwordResetConfirmSchema.parse(request.body);
    return { data: await dependencies.authService.resetPassword(body) };
  });

  app.post("/v1/auth/verify/email/request", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.authService.requestEmailVerification(currentUser.id) };
  });

  app.get("/v1/auth/verify/email/confirm", async (request) => {
    const query = z.object({ token: z.string().min(1) }).parse(request.query);
    return { data: await dependencies.authService.verifyEmail(query.token) };
  });

  app.get("/v1/auth/oauth/:provider/url", async (request) => {
    const params = oauthParamsSchema.parse(request.params);
    const query = z.object({ redirectUri: z.string().url() }).parse(request.query);
    return {
      data: dependencies.authService.getOAuthAuthorizationUrl(params.provider, query.redirectUri),
    };
  });

  app.post("/v1/auth/oauth/:provider/callback", async (request, reply) => {
    const params = oauthParamsSchema.parse(request.params);
    const body = oauthCallbackSchema.parse(request.body);
    const result = await dependencies.authService.handleOAuthCallback(
      params.provider,
      body,
      buildRequestMeta(request, { rememberMe: body.rememberMe }),
    );
    setAccessTokenCookie(reply, result.accessToken);
    setRefreshTokenCookie(reply, result.refreshToken);
    return { data: result };
  });
};
