import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { requireCurrentUser } from "../../../shared/http/guards";

const profileSchema = z.object({
  displayName: z.string().min(1).optional(),
  avatarUrl: z.string().url().optional(),
  bannerUrl: z.string().url().optional(),
  bio: z.string().max(4000).optional(),
  website: z.string().url().optional(),
  socialLinks: z.record(z.string(), z.unknown()).optional(),
  addressLine1: z.string().optional(),
  addressLine2: z.string().optional(),
  city: z.string().optional(),
  state: z.string().optional(),
  postalCode: z.string().optional(),
  country: z.string().optional(),
  language: z.string().optional(),
  timezone: z.string().optional(),
  gender: z.enum(["MALE", "FEMALE", "NON_BINARY", "OTHER", "PREFER_NOT_TO_SAY"]).optional(),
  birthday: z.coerce.date().optional(),
});

const privacySchema = z.object({
  profileVisibility: z.string().optional(),
  showBirthday: z.boolean().optional(),
  showEmail: z.boolean().optional(),
  showPhone: z.boolean().optional(),
  allowMagicLinkLogin: z.boolean().optional(),
  allowSearchByEmail: z.boolean().optional(),
  allowSearchByPhone: z.boolean().optional(),
  allowPresenceVisibility: z.boolean().optional(),
  allowDataExport: z.boolean().optional(),
});

const securitySchema = z.object({
  magicLinkEnabled: z.boolean().optional(),
  rememberMeEnabled: z.boolean().optional(),
  deviceTrustDays: z.number().int().min(1).max(365).optional(),
  suspiciousLoginAlerts: z.boolean().optional(),
  passwordRotationDays: z.number().int().positive().nullable().optional(),
  sessionAbsoluteTtlDays: z.number().int().min(1).max(365).optional(),
  sessionIdleTimeoutMins: z.number().int().min(5).max(1440).optional(),
  requireCaptchaAfterFails: z.number().int().min(1).max(20).optional(),
});

const notificationSchema = z.object({
  marketingEmails: z.boolean().optional(),
  productEmails: z.boolean().optional(),
  securityEmails: z.boolean().optional(),
  loginAlerts: z.boolean().optional(),
  mentionNotifications: z.boolean().optional(),
  pushEnabled: z.boolean().optional(),
  smsEnabled: z.boolean().optional(),
  digestFrequency: z.string().optional(),
});

const themeSchema = z.object({
  theme: z.string().optional(),
  accentColor: z.string().optional(),
  density: z.string().optional(),
  reducedMotion: z.boolean().optional(),
});

export const registerUserRoutes = async (
  app: FastifyInstance,
  dependencies: {
    userService: {
      getMe: (...args: never[]) => Promise<any>;
      getPublicProfile: (...args: never[]) => Promise<any>;
      updateProfile: (...args: never[]) => Promise<any>;
      updatePrivacy: (...args: never[]) => Promise<any>;
      updateSecurity: (...args: never[]) => Promise<any>;
      updateNotifications: (...args: never[]) => Promise<any>;
      updateTheme: (...args: never[]) => Promise<any>;
      updateEmail: (...args: never[]) => Promise<any>;
      updatePhone: (...args: never[]) => Promise<any>;
      requestArchive: (...args: never[]) => Promise<any>;
      listArchiveJobs: (...args: never[]) => Promise<any>;
      scheduleDeletion: (...args: never[]) => Promise<any>;
      recoverAccount: (...args: never[]) => Promise<any>;
      exportUserData: (...args: never[]) => Promise<any>;
      listActivity: (...args: never[]) => Promise<any>;
      listLoginHistory: (...args: never[]) => Promise<any>;
    };
  },
) => {
  app.get("/v1/users/me", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.userService.getMe(currentUser.id) };
  });

  app.get("/v1/users/:username/public", async (request) => {
    const params = z.object({ username: z.string().min(1) }).parse(request.params);
    return { data: await dependencies.userService.getPublicProfile(params.username) };
  });

  app.patch("/v1/users/me/profile", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = profileSchema.parse(request.body);
    return { data: await dependencies.userService.updateProfile(currentUser.id, body) };
  });

  app.patch("/v1/users/me/privacy", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = privacySchema.parse(request.body);
    return { data: await dependencies.userService.updatePrivacy(currentUser.id, body) };
  });

  app.patch("/v1/users/me/security", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = securitySchema.parse(request.body);
    return { data: await dependencies.userService.updateSecurity(currentUser.id, body) };
  });

  app.patch("/v1/users/me/notifications", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = notificationSchema.parse(request.body);
    return { data: await dependencies.userService.updateNotifications(currentUser.id, body) };
  });

  app.patch("/v1/users/me/theme", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = themeSchema.parse(request.body);
    return { data: await dependencies.userService.updateTheme(currentUser.id, body) };
  });

  app.patch("/v1/users/me/email", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = z.object({ email: z.string().email() }).parse(request.body);
    return { data: await dependencies.userService.updateEmail(currentUser.id, body.email) };
  });

  app.patch("/v1/users/me/phone", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = z.object({ phone: z.string().min(7) }).parse(request.body);
    return { data: await dependencies.userService.updatePhone(currentUser.id, body.phone) };
  });

  app.post("/v1/users/me/export", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.userService.requestArchive(currentUser.id) };
  });

  app.get("/v1/users/me/export", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.userService.listArchiveJobs(currentUser.id) };
  });

  app.get("/v1/users/me/export/data", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.userService.exportUserData(currentUser.id) };
  });

  app.post("/v1/users/me/delete", async (request) => {
    const currentUser = requireCurrentUser(request);
    const body = z.object({ reason: z.string().optional() }).parse(request.body || {});
    return { data: await dependencies.userService.scheduleDeletion(currentUser.id, body.reason) };
  });

  app.post("/v1/users/me/recover", async (request) => {
    const currentUser = requireCurrentUser(request);
    return { data: await dependencies.userService.recoverAccount(currentUser.id) };
  });

  app.get("/v1/users/me/activity", async (request) => {
    const currentUser = requireCurrentUser(request);
    const query = z.object({ limit: z.coerce.number().int().positive().max(200).optional() }).parse(request.query);
    return { data: await dependencies.userService.listActivity(currentUser.id, query.limit) };
  });

  app.get("/v1/users/me/login-history", async (request) => {
    const currentUser = requireCurrentUser(request);
    const query = z.object({ limit: z.coerce.number().int().positive().max(200).optional() }).parse(request.query);
    return { data: await dependencies.userService.listLoginHistory(currentUser.id, query.limit) };
  });
};
