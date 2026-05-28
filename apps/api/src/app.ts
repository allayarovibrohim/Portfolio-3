import Fastify from "fastify";
import fastifyCookie from "@fastify/cookie";
import fastifyCors from "@fastify/cors";
import fastifyCsrfProtection from "@fastify/csrf-protection";
import fastifyHelmet from "@fastify/helmet";
import fastifyMultipart from "@fastify/multipart";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifySwagger from "@fastify/swagger";
import fastifySwaggerUi from "@fastify/swagger-ui";
import { readFile } from "fs/promises";
import { join, normalize } from "path";
import { env } from "../../../config/env";
import { buildContainer, type ServiceContainer } from "./container";
import { attachRequestContext } from "../../../shared/http/request-context";
import { verifyAccessToken } from "../../../shared/security/jwt";
import { AppError, NotFoundError, UnauthorizedError } from "../../../shared/http/errors";
import { sanitizeObject } from "../../../shared/security/sanitize";
import { incrementMetric } from "../../../core/monitoring/metrics";
import { registerSystemRoutes } from "../../../modules/system/presentation/system.routes";
import { registerAuthRoutes } from "../../../modules/auth/presentation/auth.routes";
import { registerUserRoutes } from "../../../modules/users/presentation/user.routes";
import { registerFileRoutes } from "../../../modules/files/presentation/file.routes";
import { registerNotificationRoutes } from "../../../modules/notifications/presentation/notification.routes";
import { registerAdminRoutes } from "../../../modules/admin/presentation/admin.routes";
import { clearAuthCookies } from "../../../shared/http/cookies";
import { parseApiKey, verifySignedRequest } from "../../../shared/security/api-signing";
import { flattenRolePermissions } from "../../../shared/security/rbac";

const resolveAuthToken = (authorization?: string, cookieToken?: string) => {
  if (authorization?.startsWith("Bearer ")) {
    return authorization.slice("Bearer ".length);
  }

  return cookieToken;
};

export const buildApp = (container: ServiceContainer = buildContainer()) => {
  const app = Fastify({
    logger: false,
    trustProxy: true,
    bodyLimit: 10 * 1024 * 1024,
  });

  app.decorate("container", container);
  app.decorate("prisma", container.prisma);
  app.decorate("redis", container.redis);

  app.register(fastifyCors, {
    origin: env.FRONTEND_ORIGIN,
    credentials: true,
  });
  app.register(fastifyCookie);
  app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'", env.FRONTEND_ORIGIN, env.PUBLIC_BASE_URL],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  });
  app.register(fastifyMultipart, {
    limits: {
      fileSize: 25 * 1024 * 1024,
    },
  });
  app.register(fastifyRateLimit, {
    global: true,
    max: env.RATE_LIMIT_MAX,
    timeWindow: env.RATE_LIMIT_WINDOW,
  });
  app.register(fastifyCsrfProtection, {
    cookieOpts: {
      httpOnly: true,
      // Cross-domain ishlashi uchun 'none' va secure true bo'lishi kerak
      sameSite: env.NODE_ENV === "production" ? "none" : "lax",
      secure: env.NODE_ENV === "production" ? true : env.COOKIE_SECURE,
      path: "/",
    },
  });

  if (env.SWAGGER_ENABLED) {
    app.register(fastifySwagger, {
      openapi: {
        info: {
          title: env.APP_NAME,
          version: "1.0.0",
          description: "Enterprise-grade SaaS backend for identity, collaboration, commerce, billing, and administration.",
        },
        servers: [{ url: env.PUBLIC_BASE_URL }],
        tags: [
          { name: "system" },
          { name: "auth" },
          { name: "users" },
          { name: "files" },
          { name: "notifications" },
          { name: "admin" },
        ],
      },
    });
    app.register(fastifySwaggerUi, {
      routePrefix: "/docs",
      uiConfig: {
        docExpansion: "list",
        deepLinking: false,
      },
    });
  }

  app.addHook("onRequest", async (request, reply) => {
    await attachRequestContext(request, reply);
    incrementMetric("requests.total");

    const token = resolveAuthToken(
      typeof request.headers.authorization === "string" ? request.headers.authorization : undefined,
      request.cookies.access_token,
    );

    if (token) {
      try {
        const payload = verifyAccessToken(token);
        request.currentUser = {
          id: payload.sub,
          sessionId: payload.sessionId,
          deviceId: payload.deviceId,
          roles: payload.roles || [],
          permissions: payload.permissions || [],
          fingerprint: payload.fingerprint,
        };
      } catch (error) {
        clearAuthCookies(reply);
        if (request.url.startsWith(`${env.API_PREFIX}/v1/admin`)) {
          throw error;
        }
      }
    }

    const apiKeyHeader = request.headers["x-api-key"];
    const signature = request.headers["x-signature"];
    const timestamp = request.headers["x-timestamp"];

    if (
      !request.currentUser &&
      typeof apiKeyHeader === "string" &&
      typeof signature === "string" &&
      typeof timestamp === "string"
    ) {
      const parsed = parseApiKey(apiKeyHeader);
      const apiKey = await container.prisma.apiKey.findUnique({
        where: {
          prefix: parsed.prefix,
        },
        include: {
          user: {
            include: {
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
            },
          },
        },
      });

      if (!apiKey || apiKey.revokedAt || (apiKey.expiresAt && apiKey.expiresAt.getTime() < Date.now())) {
        throw new UnauthorizedError("API key is invalid or revoked");
      }

      if (parsed.hashedSecret !== apiKey.hashedSecret) {
        throw new UnauthorizedError("API key secret is invalid");
      }

      verifySignedRequest({
        method: request.method,
        url: request.url,
        timestamp,
        providedSignature: signature,
        signingKey: apiKey.hashedSecret,
      });

      request.currentUser = {
        id: apiKey.userId,
        roles: apiKey.user.userRoles.map((assignment) => assignment.role.name),
        permissions: flattenRolePermissions(apiKey.user.userRoles),
      };
    }
  });

  app.addHook("preValidation", async (request) => {
    if (request.body) {
      request.body = sanitizeObject(request.body);
    }
    if (request.query) {
      request.query = sanitizeObject(request.query);
    }
  });

  app.addHook("preHandler", async (request, reply) => {
    if (env.MAINTENANCE_MODE && !request.url.includes("/health/")) {
      return reply.status(503).send({
        error: "Service is temporarily in maintenance mode",
      });
    }
  });

  app.addHook("onResponse", async (request, reply) => {
    incrementMetric(`http.status.${reply.statusCode}`);
    container.logger.info("http.request", {
      requestId: request.requestContext?.requestId,
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      userId: request.currentUser?.id,
      ipAddress: request.ip,
    });
  });

  app.setErrorHandler((error, request, reply) => {
    const appError = error instanceof AppError ? error : null;
    const statusCode = appError?.statusCode || 500;

    container.logger.error("http.error", {
      requestId: request.requestContext?.requestId,
      method: request.method,
      url: request.url,
      statusCode,
      message: error.message,
      stack: error.stack,
    });

    reply.status(statusCode).send({
      error: appError?.code || "INTERNAL_SERVER_ERROR",
      message: appError?.message || "Unexpected server error",
      details: appError?.details,
      requestId: request.requestContext?.requestId,
    });
  });

  app.get(`/${env.LOCAL_UPLOAD_DIR}/*`, async (request, reply) => {
    const wildcard = (request.params as { "*": string })["*"];
    const candidate = normalize(join(process.cwd(), env.LOCAL_UPLOAD_DIR, wildcard));
    const root = normalize(join(process.cwd(), env.LOCAL_UPLOAD_DIR));
    if (!candidate.startsWith(root)) {
      throw new UnauthorizedError("Invalid file path");
    }

    try {
      const file = await readFile(candidate);
      return reply.send(file);
    } catch {
      throw new NotFoundError("File not found");
    }
  });

  app.register(async (api) => {
    await registerSystemRoutes(api);
    await registerAuthRoutes(api, { authService: container.authService });
    await registerUserRoutes(api, { userService: container.userService });
    await registerFileRoutes(api, { fileService: container.fileService });
    await registerNotificationRoutes(api, { notificationService: container.notificationService });
    await registerAdminRoutes(api, { adminService: container.adminService });
  }, { prefix: env.API_PREFIX });

  return app;
};
