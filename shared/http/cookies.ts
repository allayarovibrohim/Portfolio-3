import type { FastifyReply } from "fastify";
import { env } from "../../config/env";

const cookieBase = {
  httpOnly: true,
  secure: env.COOKIE_SECURE,
  sameSite: env.COOKIE_SAME_SITE,
  domain: env.COOKIE_DOMAIN,
  path: "/",
} as const;

export const setAccessTokenCookie = (reply: FastifyReply, token: string) => {
  reply.setCookie("access_token", token, {
    ...cookieBase,
    maxAge: 60 * 15,
  });
};

export const setRefreshTokenCookie = (reply: FastifyReply, token: string) => {
  reply.setCookie("refresh_token", token, {
    ...cookieBase,
    maxAge: 60 * 60 * 24 * 30,
  });
};

export const clearAuthCookies = (reply: FastifyReply) => {
  reply.clearCookie("access_token", cookieBase);
  reply.clearCookie("refresh_token", cookieBase);
};
