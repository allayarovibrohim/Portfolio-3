import jwt, { SignOptions } from "jsonwebtoken";
import { env } from "../../config/env";
import { UnauthorizedError } from "../http/errors";

export interface JwtPayloadShape {
  sub: string;
  type: "access" | "refresh" | "magic-link";
  sessionId?: string;
  deviceId?: string;
  roles?: string[];
  permissions?: string[];
  fingerprint?: string;
  jti?: string;
  [key: string]: unknown;
}

const baseOptions: SignOptions = {
  issuer: env.JWT_ISSUER,
  audience: env.JWT_AUDIENCE,
};

export const signAccessToken = (payload: JwtPayloadShape) =>
  jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    ...baseOptions,
    expiresIn: env.ACCESS_TOKEN_TTL,
  });

export const signRefreshToken = (payload: JwtPayloadShape) =>
  jwt.sign(payload, env.JWT_REFRESH_SECRET, {
    ...baseOptions,
    expiresIn: env.REFRESH_TOKEN_TTL,
  });

export const signMagicLinkToken = (payload: JwtPayloadShape) =>
  jwt.sign(payload, env.JWT_MAGIC_LINK_SECRET, {
    ...baseOptions,
    expiresIn: `${env.MAGIC_LINK_TTL_MINUTES}m`,
  });

export const verifyAccessToken = (token: string) => verifyToken(token, env.JWT_ACCESS_SECRET);
export const verifyRefreshToken = (token: string) => verifyToken(token, env.JWT_REFRESH_SECRET);
export const verifyMagicLinkToken = (token: string) => verifyToken(token, env.JWT_MAGIC_LINK_SECRET);

const verifyToken = (token: string, secret: string) => {
  try {
    return jwt.verify(token, secret, baseOptions) as JwtPayloadShape;
  } catch {
    throw new UnauthorizedError("Token is invalid or expired");
  }
};
