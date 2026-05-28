import type { FastifyRequest } from "fastify";
import { buildDeviceFingerprint } from "../security/device-fingerprint";
import { resolveGeoLocation } from "../security/geo";

export interface RequestMetaSnapshot {
  ipAddress?: string;
  userAgent?: string;
  fingerprint: string;
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  requestId?: string;
  rememberMe?: boolean;
}

export const buildRequestMeta = (
  request: FastifyRequest,
  options?: {
    rememberMe?: boolean;
  },
): RequestMetaSnapshot => {
  const geo = resolveGeoLocation(request.ip);

  return {
    ipAddress: request.ip,
    userAgent: request.headers["user-agent"],
    fingerprint: buildDeviceFingerprint(request),
    country: geo.country,
    region: geo.region,
    city: geo.city,
    latitude: geo.latitude,
    longitude: geo.longitude,
    requestId: request.requestContext?.requestId,
    rememberMe: options?.rememberMe,
  };
};
