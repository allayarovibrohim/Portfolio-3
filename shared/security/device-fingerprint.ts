import { createHash } from "crypto";
import type { FastifyRequest } from "fastify";

export const buildDeviceFingerprint = (request: FastifyRequest) => {
  const supplied = request.headers["x-device-fingerprint"];
  if (typeof supplied === "string" && supplied.trim().length > 0) {
    return supplied.trim();
  }

  const payload = [
    request.ip,
    request.headers["user-agent"] || "unknown",
    request.headers["accept-language"] || "unknown",
    request.headers["sec-ch-ua-platform"] || "unknown",
  ].join("|");

  return createHash("sha256").update(payload).digest("hex");
};
