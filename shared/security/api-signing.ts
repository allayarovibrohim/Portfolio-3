import { UnauthorizedError } from "../http/errors";
import { constantTimeEqual, hashValue, signHmac } from "../utils/crypto";

export const parseApiKey = (value: string) => {
  const [prefix, secret] = value.split(".");
  if (!prefix || !secret) {
    throw new UnauthorizedError("API key is malformed");
  }

  return {
    prefix,
    secret,
    hashedSecret: hashValue(secret),
  };
};

export const verifySignedRequest = (input: {
  method: string;
  url: string;
  timestamp: string;
  providedSignature: string;
  signingKey: string;
  toleranceMs?: number;
}) => {
  const timestampNumber = Number(input.timestamp);
  if (!Number.isFinite(timestampNumber)) {
    throw new UnauthorizedError("Signature timestamp is invalid");
  }

  const toleranceMs = input.toleranceMs || 5 * 60 * 1000;
  if (Math.abs(Date.now() - timestampNumber) > toleranceMs) {
    throw new UnauthorizedError("Signed request timestamp is outside the allowed window");
  }

  const payload = `${timestampNumber}.${input.method.toUpperCase()}.${input.url}`;
  const expected = signHmac(payload, input.signingKey);
  if (!constantTimeEqual(expected, input.providedSignature)) {
    throw new UnauthorizedError("Request signature is invalid");
  }

  return true;
};
