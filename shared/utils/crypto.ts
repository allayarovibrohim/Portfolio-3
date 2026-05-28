import { createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";

export const hashValue = (value: string) => createHash("sha256").update(value).digest("hex");
export const sha1 = (value: string) => createHash("sha1").update(value).digest("hex").toUpperCase();
export const generateToken = (bytes = 32) => randomBytes(bytes).toString("hex");
export const generateNumericCode = (digits = 6) =>
  Array.from({ length: digits }, () => Math.floor(Math.random() * 10)).join("");

export const signHmac = (payload: string, secret: string) =>
  createHmac("sha256", secret).update(payload).digest("hex");

export const constantTimeEqual = (left: string, right: string) => {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return timingSafeEqual(leftBuffer, rightBuffer);
};
