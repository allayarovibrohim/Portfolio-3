import argon2 from "argon2";
import { env } from "../../config/env";
import { ValidationError } from "../http/errors";

const blockedPasswords = new Set([
  "password",
  "password123",
  "12345678",
  "qwerty123",
  "admin123",
]);

export const enforcePasswordPolicy = (password: string, historicalHashes: string[]) => {
  if (password.length < 12) {
    throw new ValidationError("Password must be at least 12 characters");
  }

  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    throw new ValidationError("Password must contain uppercase, lowercase, digit, and symbol");
  }

  if (blockedPasswords.has(password.toLowerCase())) {
    throw new ValidationError("Password is too common or already compromised");
  }

  return Promise.all(historicalHashes.map((hash) => argon2.verify(hash, password))).then((matches) => {
    if (matches.some(Boolean)) {
      throw new ValidationError("Password cannot match your recent passwords");
    }
  });
};

export const hashPassword = (password: string) =>
  argon2.hash(password, {
    memoryCost: env.ARGON2_MEMORY_COST,
    timeCost: env.ARGON2_TIME_COST,
    parallelism: env.ARGON2_PARALLELISM,
    type: argon2.argon2id,
  });

export const verifyPassword = (hash: string, password: string) => argon2.verify(hash, password);
