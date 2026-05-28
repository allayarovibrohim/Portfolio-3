import { createLogger, format, transports } from "winston";
import { mkdirSync } from "fs";
import { join } from "path";

mkdirSync(join(process.cwd(), "logs"), { recursive: true });

const baseFormat = format.combine(
  format.timestamp(),
  format.errors({ stack: true }),
  format.metadata({ fillExcept: ["message", "level", "timestamp"] }),
  format.json(),
);

export const logger = createLogger({
  level: process.env.NODE_ENV === "production" ? "info" : "debug",
  defaultMeta: {
    service: "lunex-enterprise-api",
  },
  transports: [
    new transports.Console({
      format:
        process.env.NODE_ENV === "production"
          ? baseFormat
          : format.combine(
              format.colorize(),
              format.timestamp(),
              format.printf(({ level, message, timestamp, stack }) => {
                return `${timestamp} ${level}: ${stack || message}`;
              }),
            ),
    }),
    new transports.File({
      filename: "logs/app-error.log",
      level: "error",
      format: baseFormat,
    }),
    new transports.File({
      filename: "logs/app-combined.log",
      format: baseFormat,
    }),
  ],
});
