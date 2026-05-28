import { Queue } from "bullmq";
import { redis } from "../cache/redis";

export const emailQueue = new Queue("emails", { connection: redis });
export const notificationQueue = new Queue("notifications", { connection: redis });
export const imageQueue = new Queue("images", { connection: redis });
export const analyticsQueue = new Queue("analytics", { connection: redis });
export const cleanupQueue = new Queue("cleanup", { connection: redis });
