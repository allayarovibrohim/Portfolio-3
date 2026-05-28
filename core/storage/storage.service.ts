import { mkdir, writeFile } from "fs/promises";
import { dirname, join } from "path";
import { randomUUID } from "crypto";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { v2 as cloudinary } from "cloudinary";
import { env } from "../../config/env";

export interface UploadTarget {
  url: string;
  provider: "local" | "s3" | "cloudinary";
  key: string;
}

export class StorageService {
  private readonly s3 = env.ENABLE_S3_STORAGE
    ? new S3Client({
        region: env.S3_REGION,
        endpoint: env.S3_ENDPOINT,
        credentials: env.S3_ACCESS_KEY_ID && env.S3_SECRET_ACCESS_KEY
          ? {
              accessKeyId: env.S3_ACCESS_KEY_ID,
              secretAccessKey: env.S3_SECRET_ACCESS_KEY,
            }
          : undefined,
        forcePathStyle: env.S3_FORCE_PATH_STYLE,
      })
    : null;

  constructor() {
    if (env.ENABLE_CLOUDINARY_STORAGE) {
      cloudinary.config({
        cloud_name: env.CLOUDINARY_CLOUD_NAME,
        api_key: env.CLOUDINARY_API_KEY,
        api_secret: env.CLOUDINARY_API_SECRET,
      });
    }
  }

  async createSignedUpload(filename: string, mimeType: string): Promise<UploadTarget> {
    const key = `${new Date().toISOString().slice(0, 10)}/${randomUUID()}-${filename}`;

    if (env.ENABLE_S3_STORAGE && this.s3 && env.S3_BUCKET) {
      const command = new PutObjectCommand({
        Bucket: env.S3_BUCKET,
        Key: key,
        ContentType: mimeType,
      });
      const url = await getSignedUrl(this.s3, command, { expiresIn: 300 });
      return { key, url, provider: "s3" };
    }

    if (env.ENABLE_CLOUDINARY_STORAGE) {
      const signature = cloudinary.utils.api_sign_request(
        {
          timestamp: Math.floor(Date.now() / 1000),
          folder: "lunex-enterprise",
          public_id: key,
        },
        env.CLOUDINARY_API_SECRET || "",
      );

      return {
        key,
        provider: "cloudinary",
        url: `https://api.cloudinary.com/v1_1/${env.CLOUDINARY_CLOUD_NAME}/auto/upload?api_key=${env.CLOUDINARY_API_KEY}&timestamp=${Math.floor(Date.now() / 1000)}&signature=${signature}`,
      };
    }

    const directory = join(process.cwd(), env.LOCAL_UPLOAD_DIR, new Date().toISOString().slice(0, 10));
    await mkdir(directory, { recursive: true });
    return {
      key,
      provider: "local",
      url: `${env.PUBLIC_BASE_URL}/${env.LOCAL_UPLOAD_DIR}/${key}`,
    };
  }

  async persistLocalFile(key: string, content: Buffer) {
    const target = join(process.cwd(), env.LOCAL_UPLOAD_DIR, key);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content);
  }
}
