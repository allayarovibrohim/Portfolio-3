import type { PrismaClient } from "@prisma/client";
import { StorageService } from "../../../core/storage/storage.service";
import { QueueService } from "../../../services/queue/src/queue.service";

export interface FileRegistrationInput {
  userId?: string;
  provider: "LOCAL" | "S3" | "CLOUDINARY";
  key: string;
  originalName: string;
  mimeType: string;
  sizeBytes: number;
  publicUrl?: string;
}

export class FileService {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly storage: StorageService,
    private readonly queueService: QueueService,
  ) {}

  createSignedUpload(filename: string, mimeType: string) {
    return this.storage.createSignedUpload(filename, mimeType);
  }

  async registerUploadedFile(input: FileRegistrationInput) {
    const asset = await this.prisma.fileAsset.create({
      data: {
        userId: input.userId,
        provider: input.provider,
        key: input.key,
        originalName: input.originalName,
        mimeType: input.mimeType,
        sizeBytes: input.sizeBytes,
        publicUrl: input.publicUrl,
      },
    });

    await this.queueService.enqueueImageProcessing({
      fileAssetId: asset.id,
      key: asset.key,
      mimeType: asset.mimeType,
    });

    return asset;
  }

  listFilesForUser(userId: string) {
    return this.prisma.fileAsset.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
  }
}
