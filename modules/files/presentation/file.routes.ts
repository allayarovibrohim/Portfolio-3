import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { UnauthorizedError } from "../../../shared/http/errors";

const signUploadSchema = z.object({
  filename: z.string().min(1),
  mimeType: z.string().min(1),
});

const registerFileSchema = z.object({
  provider: z.enum(["LOCAL", "S3", "CLOUDINARY"]),
  key: z.string().min(1),
  originalName: z.string().min(1),
  mimeType: z.string().min(1),
  sizeBytes: z.number().int().positive(),
  publicUrl: z.string().url().optional(),
});

export const registerFileRoutes = async (
  app: FastifyInstance,
  dependencies: {
    fileService: {
      createSignedUpload: (filename: string, mimeType: string) => Promise<unknown>;
      registerUploadedFile: (input: z.infer<typeof registerFileSchema> & { userId?: string }) => Promise<unknown>;
      listFilesForUser: (userId: string) => Promise<unknown>;
    };
  },
) => {
  app.post("/v1/files/sign-upload", async (request) => {
    if (!request.currentUser) {
      throw new UnauthorizedError();
    }

    const body = signUploadSchema.parse(request.body);
    return {
      data: await dependencies.fileService.createSignedUpload(body.filename, body.mimeType),
    };
  });

  app.post("/v1/files/register", async (request) => {
    if (!request.currentUser) {
      throw new UnauthorizedError();
    }

    const body = registerFileSchema.parse(request.body);
    return {
      data: await dependencies.fileService.registerUploadedFile({
        ...body,
        userId: request.currentUser.id,
      }),
    };
  });

  app.get("/v1/files", async (request) => {
    if (!request.currentUser) {
      throw new UnauthorizedError();
    }

    return {
      data: await dependencies.fileService.listFilesForUser(request.currentUser.id),
    };
  });
};
