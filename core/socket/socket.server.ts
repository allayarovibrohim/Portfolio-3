import type { Server as HttpServer } from "http";
import { Server as SocketIOServer } from "socket.io";
import { env } from "../../config/env";

export let io: SocketIOServer | null = null;

export const buildSocketServer = (server: HttpServer) => {
  io = new SocketIOServer(server, {
    cors: {
      origin: env.SOCKET_CORS_ORIGIN,
      credentials: true,
    },
  });

  io.on("connection", (socket) => {
    socket.on("presence:update", (payload) => {
      socket.broadcast.emit("presence:update", payload);
    });
  });

  return io;
};
