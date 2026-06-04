import { io } from "../../../core/socket/socket.server";

export class RealtimeService {
  emitUserNotification(userId: string, payload: Record<string, unknown>) {
    io?.to(`user:${userId}`).emit("notification:new", payload);
  }

  bindUserSocket(socketId: string, userId: string) {
    io?.sockets.sockets.get(socketId)?.join(`user:${userId}`);
  }

  bindAdminSocket(socketId: string) {
    io?.sockets.sockets.get(socketId)?.join("admins");
  }
}
