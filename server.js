import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import http from "http";
import { Server } from "socket.io";
import Message from "./models/Message.js";
import User from "./models/User.js";
import authRoutes from "./routes/auth.js";

dotenv.config();
const app = express();

/* =========================
   CREATE HTTP SERVER
========================= */
const server = http.createServer(app);

/* =========================
   SOCKET.IO SETUP
========================= */
export const io = new Server(server, {
  cors: {
    origin: "*", // 🔥 change to your frontend URL in production
    methods: ["GET", "POST"]
  }
});

/* =========================
   STORE CONNECTED USERS
========================= */
// userId → socketId
export const onlineUsers = new Map();

/* =========================
   SOCKET CONNECTION
========================= */
io.on("connection", (socket) => {
  console.log("⚡ User connected:", socket.id);

  // ── REGISTER ────────────────────────────────────────────
  socket.on("register", async (userId) => {
    if (!userId || userId === "null") return;
    onlineUsers.set(userId, socket.id);
    socket.userId = userId;
    console.log("✅ Registered:", userId);

    try {
      const pending = await Message.find({
        receiver: userId,
        delivered: false
      }).sort({ createdAt: 1 });

      for (const msg of pending) {
        socket.emit("receive_message", {
          from:      msg.sender.toString(),
          message:   msg.text,
          messageId: msg._id.toString(),
          timestamp: msg.createdAt,
          replyTo:   msg.replyTo?.messageId ? {
            messageId: msg.replyTo.messageId.toString(),
            text:      msg.replyTo.text,
            sender:    msg.replyTo.sender.toString()
          } : null
        });
        msg.delivered = true;
        await msg.save();
      }
    } catch (err) {
      console.error("Queue flush error:", err);
    }
  });

  // ── TYPING ──────────────────────────────────────────────
  socket.on("typing_start", ({ to }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("typing_start", { from: socket.userId });
    }
  });

  socket.on("typing_stop", ({ to }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("typing_stop", { from: socket.userId });
    }
  });

  // ── SEND MESSAGE ────────────────────────────────────────
  socket.on("send_message", async ({ to, message, replyTo }) => {
    const senderId = socket.userId;
    if (!senderId || !to || !message?.trim()) return;

    try {
      const recipientSocketId = onlineUsers.get(to);
      const isOnline = !!recipientSocketId;

      const msgData = {
        sender:    senderId,
        receiver:  to,
        text:      message.trim(),
        delivered: isOnline,
        read:      false
      };

      if (replyTo?.messageId) {
        msgData.replyTo = {
          messageId: replyTo.messageId,
          text:      replyTo.text,
          sender:    replyTo.sender
        };
      }

      const saved = await Message.create(msgData);
      const senderUser = await User.findById(senderId).select("username avatarUrl");

      if (isOnline) {
        io.to(recipientSocketId).emit("receive_message", {
          from:      senderId,
          message:   saved.text,
          messageId: saved._id.toString(),
          timestamp: saved.createdAt,
          replyTo:   replyTo || null
        });

        io.to(recipientSocketId).emit("new_conversation_message", {
          friendId:    senderId,
          username:    senderUser.username,
          avatarUrl:   senderUser.avatarUrl || "",
          lastMessage: saved.text,
          lastTime:    saved.createdAt,
          unreadCount: 1
        });
      }

      socket.emit("message_sent", {
        messageId: saved._id.toString(),
        timestamp: saved.createdAt
      });

    } catch (err) {
      console.error("send_message error:", err);
    }
  });

  // ── DISCONNECT ──────────────────────────────────────────
  socket.on("disconnect", () => {
    for (const [uid, sid] of onlineUsers.entries()) {
      if (sid === socket.id) { onlineUsers.delete(uid); break; }
    }
    console.log("❌ Disconnected:", socket.id);
  });
});

/* =========================
   MIDDLEWARE
========================= */
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =========================
   ROUTES
========================= */
app.use("/api/auth", authRoutes);

/* =========================
   MONGODB CONNECTION
========================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");

    server.listen(process.env.PORT, () =>
      console.log(`🚀 Server running on port ${process.env.PORT}`)
    );
  })
  .catch(err => console.error("MongoDB connection error:", err));