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
const server = http.createServer(app);

/* =========================
   SOCKET SETUP
========================= */
export const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

/* =========================
   ONLINE USERS MAP
========================= */
export const onlineUsers = new Map();

/* =========================
   SOCKET LOGIC
========================= */
io.on("connection", (socket) => {
  console.log("⚡ Connected:", socket.id);

  /* =========================
     REGISTER USER
  ========================= */
  socket.on("register", async (userId) => {
    if (!userId) return;

    socket.userId = userId;
    onlineUsers.set(userId, socket.id);

    console.log("✅ Registered:", userId);

    try {
      // Deliver undelivered messages
      const pending = await Message.find({
        receiver: userId,
        delivered: false
      }).sort({ createdAt: 1 });

      for (const msg of pending) {
        socket.emit("receive_message", {
          from: msg.sender.toString(),
          message: msg.text,
          messageId: msg._id.toString(),
          timestamp: msg.createdAt,
          replyTo: msg.replyTo || null
        });

        // mark delivered
        msg.delivered = true;
        await msg.save();

        // notify sender about delivery
        const senderSocket = onlineUsers.get(msg.sender.toString());

        if (senderSocket) {
          io.to(senderSocket).emit("message_delivered", {
            friendId: msg.receiver.toString(),
            messageId: msg._id.toString()
          });
        }
      }
    } catch (err) {
      console.error("Queue error:", err);
    }
  });

  /* =========================
     TYPING
  ========================= */
  socket.on("typing_start", ({ to }) => {
    const target = onlineUsers.get(to);
    if (target) {
      io.to(target).emit("typing_start", { from: socket.userId });
    }
  });

  socket.on("typing_stop", ({ to }) => {
    const target = onlineUsers.get(to);
    if (target) {
      io.to(target).emit("typing_stop", { from: socket.userId });
    }
  });

  /* =========================
     SEND MESSAGE
  ========================= */
  socket.on("send_message", async ({ to, message, replyTo }) => {
    const senderId = socket.userId;
    if (!senderId || !to || !message?.trim()) return;

    try {
      const recipientSocket = onlineUsers.get(to);
      const isOnline = !!recipientSocket;

      const saved = await Message.create({
        sender: senderId,
        receiver: to,
        text: message.trim(),
        delivered: false,
        read: false
      });

      // attach reply
      if (replyTo?.messageId) {
        saved.replyTo = replyTo;
        await saved.save();
      }

      const senderUser = await User.findById(senderId).select("username avatarUrl");
      const receiverUser = await User.findById(to).select("username avatarUrl");

      /* =========================
         DELIVER MESSAGE
      ========================= */
      if (isOnline) {
        io.to(recipientSocket).emit("receive_message", {
          from: senderId,
          message: saved.text,
          messageId: saved._id.toString(),
          timestamp: saved.createdAt,
          replyTo: replyTo || null
        });

        saved.delivered = true;
        await saved.save();

        // sender sees delivery tick
        socket.emit("message_delivered", {
          friendId: to,
          messageId: saved._id.toString()
        });
      }

      /* =========================
         UPDATE CHAT LIST (SENDER)
      ========================= */
      socket.emit("new_conversation_message", {
        friendId: to,
        username: receiverUser.username,
        avatarUrl: receiverUser.avatarUrl || "",
        lastMessage: saved.text,
        lastTime: saved.createdAt,
        lastSender: senderId,
        delivered: isOnline
      });

      /* =========================
         UPDATE CHAT LIST (RECEIVER)
      ========================= */
      if (isOnline) {
        io.to(recipientSocket).emit("new_conversation_message", {
          friendId: senderId,
          username: senderUser.username,
          avatarUrl: senderUser.avatarUrl || "",
          lastMessage: saved.text,
          lastTime: saved.createdAt,
          lastSender: senderId,
          delivered: true
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

  /* =========================
     CHAT OPENED (DELIVER UPDATE)
  ========================= */
  socket.on("chat_opened", async ({ from }) => {
    const userId = socket.userId;

    try {
      await Message.updateMany(
        {
          sender: from,
          receiver: userId,
          delivered: false
        },
        { $set: { delivered: true } }
      );
    } catch (err) {
      console.error("chat_opened error:", err);
    }
  });

  /* =========================
     READ RECEIPT SYNC
  ========================= */
  socket.on("chat_read", async ({ friendId }) => {
    const userId = socket.userId;

    const senderSocket = onlineUsers.get(friendId);

    if (senderSocket) {
      io.to(senderSocket).emit("chat_read", {
        friendId: userId
      });
    }
  });

  /* =========================
     DISCONNECT
  ========================= */
  socket.on("disconnect", () => {
    for (const [uid, sid] of onlineUsers.entries()) {
      if (sid === socket.id) {
        onlineUsers.delete(uid);
        break;
      }
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
   DB CONNECT
========================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");

    server.listen(process.env.PORT, () => {
      console.log(`🚀 Server running on ${process.env.PORT}`);
    });
  })
  .catch(err => console.error(err));