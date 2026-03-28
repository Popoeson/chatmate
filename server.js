import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import http from "http";
import { Server } from "socket.io";

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

  // When frontend sends userId after login
  socket.on("register", (userId) => {
    onlineUsers.set(userId, socket.id);
    console.log("✅ Registered user:", userId);
  });

  socket.on("disconnect", () => {
    console.log("❌ User disconnected:", socket.id);

    // remove user from map
    for (let [userId, sId] of onlineUsers.entries()) {
      if (sId === socket.id) {
        onlineUsers.delete(userId);
        break;
      }
    }
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