import express from "express";
import mongoose from "mongoose";
import Message from "../models/Message.js";
import User from "../models/User.js";
import OTP from "../models/OTP.js";
import FriendRequest from "../models/FriendRequest.js";
import authenticateJWT from "../middlewares/authenticateJWT.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { sendOTPEmail } from "../utils/sendEmail.js";
import validator from "validator";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";
import { io, onlineUsers } from "../server.js";

const router = express.Router();
const rateLimitMap = new Map(); // key: userId, value: { count, firstRequestTime }


/* =========================
   CLOUDINARY CONFIG
========================= */
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_KEY,
  api_secret: process.env.CLOUDINARY_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "avatars",
    allowed_formats: ["jpg","png","jpeg","webp"],
    transformation: [{ width: 300, height: 300, crop: "thumb", gravity: "face" }]
  }
});

const upload = multer({ storage });

/* =========================
   GET LOGGED-IN USER
========================= */
router.get("/me", authenticateJWT, async (req, res)=>{
  try{
    const user = await User.findById(req.userId).select("-passwordHash -__v");
    if(!user) return res.status(404).json({ message: "User not found" });

    res.status(200).json({ user });
  }catch(err){
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   UPDATE PROFILE
========================= */
router.post("/update-profile", authenticateJWT, upload.single("avatar"), async (req,res)=>{
  const userId = req.userId;
  const { phone, email, username, bio, lastSeenVisible, links } = req.body;

  try{
    // ===== Rate Limiting =====
    const now = Date.now();
    const limitWindow = 60 * 1000;
    const maxAttempts = 2;

    const userRate = rateLimitMap.get(userId) || { count: 0, firstRequestTime: now };

    if(now - userRate.firstRequestTime > limitWindow){
      userRate.count = 0;
      userRate.firstRequestTime = now;
    }

    userRate.count += 1;
    rateLimitMap.set(userId, userRate);

    if(userRate.count > maxAttempts){
      return res.status(429).json({ message: "Too many attempts. Try again later." });
    }

    const user = await User.findById(userId);
    if(!user) return res.status(404).json({ message: "User not found" });

    if(!phone || !email || !username)
      return res.status(400).json({ message: "Phone, email, and username required" });

    if(!validator.isEmail(email))
      return res.status(400).json({ message: "Invalid email format" });

    const existing = await User.findOne({ username, _id: { $ne: user._id } });
    if(existing) return res.status(400).json({ message: "Username already taken" });

    user.phone = phone;
    user.email = email.toLowerCase();
    user.username = username;
    user.bio = bio || "";
    user.lastSeenVisible = lastSeenVisible === "true" || lastSeenVisible === true;
    user.links = Array.isArray(links) ? links : [];

    if(req.file && req.file.path) user.avatarUrl = req.file.path;

    // 🔐 Invalidate old token
    user.tokenVersion += 1;
    await user.save();

    const newToken = jwt.sign(
      { userId: user._id, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: "3d" }
    );

    res.status(200).json({ message: "Profile updated", user, newToken });

  }catch(err){
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   REGISTER
========================= */
router.post("/register", async (req, res) => {
  let { email, phone, password } = req.body;

  if (!email || !phone || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  email = email.toLowerCase().trim();

  if (!validator.isEmail(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  if (!/^\d{10,15}$/.test(phone)) {
    return res.status(400).json({ message: "Invalid phone number" });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters" });
  }

  try {
    let user = await User.findOne({ email });

    if (user && user.isVerified) {
      return res.status(400).json({ message: "Account already exists. Please login." });
    }

    if (!user) {
      const passwordHash = await bcrypt.hash(password, 10);

      user = await User.create({
        email,
        phone,
        passwordHash,
        isVerified: false,
        registrationStep: "otp_pending"
      });
    }

    const existingOTP = await OTP.findOne({ userId: user._id, purpose: "verify" });
    const now = new Date();

    if (existingOTP && (now - existingOTP.lastSentAt < 60 * 1000)) {
      return res.status(429).json({ message: "Please wait before requesting another OTP" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);

    await OTP.deleteOne({ userId: user._id, purpose: "verify" });

    await OTP.create({
      userId: user._id,
      otpHash,
      expiresAt: new Date(now.getTime() + 5 * 60 * 1000),
      lastSentAt: now,
      attempts: 0,
      purpose: "verify"
    });

    await sendOTPEmail(email, otp);

    res.status(200).json({ message: "OTP sent", userId: user._id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   VERIFY OTP (REGISTER)
========================= */
router.post("/verify-otp", async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ message: "Invalid input" });
  }

  try {
    const otpRecord = await OTP.findOne({ userId, purpose: "verify" });
    if (!otpRecord) return res.status(400).json({ message: "OTP not found or expired" });

    if (otpRecord.expiresAt < new Date()) {
      await OTP.deleteOne({ userId, purpose: "verify" });
      return res.status(400).json({ message: "OTP expired" });
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isMatch) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: "Invalid OTP" });
    }

    const user = await User.findByIdAndUpdate(
  userId,
  { isVerified: true, registrationStep: "verified", tokenVersion: 1 },
  { new: true }
);

    await OTP.deleteOne({ userId, purpose: "verify" });

    const token = jwt.sign(
      { userId: user._id, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      message: "Verified successfully",
      token,
      user: { email: user.email, phone: user.phone }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   RESEND OTP
========================= */
router.post("/resend-otp", async (req, res) => {
  const { userId } = req.body;

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const otpRecord = await OTP.findOne({ userId, purpose: "verify" });
    const now = new Date();

    if (otpRecord && (now - otpRecord.lastSentAt < 60 * 1000)) {
      return res.status(429).json({ message: "Wait before requesting another OTP" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);

    await OTP.deleteOne({ userId, purpose: "verify" });

    await OTP.create({
      userId,
      otpHash,
      expiresAt: new Date(now.getTime() + 5 * 60 * 1000),
      lastSentAt: now,
      attempts: 0,
      purpose: "verify"
    });

    await sendOTPEmail(user.email, otp);

    res.status(200).json({ message: "OTP resent successfully" });

  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   LOGIN
========================= */
router.post("/login", async (req, res) => {
  const { identifier, password } = req.body;

  try {
    let user = identifier.includes("@")
      ? await User.findOne({ email: identifier.toLowerCase() })
      : await User.findOne({ username: identifier });

    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    if (!user.isVerified) {
      return res.status(403).json({ message: "Verify your account first" });
    }

    const token = jwt.sign(
      { userId: user._id, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: "3d" }
    );

    res.json({ message: "Login successful", token });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   FORGOT PASSWORD
========================= */
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });

    const existingOTP = await OTP.findOne({ userId: user._id, purpose: "reset_password" });
    const now = new Date();

    if (existingOTP && (now - existingOTP.lastSentAt < 60 * 1000)) {
      return res.status(429).json({ message: "Wait before requesting OTP" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);

    await OTP.deleteOne({ userId: user._id, purpose: "reset_password" });

    await OTP.create({
      userId: user._id,
      otpHash,
      expiresAt: new Date(now.getTime() + 5 * 60 * 1000),
      lastSentAt: now,
      attempts: 0,
      purpose: "reset_password"
    });

    await sendOTPEmail(user.email, otp);

    res.json({ message: "OTP sent" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   VERIFY RESET OTP
========================= */
router.post("/verify-reset-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    const otpRecord = await OTP.findOne({ userId: user._id, purpose: "reset_password" });

    if (!otpRecord) return res.status(400).json({ message: "OTP not found" });

    const isMatch = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isMatch) return res.status(400).json({ message: "Invalid OTP" });

    // mark verified
    user.resetVerified = true;
    await user.save();

    otpRecord.isVerified = true;
await otpRecord.save();

    res.json({ message: "OTP verified" });

  } catch {
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   RESET PASSWORD
========================= */
router.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !validator.isEmail(email)) {
    return res.status(400).json({ message: "Invalid email" });
  }

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters" });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otpRecord = await OTP.findOne({
      userId: user._id,
      purpose: "reset_password"
    });

    if (!otpRecord || !otpRecord.isVerified) {
      return res.status(400).json({ message: "OTP verification required" });
    }

    // Update password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;

    // Invalidate old sessions
    user.tokenVersion += 1;

    await user.save();

    // Clean up OTP AFTER success
    await OTP.deleteOne({ userId: user._id, purpose: "reset_password" });

    res.status(200).json({ message: "Password updated successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   SEARCH USERS
========================= */
router.get('/users/search', authenticateJWT, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const query = req.query.username || '';
    if (!query) return res.json({ users: [] });

    // Find users matching the query
    let users = await User.find({
      username: { $regex: query, $options: 'i' },
      _id: { $ne: currentUserId } // exclude self
    })
    .select('_id username avatarUrl bio')
    .limit(10)
    .lean();

    // Fetch blocked relationships involving current user
    const blockedRelations = await FriendRequest.find({
      $or: [
        { requester: currentUserId, status: "blocked" }, // users currentUser blocked
        { recipient: currentUserId, status: "blocked" }  // users who blocked currentUser
      ]
    }).lean();

    const blockedByCurrentUser = blockedRelations
      .filter(r => r.requester.toString() === currentUserId.toString())
      .map(r => r.recipient.toString());

    const blockedByOthers = blockedRelations
      .filter(r => r.recipient.toString() === currentUserId.toString())
      .map(r => r.requester.toString());

    // Mark blocked info on each user
    users = users
      .map(u => ({
        ...u,
        blocked: blockedByCurrentUser.includes(u._id.toString()),   // we blocked them
        blockedBy: blockedByOthers.includes(u._id.toString()) ? [currentUserId] : [] // they blocked us
      }))
      // Remove users who blocked current user (optional)
      .filter(u => !blockedByOthers.includes(u._id.toString()));

    res.json({ users });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* =========================
   FRIEND REQUEST
========================= */
router.post('/friends/request', authenticateJWT, async (req, res) => {
  try {
    const requesterId = req.userId;
    const { userId } = req.body;

    if (!userId) return res.status(400).json({ message: 'Recipient userId required' });
    if (userId === requesterId) return res.status(400).json({ message: "Cannot add yourself" });

    // Check if request already exists in either direction
    const existing = await FriendRequest.findOne({
      $or: [
        { requester: requesterId, recipient: userId },
        { requester: userId, recipient: requesterId },
      ]
    });

    if (existing) {
      return res.status(400).json({
        message: existing.status === 'pending'
          ? 'Friend request already pending'
          : 'You are already friends'
      });
    }

    const newRequest = new FriendRequest({
      requester: requesterId,
      recipient: userId,
      status: 'pending'
    });

    await newRequest.save();

    // 🔔 SOCKET: Notify recipient if online
    const recipientSocketId = onlineUsers.get(userId);
    if (recipientSocketId) {
      const requester = await User.findById(requesterId).select("username");
      io.to(recipientSocketId).emit("friend_request_received", {
        from: requesterId,
        username: requester.username
      });
    }

    res.json({ message: 'Friend request sent' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* =========================
   GET FRIENDS LIST
========================= */
router.get('/friends', authenticateJWT, async (req, res) => {
  try {
    const userId = req.userId.toString();

    const requests = await FriendRequest.find({
      $or: [
        { requester: userId },
        { recipient: userId }
      ]
    })
    .populate("requester", "username avatarUrl")
    .populate("recipient", "username avatarUrl");

    const accepted = [];
    const sent = [];
    const received = [];

    requests.forEach(reqItem => {
      if (!reqItem.requester || !reqItem.recipient) return;

      const requesterId = reqItem.requester._id.toString();
      const recipientId = reqItem.recipient._id.toString();

      const isRequester = requesterId == userId;
      const isRecipient = recipientId == userId;

      if (reqItem.status === "accepted") {
        const friend = isRequester ? reqItem.recipient : reqItem.requester;
        if (friend) accepted.push(friend);
      } else if (reqItem.status === "pending") {
        if (isRequester) sent.push(reqItem.recipient);
        if (isRecipient) received.push(reqItem.requester);
      }
    });

    res.json({
      friends: accepted,
      sentRequests: sent,
      receivedRequests: received
    });
  } catch (err) {
    console.error("FRIENDS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   ACCEPT REQUEST
========================= */
router.post('/friends/request/:userId/accept', authenticateJWT, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const requesterId = req.params.userId;

    const request = await FriendRequest.findOne({
      requester: requesterId,
      recipient: currentUserId,
      status: "pending"
    });

    if (!request) return res.status(404).json({ message: "Request not found" });

    request.status = "accepted";
    await request.save();

    // 🔔 SOCKET: Notify requester
    const requesterSocketId = onlineUsers.get(requesterId);
    if (requesterSocketId) {
      const currentUser = await User.findById(currentUserId).select("username");
      io.to(requesterSocketId).emit("friend_request_accepted", {
        by: currentUserId,
        username: currentUser.username
      });
    }

    res.json({ message: "Friend request accepted" });
  } catch (err) {
    console.error("ACCEPT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   REJECT REQUEST
========================= */
router.post('/friends/request/:userId/reject', authenticateJWT, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const requesterId = req.params.userId;

    const request = await FriendRequest.findOneAndDelete({
      requester: requesterId,
      recipient: currentUserId,
      status: "pending"
    });

    if (!request) return res.status(404).json({ message: "Request not found" });

    // 🔔 SOCKET: Notify requester
    const requesterSocketId = onlineUsers.get(requesterId);
    if (requesterSocketId) {
      const currentUser = await User.findById(currentUserId).select("username");
      io.to(requesterSocketId).emit("friend_request_rejected", {
        by: currentUserId,
        username: currentUser.username
      });
    }

    res.json({ message: "Friend request rejected" });
  } catch (err) {
    console.error("REJECT ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   DELETE REQUEST
========================= */
router.delete('/friends/request/:userId', authenticateJWT, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const recipientId = req.params.userId;

    const request = await FriendRequest.findOneAndDelete({
      requester: currentUserId,
      recipient: recipientId,
      status: "pending"
    });

    if (!request) return res.status(404).json({ message: "Request not found" });

    // 🔔 SOCKET: Notify recipient
    const recipientSocketId = onlineUsers.get(recipientId);
    if (recipientSocketId) {
      const currentUser = await User.findById(currentUserId).select("username");
      io.to(recipientSocketId).emit("friend_request_deleted", {
        by: currentUserId,
        username: currentUser.username
      });
    }

    res.json({ message: "Request cancelled" });
  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   UPDATE PENDING FRINED FOR HOME
========================= */
// GET pending friend requests count
router.get("/pending", authenticateJWT, async (req, res) => {
  try {
    const count = await FriendRequest.countDocuments({
      recipient: req.userId,
      status: "pending"
    });
    res.status(200).json({ count });
  } catch (err) {
    console.error("PENDING FRIENDS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   BLOCK USER
========================= */
router.post('/friends/block/:userId', authenticateJWT, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const targetUserId = req.params.userId;

    if (currentUserId === targetUserId) 
      return res.status(400).json({ message: "Cannot block yourself" });

    const request = await FriendRequest.findOne({
      $or: [
        { requester: currentUserId, recipient: targetUserId },
        { requester: targetUserId, recipient: currentUserId }
      ]
    });

    if (request) {
      request.status = "blocked"; // mark as blocked
      await request.save();
    } else {
      // If no friend request exists, create a blocked record
      await FriendRequest.create({
        requester: currentUserId,
        recipient: targetUserId,
        status: "blocked"
      });
    }

    // 🔔 SOCKET: optional notification
    const targetSocketId = onlineUsers.get(targetUserId);
    if (targetSocketId) {
      io.to(targetSocketId).emit("user_blocked", { by: currentUserId });
    }

    res.json({ message: "User blocked" });

  } catch (err) {
    console.error("BLOCK ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   UNBLOCK USER
========================= */
router.post('/friends/unblock/:userId', authenticateJWT, async (req, res) => {
  try {
    const currentUserId = req.userId;
    const targetUserId = req.params.userId;

    const request = await FriendRequest.findOne({
      requester: currentUserId,
      recipient: targetUserId,
      status: "blocked"
    });

    if (!request) return res.status(404).json({ message: "No blocked user found" });

    await request.deleteOne(); // remove the blocked record

    res.json({ message: "User unblocked" });

  } catch (err) {
    console.error("UNBLOCK ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});


/* =========================
   FETCH USERS FOR CHAT
========================= */

router.get('/users/:id', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findById(req.params.id)
      .select('_id username avatarUrl bio');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* =========================
   GET CHAT HISTORY
========================= */
router.get("/messages/:userId", authenticateJWT, async (req, res) => {
  try {

    const currentUserId = req.userId;
    const otherUserId = req.params.userId;

    const page = parseInt(req.query.page) || 1;
    const limit = 20;
    const skip = (page - 1) * limit;

    const messages = await Message.find({
      $or: [
        { sender: currentUserId, receiver: otherUserId },
        { sender: otherUserId, receiver: currentUserId }
      ]
    })
    .sort({ createdAt: -1 }) // newest first for pagination
    .skip(skip)
    .limit(limit)
    .select("sender receiver text delivered createdAt replyTo");

    res.json({
      messages: messages.reverse(), // restore correct UI order
      hasMore: messages.length === limit
    });

  } catch (err) {
    console.error("GET MESSAGES ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   GET CONVERSATIONS
========================= */
router.get("/conversations", authenticateJWT, async (req, res) => {
  try {
    const currentUserId = new mongoose.Types.ObjectId(req.userId);

    const conversations = await Message.aggregate([
      {
        $match: {
          $or: [
            { sender: currentUserId },
            { receiver: currentUserId }
          ]
        }
      },
      { $sort: { createdAt: -1 } },
      {
        $group: {
          _id: {
            $cond: [
              { $eq: ["$sender", currentUserId] },
              "$receiver",
              "$sender"
            ]
          },
          lastMessage: { $first: "$$ROOT" },
          unreadCount: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $eq: ["$receiver", currentUserId] },
                    { $eq: ["$read", false] }
                  ]
                },
                1, 0
              ]
            }
          }
        }
      },
      { $sort: { "lastMessage.createdAt": -1 } },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "friend"
        }
      },
      { $unwind: "$friend" },
      {
        $project: {
          _id: 0,
          friendId:    "$_id",
          username:    "$friend.username",
          avatarUrl:   "$friend.avatarUrl",
          lastMessage: "$lastMessage.text",
          lastTime:    "$lastMessage.createdAt",
          lastSender:  "$lastMessage.sender",
          delivered:   "$lastMessage.delivered",
          unreadCount: 1
        }
      }
    ]);

    res.json({ conversations });

  } catch (err) {
    console.error("GET CONVERSATIONS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   MARK MESSAGES AS READ
========================= */
router.get("/messages/:userId", authenticateJWT, async (req, res) => {

  try {

    const currentUserId = req.userId;
    const otherUserId = req.params.userId;

    const page = parseInt(req.query.page) || 1;
    const limit = 30;

    const messages = await Message.find({
      $or: [
        { sender: currentUserId, receiver: otherUserId },
        { sender: otherUserId, receiver: currentUserId }
      ]
    })
    .sort({ createdAt: -1 })
    .skip((page - 1) * limit)
    .limit(limit);

    res.json({ messages });

  } catch (err) {

    console.error(err);
    res.status(500).json({ message: "Server error" });

  }

});

/* =========================
   HEALTH CHECK
========================= */
router.get("/api/health", (req, res) => {
  res.send("Server is awake");
});

export default router;

