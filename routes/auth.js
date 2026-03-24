import express from "express";
import User from "../models/User.js";
import OTP from "../models/OTP.js";
import authenticateJWT from "../middlewares/authenticateJWT.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { sendOTPEmail } from "../utils/sendEmail.js";
import validator from "validator";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";

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
    const limitWindow = 60 * 1000; // 1 min
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

    // ===== Fetch user =====
    const user = await User.findById(userId);
    if(!user) return res.status(404).json({ message: "User not found" });

    // ===== Validation =====
    if(!phone || !email || !username)
      return res.status(400).json({ message: "Phone, email, and username required" });

    if(!validator.isEmail(email))
      return res.status(400).json({ message: "Invalid email format" });

    const existing = await User.findOne({ username, _id: { $ne: user._id } });
    if(existing) return res.status(400).json({ message: "Username already taken" });

    // ===== Update profile =====
    user.phone = phone;
    user.email = email.toLowerCase();
    user.username = username;
    user.bio = bio || "";
    user.lastSeenVisible = lastSeenVisible === "true" || lastSeenVisible === true;
    user.links = Array.isArray(links) ? links : [];
    if(req.file && req.file.path) user.avatarUrl = req.file.path;

    // ===== Invalidate old token =====
    user.tokenVersion += 1; // increments version => old tokens invalid
    await user.save();

    // ===== Generate new JWT =====
    const newToken = jwt.sign(
      { userId: user._id, tokenVersion: user.tokenVersion },
      process.env.JWT_SECRET,
      { expiresIn: '3d' }
    );

    res.status(200).json({ message: "Profile updated", user, newToken });

  }catch(err){
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   REGISTER ROUTE (FINAL)
========================= */
router.post("/register", async (req, res) => {
  let { email, phone, password } = req.body;

  /* =========================
     INPUT VALIDATION
  ========================= */

  if (!email || !phone || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  // Normalize email
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

    /* =========================
       DUPLICATE HANDLING
    ========================= */

    if (user) {
      if (user.isVerified) {
        return res.status(400).json({
          message: "Account already exists. Please login."
        });
      }
      // If not verified → continue (resend OTP flow)
    } else {
      const passwordHash = await bcrypt.hash(password, 10);

      user = await User.create({
        email,
        phone,
        passwordHash,
        isVerified: false,
        registrationStep: "otp_pending"
      });
    }

    /* =========================
       RATE LIMITING (OTP COOLDOWN)
    ========================= */

    const existingOTP = await OTP.findOne({ userId: user._id });

    if (existingOTP) {
      const now = new Date();

      // ⛔ 60 seconds cooldown
      if (existingOTP.lastSentAt && (now - existingOTP.lastSentAt) < 60 * 1000) {
        return res.status(429).json({
          message: "Please wait before requesting another OTP"
        });
      }
    }

    /* =========================
       GENERATE OTP
    ========================= */

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 mins

    /* =========================
       SAVE OTP
    ========================= */

    await OTP.findOneAndDelete({ userId: user._id, purpose: "verify" });

    await OTP.create({
  userId: user._id,
  otpHash,
  expiresAt,
  lastSentAt: new Date(),
  purpose: "verify"
});


    /* =========================
       SEND EMAIL
    ========================= */

    await sendOTPEmail(email, otp);

    res.status(200).json({
      message: "OTP sent",
      userId: user._id
    });

  } catch (err) {
    console.error(err);

    // 🔥 Handle duplicate email (DB-level protection)
    if (err.code === 11000) {
      return res.status(400).json({
        message: "Email already registered"
      });
    }

    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   VERIFY OTP (WITH JWT)
========================= */
router.post("/verify-otp", async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.status(400).json({ message: "Missing parameters" });
  }

  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ message: "OTP must be 6 digits" });
  }

  try {
    const otpRecord = await OTP.findOne({ userId, purpose: "verify" });
    if (!otpRecord) {
      return res.status(400).json({ message: "OTP not found or expired" });
    }

    const now = new Date();

    if (otpRecord.expiresAt < now) {
      await OTP.deleteOne({ userId });
      return res.status(400).json({ message: "OTP expired" });
    }

    if (otpRecord.attempts >= 5) {
      return res.status(429).json({
        message: "Too many invalid attempts. Request a new OTP."
      });
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otpHash);

    if (!isMatch) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: "Invalid OTP" });
    }

    /* =========================
       SUCCESS: VERIFY USER
    ========================= */
    const user = await User.findByIdAndUpdate(
      userId,
      { isVerified: true, registrationStep: "verified" },
      { new: true }
    );

    await OTP.deleteOne({ userId });

    /* =========================
       GENERATE JWT
    ========================= */
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      message: "Verified successfully",
      token,
      user: {
        email: user.email,
        phone: user.phone
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   RESEND OTP (SECURE WITH RATE LIMIT)
========================= */
router.post("/resend-otp", async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ message: "Missing userId" });

  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    let otpRecord = await OTP.findOne({ userId });

    const now = new Date();

    // Check for existing OTP and cooldown (60s)
    if (otpRecord && otpRecord.lastSentAt && (now - otpRecord.lastSentAt < 60 * 1000)) {
      return res.status(429).json({
        message: "Please wait before requesting another OTP"
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    // Delete old OTP if exists
    if (otpRecord) await OTP.deleteOne({ userId });

    // Save new OTP with lastSentAt
    await OTP.create({
      userId,
      otpHash,
      expiresAt,
      lastSentAt: now,
      attempts: 0
    });

    // Send OTP via email
    await sendOTPEmail(user.email, otp);

    res.status(200).json({ message: "OTP resent successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   LOGIN ROUTE
========================= */
router.post("/login", async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  try {
    // ===== Rate Limiting =====
    const key = identifier.toLowerCase();
    const now = Date.now();
    const limitWindow = 60 * 1000; // 1 minute
    const maxAttempts = 2;

    const rate = rateLimitMap.get(key) || { count: 0, firstRequestTime: now };

    if (now - rate.firstRequestTime > limitWindow) {
      rate.count = 0;
      rate.firstRequestTime = now;
    }

    rate.count += 1;
    rateLimitMap.set(key, rate);

    if (rate.count > maxAttempts) {
      return res.status(429).json({
        message: "Too many attempts. Try again later."
      });
    }

    // ===== Find User (Email OR Username) =====
    let user;

    if (identifier.includes("@")) {
      user = await User.findOne({ email: identifier.toLowerCase() });
    } else {
      user = await User.findOne({ username: identifier });
    }

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // ===== Check Password =====
    const isMatch = await bcrypt.compare(password, user.passwordHash);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // ===== Check Verification =====
    if (!user.isVerified) {
      return res.status(403).json({
        message: "Please verify your account first"
      });
    }

    // ===== Generate JWT =====
    const token = jwt.sign(
      {
        userId: user._id,
        tokenVersion: user.tokenVersion
      },
      process.env.JWT_SECRET,
      { expiresIn: "3d" }
    );

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        email: user.email,
        username: user.username
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   FORGOT PASSWORD
========================= */
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  if (!email || !validator.isEmail(email)) {
    return res.status(400).json({ message: "Invalid email" });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });

    // ===== Rate limit OTP requests =====
    const existingOTP = await OTP.findOne({ userId: user._id, purpose: "reset_password" });
    const now = new Date();
    if (existingOTP && existingOTP.lastSentAt && (now - existingOTP.lastSentAt < 60 * 1000)) {
      return res.status(429).json({ message: "Wait before requesting another OTP" });
    }

    // ===== Generate OTP =====
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(now.getTime() + 5 * 60 * 1000); // 5 mins

    if (existingOTP) await OTP.deleteOne({ userId: user._id, purpose: "reset_password" });

    await OTP.create({
      userId: user._id,
      otpHash,
      expiresAt,
      lastSentAt: now,
      attempts: 0,
      purpose: "reset_password"
    });

    // Send OTP email
    await sendOTPEmail(user.email, otp);

    res.status(200).json({ message: "OTP sent to your email" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   VERIFY RESET OTP
========================= */
router.post("/verify-reset-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !validator.isEmail(email)) {
    return res.status(400).json({ message: "Invalid email" });
  }
  if (!otp || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ message: "OTP must be 6 digits" });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ message: "User not found" });

    const otpRecord = await OTP.findOne({ userId: user._id, purpose: "reset_password" });
    if (!otpRecord) return res.status(400).json({ message: "OTP not found or expired" });

    if (otpRecord.expiresAt < new Date()) {
      await OTP.deleteOne({ userId: user._id, purpose: "reset_password" });
      return res.status(400).json({ message: "OTP expired" });
    }

    if (otpRecord.attempts >= 5) {
      return res.status(429).json({ message: "Too many invalid attempts. Request a new OTP." });
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isMatch) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // OTP valid → allow password reset
    await OTP.deleteOne({ userId: user._id, purpose: "reset_password" });
    res.status(200).json({ message: "OTP verified successfully" });

  } catch (err) {
    console.error(err);
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

    // Hash and save password
    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;

    // Invalidate old JWTs
    user.tokenVersion += 1;

    await user.save();

    res.status(200).json({ message: "Password updated successfully" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;

