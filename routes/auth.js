import express from "express";
import User from "../models/User.js";
import OTP from "../models/OTP.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { sendOTPEmail } from "../utils/sendEmail.js"
import validator from "validator";

const router = express.Router();

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

    await OTP.findOneAndDelete({ userId: user._id });

    await OTP.create({
      userId: user._id,
      otpHash,
      expiresAt,
      lastSentAt: new Date()
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
   VERIFY OTP (WITH RATE LIMIT & ATTEMPT LIMIT)
========================= */
router.post("/verify-otp", async (req, res) => {
  const { userId, otp } = req.body;

  if (!userId || !otp) {
    return res.status(400).json({ message: "Missing parameters" });
  }

  // Validate OTP format (6 digits)
  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({ message: "OTP must be 6 digits" });
  }

  try {
    const otpRecord = await OTP.findOne({ userId });
    if (!otpRecord) return res.status(400).json({ message: "OTP not found or expired" });

    const now = new Date();

    // Check if OTP expired
    if (otpRecord.expiresAt < now) {
      await OTP.deleteOne({ userId });
      return res.status(400).json({ message: "OTP expired" });
    }

    // Check attempt limit (max 5)
    if (otpRecord.attempts >= 5) {
      return res.status(429).json({ message: "Too many invalid attempts. Request a new OTP." });
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otpHash);

    if (!isMatch) {
      otpRecord.attempts += 1;
      otpRecord.lastFailedAt = now; // optional: track last failed attempt
      await otpRecord.save();

      return res.status(400).json({ message: "Invalid OTP" });
    }

    // OTP correct — verify user
    await User.findByIdAndUpdate(userId, { isVerified: true, registrationStep: "verified" });
    await OTP.deleteOne({ userId });

    res.status(200).json({ message: "Verified successfully" });

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

export default router;