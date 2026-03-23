import express from "express";
import User from "../models/User.js";
import OTP from "../models/OTP.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { sendOTPEmail } from "../utils/sendEmail.js";

const router = express.Router();

/* =========================
   REGISTER ROUTE
========================= */
router.post("/register", async (req, res) => {
  const { email, phone, password } = req.body;

  if (!email || !phone || !password) return res.status(400).json({ message: "All fields required" });

  try {
    let user = await User.findOne({ email });

    if(user){
      if(user.isVerified){
        return res.status(400).json({ message: "User already exists" });
      }
      // User exists but unverified — continue to resend OTP
    } else {
      const passwordHash = await bcrypt.hash(password, 10);
      user = await User.create({ email, phone, passwordHash, registrationStep: "otp_pending" });
    }

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 mins

    // Save OTP
    await OTP.findOneAndDelete({ userId: user._id }); // remove old OTP if exists
    await OTP.create({ userId: user._id, otpHash, expiresAt });

    // Send OTP
    await sendOTPEmail(email, otp);

    res.status(200).json({ message: "OTP sent", userId: user._id });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   VERIFY OTP
========================= */
router.post("/verify-otp", async (req, res) => {
  const { userId, otp } = req.body;

  if(!userId || !otp) return res.status(400).json({ message: "Missing parameters" });

  try {
    const otpRecord = await OTP.findOne({ userId });
    if(!otpRecord) return res.status(400).json({ message: "OTP not found or expired" });

    if(otpRecord.expiresAt < new Date()) {
      await OTP.deleteOne({ userId });
      return res.status(400).json({ message: "OTP expired" });
    }

    const isMatch = await bcrypt.compare(otp, otpRecord.otpHash);
    if(!isMatch){
      otpRecord.attempts += 1;
      await otpRecord.save();
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // OTP correct — verify user
    await User.findByIdAndUpdate(userId, { isVerified: true, registrationStep: "verified" });
    await OTP.deleteOne({ userId });

    res.status(200).json({ message: "Verified successfully" });

  } catch(err){
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   RESEND OTP
========================= */
router.post("/resend-otp", async (req,res)=>{
  const { userId } = req.body;
  if(!userId) return res.status(400).json({ message: "Missing userId" });

  try{
    const user = await User.findById(userId);
    if(!user) return res.status(404).json({ message: "User not found" });

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 5*60*1000);

    await OTP.findOneAndDelete({ userId });
    await OTP.create({ userId, otpHash, expiresAt });

    await sendOTPEmail(user.email, otp);
    res.status(200).json({ message: "OTP resent" });

  }catch(err){
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;