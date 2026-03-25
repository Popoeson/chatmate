import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  passwordHash: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  registrationStep: { type: String, default: "otp_pending" },

  // New fields
  username: { type: String, unique: true, sparse: true },
  avatarUrl: { type: String, default: "" },
  bio: { type: String, default: "" },
  lastSeen: { type: Date, default: Date.now },
  onlineStatus: { type: Boolean, default: false },
  links: { type: [String], default: [] },
  tokenVersion: { type: Number, default: 1 }
});

export default mongoose.model("User", userSchema);