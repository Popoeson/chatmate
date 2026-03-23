import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true,trim: true },
  phone: { type: String, required: true },
  passwordHash: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  registrationStep: { type: String, default: "form_submitted" } // form_submitted | otp_pending | verified
}, { timestamps: true });

export default mongoose.model("User", userSchema);