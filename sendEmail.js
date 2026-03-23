import { Resend } from "resend";
import dotenv from "dotenv";
dotenv.config();

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendOTPEmail(to, otp) {
  try {
    await resend.emails.send({
      from: process.env.FROM_EMAIL,
      to,
      subject: "ChatMate OTP Verification",
      html: `<p>Your OTP for ChatMate registration is: <b>${otp}</b></p>
             <p>It expires in 5 minutes.</p>`
    });
    console.log("OTP sent to:", to);
  } catch (err) {
    console.error("Failed to send OTP email:", err);
    throw err;
  }
}