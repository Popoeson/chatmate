import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
  sender:    { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiver:  { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text:      { type: String, required: true },
  delivered: { type: Boolean, default: false },
  read:      { type: Boolean, default: false },
  replyTo: {
    messageId: { type: mongoose.Schema.Types.ObjectId, ref: "Message", default: null },
    text:      { type: String, default: null },
    sender:    { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null }
  }
}, { timestamps: true });

export default mongoose.model("Message", messageSchema);