import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import authRoutes from "./routes/auth.js";

dotenv.config();
const app = express();

/* =========================
   MIDDLEWARE
========================= */
app.use(cors());

// For JSON bodies
app.use(express.json());

// For parsing urlencoded form data (needed for multer multipart/form-data)
app.use(express.urlencoded({ extended: true }));

/* =========================
   ROUTES
========================= */
app.use("/api/auth", authRoutes);

/* =========================
   MONGODB CONNECTION
========================= */
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("MongoDB connected");
    app.listen(process.env.PORT, () =>
      console.log(`Server running on port ${process.env.PORT}`)
    );
  })
  .catch(err => console.error("MongoDB connection error:", err));