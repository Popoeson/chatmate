import jwt from "jsonwebtoken";
import User from "../models/User.js";

export default async function authenticateJWT(req, res, next){
  const authHeader = req.headers.authorization;

  if(!authHeader || !authHeader.startsWith("Bearer ")){
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try{
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ✅ SUPPORT BOTH OLD & NEW TOKENS
    const userId = decoded.userId || decoded.id;

    if(!userId){
      return res.status(401).json({ message: "Invalid token payload" });
    }

    const user = await User.findById(userId);
    if(!user){
      return res.status(401).json({ message: "User not found" });
    }

    // ✅ ONLY CHECK tokenVersion IF IT EXISTS
    if(decoded.tokenVersion !== undefined){
      if(decoded.tokenVersion !== user.tokenVersion){
        return res.status(401).json({ message: "Session expired" });
      }
    }

    req.userId = user._id;
    next();

  }catch(err){
    console.error("JWT ERROR:", err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}