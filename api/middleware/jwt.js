import jwt from "jsonwebtoken";
import createError from "../utils/createError.js";
export const verifyToken = async (req, res, next) => {
  const token = req.cookies.accessToken;
  if (!token) {
    return next(createError(403, "Y ar not authorized"));
  }
  jwt.verify(token, process.env.JWT_KEY, (err, payload) => {
    if (err) return next(createError(403, "Token invalid"));
    req.userId = payload.id;
    req.isSeller = payload.isSeller;
    next()
  });
};
