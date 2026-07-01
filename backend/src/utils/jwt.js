import jwt from 'jsonwebtoken';

export const generateToken = (userId, accountId) => {
  return jwt.sign(
    { userId, accountId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRE }
  );
};

export const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
};