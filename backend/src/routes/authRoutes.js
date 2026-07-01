import express from 'express';
import { register, login, verifyTwoFactor, logout, getMe } from '../controllers/authController.js';
import { protect } from '../middleware/auth.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/verify-2fa', verifyTwoFactor);
router.post('/logout', logout);
router.get('/me', protect, getMe);

export default router;