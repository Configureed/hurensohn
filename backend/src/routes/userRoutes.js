import express from 'express';
import { protect } from '../middleware/auth.js';
import {
  getUserInfo,
  regenerateApiKey,
  changePassword,
  enableTwoFactor,
  verifyTwoFactor,
  disableTwoFactor,
  getBackupCodes
} from '../controllers/userController.js';

const router = express.Router();

router.get('/info', protect, getUserInfo);
router.post('/regenerate-key', protect, regenerateApiKey);
router.put('/change-password', protect, changePassword);
router.post('/enable-2fa', protect, enableTwoFactor);
router.post('/verify-2fa', protect, verifyTwoFactor);
router.post('/disable-2fa', protect, disableTwoFactor);
router.get('/backup-codes', protect, getBackupCodes);

export default router;