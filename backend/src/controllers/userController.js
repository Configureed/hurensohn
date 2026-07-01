import User from '../models/User.js';
import { generateTwoFactorSecret, generateQRCode, verifyTwoFactorToken, generateBackupCodes } from '../utils/twoFactor.js';
import { Encryption } from '../utils/encryption.js';
import logger from '../utils/logger.js';
import bcrypt from 'bcryptjs';

export const getUserInfo = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    logger.error('Get user info error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user info'
    });
  }
};

export const regenerateApiKey = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    user.apiKey = crypto.randomBytes(32).toString('hex');
    await user.save();

    res.status(200).json({
      success: true,
      apiKey: user.apiKey
    });
  } catch (error) {
    logger.error('Regenerate API key error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to regenerate API key'
    });
  }
};

export const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const isPasswordValid = await user.comparePassword(currentPassword);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    user.password = newPassword;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    logger.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
};

export const enableTwoFactor = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.twoFactor.enabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is already enabled'
      });
    }

    const { secret, otpauthUrl } = generateTwoFactorSecret();
    const qrCode = await generateQRCode(otpauthUrl);
    const backupCodes = generateBackupCodes(10);

    user.twoFactor.secret = secret;
    user.twoFactor.backupCodes = backupCodes.map(code => 
      bcrypt.hashSync(code, 10)
    );
    await user.save();

    res.status(200).json({
      success: true,
      secret,
      qrCode,
      backupCodes
    });
  } catch (error) {
    logger.error('Enable 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to enable 2FA'
    });
  }
};

export const verifyTwoFactor = async (req, res) => {
  try {
    const { token } = req.body;

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (!user.twoFactor.secret) {
      return res.status(400).json({
        success: false,
        message: '2FA not set up'
      });
    }

    const isValid = verifyTwoFactorToken(user.twoFactor.secret, token);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid 2FA code'
      });
    }

    user.twoFactor.enabled = true;
    await user.save();

    res.status(200).json({
      success: true,
      message: '2FA enabled successfully'
    });
  } catch (error) {
    logger.error('Verify 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to verify 2FA'
    });
  }
};

export const disableTwoFactor = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    user.twoFactor = { enabled: false, secret: null, backupCodes: [] };
    await user.save();

    res.status(200).json({
      success: true,
      message: '2FA disabled successfully'
    });
  } catch (error) {
    logger.error('Disable 2FA error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to disable 2FA'
    });
  }
};

export const getBackupCodes = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    if (!user.twoFactor.enabled) {
      return res.status(400).json({
        success: false,
        message: '2FA is not enabled'
      });
    }

    const newBackupCodes = generateBackupCodes(10);
    user.twoFactor.backupCodes = newBackupCodes.map(code => 
      bcrypt.hashSync(code, 10)
    );
    await user.save();

    res.status(200).json({
      success: true,
      backupCodes: newBackupCodes
    });
  } catch (error) {
    logger.error('Get backup codes error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get backup codes'
    });
  }
};