import User from '../models/User.js';
import { generateToken } from '../utils/jwt.js';
import { generateTwoFactorSecret, generateQRCode, verifyTwoFactorToken, generateBackupCodes } from '../utils/twoFactor.js';
import logger from '../utils/logger.js';

export const register = async (req, res) => {
  try {
    const { username, password, email } = req.body;

    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Username or email already exists'
      });
    }

    const user = new User({
      username,
      password,
      email,
      role: username.toLowerCase() === 'voip' ? 'owner' : 'user'
    });

    await user.save();

    const token = generateToken(user._id, user.accountId);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        accountId: user.accountId,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('Register error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed'
    });
  }
};

export const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    user.lastLogin = new Date();
    await user.save();

    const token = generateToken(user._id, user.accountId);

    res.status(200).json({
      success: true,
      token,
      requiresTwoFactor: user.twoFactor.enabled,
      user: {
        id: user._id,
        username: user.username,
        accountId: user.accountId,
        email: user.email,
        role: user.role,
        twoFactorEnabled: user.twoFactor.enabled
      }
    });
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed'
    });
  }
};

export const verifyTwoFactor = async (req, res) => {
  try {
    const { username, token } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    if (!user.twoFactor.enabled) {
      return res.status(400).json({
        success: false,
        message: '2FA not enabled for this user'
      });
    }

    const isValid = verifyTwoFactorToken(user.twoFactor.secret, token);
    if (!isValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid 2FA code'
      });
    }

    const jwtToken = generateToken(user._id, user.accountId);

    res.status(200).json({
      success: true,
      token: jwtToken,
      user: {
        id: user._id,
        username: user.username,
        accountId: user.accountId,
        email: user.email
      }
    });
  } catch (error) {
    logger.error('2FA verification error:', error);
    res.status(500).json({
      success: false,
      message: '2FA verification failed'
    });
  }
};

export const logout = async (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
};

export const getMe = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user
    });
  } catch (error) {
    logger.error('Get me error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user info'
    });
  }
};