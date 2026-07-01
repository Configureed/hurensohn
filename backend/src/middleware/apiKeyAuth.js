import User from '../models/User.js';
import logger from '../utils/logger.js';

export const apiKeyAuth = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: 'API key required'
      });
    }

    const user = await User.findOne({ apiKey });
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error('API key auth error:', error);
    res.status(500).json({
      success: false,
      message: 'Authentication failed'
    });
  }
};