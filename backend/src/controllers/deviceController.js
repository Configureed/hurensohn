import Device from '../models/Device.js';
import { Encryption } from '../utils/encryption.js';
import logger from '../utils/logger.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const getDevices = async (req, res) => {
  try {
    const devices = await Device.find({ userId: req.user._id });
    res.status(200).json({
      success: true,
      devices
    });
  } catch (error) {
    logger.error('Get devices error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get devices'
    });
  }
};

export const registerDevice = async (req, res) => {
  try {
    const { name, deviceType, hostname } = req.body;

    const sessionKey = Encryption.generateSessionKey();
    const encryptedSessionKey = sessionKey.toString('base64');

    const device = new Device({
      userId: req.user._id,
      name,
      deviceType,
      hostname,
      sessionKey: encryptedSessionKey,
      status: 'offline'
    });

    await device.save();

    req.user.devices.push(device._id);
    await req.user.save();

    res.status(201).json({
      success: true,
      device: {
        deviceId: device.deviceId,
        name: device.name,
        status: device.status,
        sessionKey: encryptedSessionKey
      }
    });
  } catch (error) {
    logger.error('Register device error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to register device'
    });
  }
};

export const getDevice = async (req, res) => {
  try {
    const device = await Device.findOne({
      deviceId: req.params.id,
      userId: req.user._id
    });

    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    res.status(200).json({
      success: true,
      device
    });
  } catch (error) {
    logger.error('Get device error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get device'
    });
  }
};

export const updateDevice = async (req, res) => {
  try {
    const device = await Device.findOne({
      deviceId: req.params.id,
      userId: req.user._id
    });

    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    const { name, status } = req.body;
    if (name) device.name = name;
    if (status) device.status = status;
    device.lastSeen = new Date();

    await device.save();

    res.status(200).json({
      success: true,
      device
    });
  } catch (error) {
    logger.error('Update device error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update device'
    });
  }
};

export const deleteDevice = async (req, res) => {
  try {
    const device = await Device.findOne({
      deviceId: req.params.id,
      userId: req.user._id
    });

    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    await device.deleteOne();

    req.user.devices = req.user.devices.filter(id => id.toString() !== device._id.toString());
    await req.user.save();

    res.status(200).json({
      success: true,
      message: 'Device deleted successfully'
    });
  } catch (error) {
    logger.error('Delete device error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete device'
    });
  }
};

export const sendCommand = async (req, res) => {
  try {
    const device = await Device.findOne({
      deviceId: req.params.id,
      userId: req.user._id
    });

    if (!device) {
      return res.status(404).json({
        success: false,
        message: 'Device not found'
      });
    }

    const { command, params } = req.body;

    if (!command) {
      return res.status(400).json({
        success: false,
        message: 'Command is required'
      });
    }

    const io = req.app.get('io');
    const commandData = {
      command,
      params: params || {},
      deviceId: device.deviceId,
      timestamp: new Date().toISOString()
    };

    io.to(`device_${device.deviceId}`).emit('command', commandData);

    res.status(200).json({
      success: true,
      message: 'Command sent successfully',
      command: commandData
    });
  } catch (error) {
    logger.error('Send command error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send command'
    });
  }
};

export const buildClient = async (req, res) => {
  try {
    const { name } = req.body;
    const user = req.user;

    const templatePath = path.join(__dirname, '../../../python-template/lock_client_template.py');
    let template = fs.readFileSync(templatePath, 'utf8');

    // Replace placeholders
    const serverUrl = process.env.SERVER_URL || `http://${req.get('host')}`;
    
    template = template
      .replace('{{API_KEY}}', user.apiKey)
      .replace('{{ACCOUNT_ID}}', user.accountId)
      .replace('{{DEVICE_NAME}}', name || 'OathNet-Device')
      .replace('{{SERVER_URL}}', serverUrl);

    res.setHeader('Content-Type', 'text/x-python');
    res.setHeader('Content-Disposition', `attachment; filename=${name || 'client'}.py`);
    res.send(template);
  } catch (error) {
    logger.error('Build client error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to build client'
    });
  }
};