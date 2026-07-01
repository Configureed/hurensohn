import { Server } from 'socket.io';
import Device from '../models/Device.js';
import { Encryption } from '../utils/encryption.js';
import logger from '../utils/logger.js';

let io;

export const initializeSocket = (server) => {
  io = new Server(server, {
    cors: {
      origin: process.env.CLIENT_URL || 'http://localhost:3000',
      methods: ['GET', 'POST']
    }
  });

  io.on('connection', (socket) => {
    logger.info(`Socket connected: ${socket.id}`);

    socket.on('device:auth', async (data) => {
      try {
        const device = await Device.findOne({ deviceId: data.deviceId });
        if (!device) {
          socket.emit('device:error', { message: 'Device not found' });
          return;
        }

        socket.join(`device_${device.deviceId}`);
        device.status = 'online';
        device.lastSeen = new Date();
        await device.save();

        io.emit('device:connected', {
          deviceId: device.deviceId,
          name: device.name,
          status: 'online'
        });

        logger.info(`Device ${device.deviceId} authenticated`);
      } catch (error) {
        logger.error('Device auth error:', error);
        socket.emit('device:error', { message: 'Authentication failed' });
      }
    });

    socket.on('device:frame', async (data) => {
      try {
        const device = await Device.findOne({ deviceId: data.deviceId });
        if (!device) return;

        const sessionKey = Buffer.from(device.sessionKey, 'base64');
        const decryptedData = Encryption.decrypt(data, sessionKey);

        io.emit('device:frame', {
          deviceId: device.deviceId,
          frame: decryptedData.frame,
          timestamp: decryptedData.timestamp
        });
      } catch (error) {
        logger.error('Frame processing error:', error);
      }
    });

    socket.on('device:metrics', async (data) => {
      try {
        const device = await Device.findOne({ deviceId: data.deviceId });
        if (!device) return;

        const sessionKey = Buffer.from(device.sessionKey, 'base64');
        const decryptedData = Encryption.decrypt(data, sessionKey);

        io.emit('device:metrics', {
          deviceId: device.deviceId,
          metrics: decryptedData.metrics,
          timestamp: decryptedData.timestamp
        });
      } catch (error) {
        logger.error('Metrics processing error:', error);
      }
    });

    socket.on('disconnect', async () => {
      try {
        const device = await Device.findOne({ status: 'online' });
        if (device) {
          device.status = 'offline';
          device.lastSeen = new Date();
          await device.save();

          io.emit('device:disconnected', {
            deviceId: device.deviceId,
            name: device.name,
            status: 'offline'
          });
        }
        logger.info(`Socket disconnected: ${socket.id}`);
      } catch (error) {
        logger.error('Disconnect error:', error);
      }
    });
  });

  return io;
};

export const getIO = () => io;