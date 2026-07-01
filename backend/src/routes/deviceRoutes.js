import express from 'express';
import { protect } from '../middleware/auth.js';
import { apiKeyAuth } from '../middleware/apiKeyAuth.js';
import {
  getDevices,
  registerDevice,
  getDevice,
  updateDevice,
  deleteDevice,
  sendCommand,
  buildClient
} from '../controllers/deviceController.js';

const router = express.Router();

router.get('/devices', protect, getDevices);
router.post('/devices', protect, registerDevice);
router.post('/devices/build', protect, buildClient);
router.get('/devices/:id', protect, getDevice);
router.put('/devices/:id', protect, updateDevice);
router.delete('/devices/:id', protect, deleteDevice);
router.post('/devices/:id/command', protect, sendCommand);

export default router;