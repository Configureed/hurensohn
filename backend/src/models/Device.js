import mongoose from 'mongoose';
import { v4 as uuidv4 } from 'uuid';

const DeviceSchema = new mongoose.Schema({
  deviceId: {
    type: String,
    required: true,
    unique: true,
    default: () => `dev_${uuidv4().replace(/-/g, '').substring(0, 12)}`
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true
  },
  deviceType: {
    type: String,
    enum: ['Windows', 'Linux', 'Mac', 'Raspberry Pi', 'Other'],
    default: 'Other'
  },
  hostname: {
    type: String
  },
  status: {
    type: String,
    enum: ['online', 'offline', 'idle'],
    default: 'offline'
  },
  lastSeen: {
    type: Date,
    default: Date.now
  },
  ipAddress: {
    type: String
  },
  sessionKey: {
    type: String
  },
  metadata: {
    type: Map,
    of: String
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

DeviceSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

const Device = mongoose.model('Device', DeviceSchema);
export default Device;