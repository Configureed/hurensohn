import React from 'react';
import { motion } from 'framer-motion';
import { Monitor, Activity, Shield, Lock, Unlock } from 'lucide-react';

const DeviceCard = ({ device, onClick }) => {
  const isOnline = device.status === 'online';

  return (
    <motion.div
      whileHover={{ y: -5 }}
      onClick={onClick}
      className="glass rounded-[32px] p-6 cursor-pointer border border-white/5 hover:border-purple-500/30 transition-all relative overflow-hidden group"
    >
      {/* Status Glow */}
      <div className={`absolute top-0 right-0 w-32 h-32 blur-[50px] rounded-full -mr-16 -mt-16 transition-colors ${isOnline ? 'bg-green-500/10' : 'bg-red-500/10'}`} />

      <div className="flex items-start justify-between mb-6 relative z-10">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-2xl bg-white/5 flex items-center justify-center border border-white/10 group-hover:border-purple-500/50 transition-colors">
            <Monitor size={24} className="text-white/80" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white tracking-tight">{device.name}</h3>
            <p className="text-[10px] text-white/30 uppercase tracking-widest font-bold">ID: {device.deviceId.substring(0, 12)}</p>
          </div>
        </div>
        <div className={`px-3 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 ${isOnline ? 'bg-green-500/10 text-green-400 border border-green-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
          <div className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-green-400 animate-pulse' : 'bg-red-400'}`} />
          {isOnline ? 'Online' : 'Offline'}
        </div>
      </div>

      <div className="space-y-3 relative z-10">
        <div className="flex items-center justify-between p-3 bg-white/5 rounded-2xl border border-white/5">
          <span className="text-xs font-bold text-white/30 uppercase tracking-tighter">Platform</span>
          <span className="text-xs font-bold text-white/80">{device.deviceType || 'Unknown'}</span>
        </div>
        <div className="flex items-center justify-between p-3 bg-white/5 rounded-2xl border border-white/5">
          <span className="text-xs font-bold text-white/30 uppercase tracking-tighter">Last Contact</span>
          <span className="text-xs font-bold text-white/80">
            {device.lastSeen ? new Date(device.lastSeen).toLocaleTimeString() : 'Never'}
          </span>
        </div>
      </div>

      <div className="mt-6 pt-6 border-t border-white/5 flex items-center justify-between relative z-10">
        <div className="flex items-center gap-2">
          <Activity size={14} className={isOnline ? 'text-purple-400' : 'text-white/10'} />
          <span className="text-[10px] font-bold text-white/20 uppercase tracking-widest">Live Control</span>
        </div>
        <div className="flex gap-2">
          <div className="p-1.5 bg-white/5 rounded-lg border border-white/10">
            <Shield size={14} className="text-white/40" />
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default DeviceCard;