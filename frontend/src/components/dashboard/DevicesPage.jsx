import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Plus, RefreshCw, Monitor, Search } from 'lucide-react';
import toast from 'react-hot-toast';
import DeviceCard from './DeviceCard';
import LiveViewModal from './LiveViewModal';
import { useDevices } from '../../hooks/useDevices';
import api from '../../utils/api';

const DevicesPage = () => {
  const { devices, loading, fetchDevices } = useDevices();
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newDeviceName, setNewDeviceName] = useState('');
  const [creating, setCreating] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchDevices();
  }, []);

  const handleCreateDevice = async () => {
    if (!newDeviceName.trim()) {
      toast.error('Device name is required');
      return;
    }

    setCreating(true);
    try {
      await api.post('/v1/devices', { name: newDeviceName });
      toast.success('Device registered successfully!');
      setNewDeviceName('');
      setShowCreateModal(false);
      fetchDevices();
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to register device');
    } finally {
      setCreating(false);
    }
  };

  const filteredDevices = devices.filter(d => 
    d.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    d.deviceId.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
        <div>
          <h1 className="text-4xl font-bold text-white mb-2 tracking-tight">Active Devices</h1>
          <p className="text-white/40">Manage and monitor your OathNet infrastructure.</p>
        </div>
        
        <div className="flex items-center gap-3">
          <div className="relative group">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20 group-focus-within:text-purple-400 transition-colors" />
            <input 
              type="text"
              placeholder="Filter devices..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-white/5 border border-white/10 rounded-xl pl-11 pr-4 py-2.5 text-sm text-white placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/10 transition-all w-64"
            />
          </div>
          <button
            onClick={fetchDevices}
            className="p-2.5 glass rounded-xl text-white/40 hover:text-white transition-all"
          >
            <RefreshCw size={20} className={loading ? 'animate-spin' : ''} />
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-6 py-2.5 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-bold transition-all shadow-lg shadow-purple-900/20 flex items-center gap-2"
          >
            <Plus size={18} />
            Deploy Device
          </button>
        </div>
      </div>

      {loading && devices.length === 0 ? (
        <div className="flex items-center justify-center h-64">
          <div className="w-12 h-12 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin"></div>
        </div>
      ) : filteredDevices.length === 0 ? (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass rounded-[32px] p-20 text-center border-dashed border-2 border-white/5"
        >
          <div className="w-20 h-20 bg-white/5 rounded-3xl flex items-center justify-center mx-auto mb-6 border border-white/10">
            <Monitor size={40} className="text-white/20" />
          </div>
          <h3 className="text-2xl font-bold text-white mb-2">No Devices Found</h3>
          <p className="text-white/40 mb-8 max-w-xs mx-auto">No devices are currently connected or match your search criteria.</p>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-8 py-3 bg-white/5 hover:bg-white/10 text-white rounded-xl font-bold transition-all border border-white/10"
          >
            Deploy First Device
          </button>
        </motion.div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
          {filteredDevices.map((device) => (
            <DeviceCard
              key={device.deviceId}
              device={device}
              onClick={() => setSelectedDevice(device)}
            />
          ))}
        </div>
      )}

      {selectedDevice && (
        <LiveViewModal
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
        />
      )}

      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-[100] p-4">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="glass rounded-[32px] p-8 w-full max-w-md relative"
          >
            <div className="text-center mb-8">
              <h2 className="text-2xl font-bold text-white tracking-tight">Deploy New Device</h2>
              <p className="text-white/40 text-sm mt-1">Register a new device to your account.</p>
            </div>
            
            <div className="space-y-6">
              <div>
                <label className="block text-xs font-semibold text-white/40 uppercase tracking-widest mb-2 ml-1">
                  Device Identifier
                </label>
                <input
                  type="text"
                  value={newDeviceName}
                  onChange={(e) => setNewDeviceName(e.target.value)}
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/10 transition-all"
                  placeholder="e.g. Server-Main-01"
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => setShowCreateModal(false)}
                  className="flex-1 py-3 bg-white/5 hover:bg-white/10 text-white/60 rounded-xl font-bold transition-all"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateDevice}
                  disabled={creating}
                  className="flex-1 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-bold transition-all shadow-lg shadow-purple-900/20 disabled:opacity-50"
                >
                  {creating ? 'Deploying...' : 'Deploy Now'}
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default DevicesPage;