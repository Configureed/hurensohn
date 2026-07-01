import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Download, Terminal, Shield, Cpu, Zap } from 'lucide-react';
import toast from 'react-hot-toast';
import { useAuth } from '../../context/AuthContext';
import api from '../../utils/api';

const GeneratorPage = () => {
  const { user } = useAuth();
  const [deviceName, setDeviceName] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);

  const generateAndDownload = async () => {
    if (!deviceName) {
      toast.error('Please enter a device name');
      return;
    }

    setIsGenerating(true);
    try {
      const response = await api.post('/v1/devices/build', {
        name: deviceName
      }, { responseType: 'blob' });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${deviceName.toLowerCase().replace(/\s+/g, '_')}_client.py`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      toast.success('Client generated successfully!');
    } catch (error) {
      toast.error('Failed to generate client');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="p-8 max-w-5xl mx-auto">
      <header className="mb-12">
        <h1 className="text-4xl font-bold text-white mb-2 tracking-tight">Client Generator</h1>
        <p className="text-white/40">Create a new OathNet client for your remote devices.</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <motion.div 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="glass rounded-3xl p-8"
        >
          <div className="flex items-center gap-3 mb-8">
            <div className="w-10 h-10 bg-purple-600/20 rounded-xl flex items-center justify-center border border-purple-500/20">
              <Terminal className="w-5 h-5 text-purple-400" />
            </div>
            <h2 className="text-xl font-bold text-white">Configure Client</h2>
          </div>

          <div className="space-y-6">
            <div>
              <label className="block text-xs font-semibold text-white/40 uppercase tracking-widest mb-2 ml-1">
                Device Name
              </label>
              <input
                type="text"
                value={deviceName}
                onChange={(e) => setDeviceName(e.target.value)}
                placeholder="Workstation-01"
                className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/10 transition-all"
              />
            </div>

            <div className="pt-4">
              <button
                onClick={generateAndDownload}
                disabled={isGenerating}
                className="w-full py-4 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-bold transition-all shadow-lg shadow-purple-900/20 flex items-center justify-center gap-3 disabled:opacity-50"
              >
                {isGenerating ? (
                  <>Building...</>
                ) : (
                  <>
                    <Download className="w-5 h-5" />
                    Build & Download
                  </>
                )}
              </button>
            </div>
          </div>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >
          <div className="glass rounded-3xl p-6 border-l-4 border-purple-500">
            <div className="flex items-start gap-4">
              <div className="p-2 bg-purple-500/10 rounded-lg">
                <Shield className="w-5 h-5 text-purple-400" />
              </div>
              <div>
                <h3 className="text-white font-bold mb-1">Encrypted Communication</h3>
                <p className="text-white/40 text-sm">All commands are AES-256-GCM encrypted between the server and your device.</p>
              </div>
            </div>
          </div>

          <div className="glass rounded-3xl p-6 border-l-4 border-blue-500">
            <div className="flex items-start gap-4">
              <div className="p-2 bg-blue-500/10 rounded-lg">
                <Cpu className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <h3 className="text-white font-bold mb-1">Low Resource Usage</h3>
                <p className="text-white/40 text-sm">The client is optimized for Windows systems with minimal CPU and RAM footprint.</p>
              </div>
            </div>
          </div>

          <div className="glass rounded-3xl p-6 border-l-4 border-amber-500">
            <div className="flex items-start gap-4">
              <div className="p-2 bg-amber-500/10 rounded-lg">
                <Zap className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="text-white font-bold mb-1">Instant Control</h3>
                <p className="text-white/40 text-sm">Lock, unlock, and manage your device in real-time via the OathNet dashboard.</p>
              </div>
            </div>
          </div>
        </motion.div>
      </div>

      <div className="mt-12 glass rounded-3xl p-8">
        <h3 className="text-lg font-bold text-white mb-4">How to install</h3>
        <div className="space-y-4 text-sm text-white/60">
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center text-xs font-bold text-white">1</div>
            <p>Download the generated Python script.</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center text-xs font-bold text-white">2</div>
            <p>Install requirements: <code className="bg-black/40 px-2 py-0.5 rounded text-purple-400">pip install socketio requests pycryptodome keyboard pillow pyautogui</code></p>
          </div>
          <div className="flex items-center gap-3">
            <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center text-xs font-bold text-white">3</div>
            <p>Run the script as Administrator to allow key blocking.</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GeneratorPage;