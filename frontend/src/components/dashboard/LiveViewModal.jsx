import React, { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { X, Play, Square, Mic, Camera, RotateCcw, Terminal, Lock, Unlock, ShieldAlert } from 'lucide-react';
import toast from 'react-hot-toast';
import { useWebSocket } from '../../hooks/useWebSocket';
import api from '../../utils/api';

const LiveViewModal = ({ device, onClose }) => {
  const [isStreaming, setIsStreaming] = useState(false);
  const [frame, setFrame] = useState(null);
  const [textInput, setTextInput] = useState('');
  const [logs, setLogs] = useState([]);
  const [isRecording, setIsRecording] = useState(false);
  const recognitionRef = useRef(null);

  const ws = useWebSocket(device.deviceId);

  React.useEffect(() => {
    if (ws) {
      ws.on('device:frame', (data) => {
        if (data.deviceId === device.deviceId) {
          setFrame(data.frame);
        }
      });

      ws.on('device:log', (data) => {
        setLogs(prev => [...prev, { ...data, timestamp: new Date() }]);
      });
    }
  }, [ws, device.deviceId]);

  const sendCommand = async (command, params = {}) => {
    try {
      await api.post(`/v1/devices/${device.deviceId}/command`, {
        command,
        params,
      });
      toast.success(`Sent: ${command.toUpperCase()}`);
    } catch (error) {
      toast.error('Command transmission failed');
    }
  };

  const handleStartStream = () => {
    setIsStreaming(true);
    sendCommand('start');
  };

  const handleStopStream = () => {
    setIsStreaming(false);
    sendCommand('stop');
  };

  const handleLock = () => {
    sendCommand('lock');
  };

  const handleUnlock = () => {
    sendCommand('unlock');
  };

  const handleSendText = () => {
    if (textInput.trim()) {
      sendCommand('text', { text: textInput });
      setTextInput('');
    }
  };

  const handleScreenshot = () => {
    sendCommand('screenshot');
  };

  return (
    <div className="fixed inset-0 bg-[#0d0b14]/95 backdrop-blur-xl flex items-center justify-center z-[200] p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass rounded-[40px] w-full max-w-7xl max-h-[95vh] overflow-hidden flex flex-col border border-white/10"
      >
        <div className="flex items-center justify-between p-6 border-b border-white/5">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-purple-600/20 rounded-2xl flex items-center justify-center border border-purple-500/20">
              <ShieldAlert className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-white tracking-tight">{device.name}</h2>
              <p className="text-[10px] text-white/30 uppercase tracking-widest font-bold">Session ID: {device.deviceId}</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-10 h-10 bg-white/5 hover:bg-white/10 rounded-xl flex items-center justify-center text-white/40 hover:text-white transition-all"
          >
            <X size={20} />
          </button>
        </div>

        <div className="flex-1 p-6 grid grid-cols-1 lg:grid-cols-4 gap-6 overflow-hidden">
          {/* Stream View */}
          <div className="lg:col-span-3 bg-black/40 rounded-[32px] overflow-hidden relative border border-white/5 shadow-inner">
            {frame ? (
              <img
                src={`data:image/jpeg;base64,${frame}`}
                alt="Device screen"
                className="w-full h-full object-contain"
              />
            ) : (
              <div className="flex items-center justify-center h-full">
                <div className="text-center">
                  <div className="w-20 h-20 bg-white/5 rounded-full flex items-center justify-center mx-auto mb-4 border border-white/5">
                    <Play size={32} className="text-white/10 ml-1" />
                  </div>
                  <p className="text-white/20 font-bold uppercase tracking-widest text-xs">No active stream</p>
                  <button 
                    onClick={handleStartStream}
                    className="mt-6 px-8 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-bold text-sm transition-all"
                  >
                    Initialize Stream
                  </button>
                </div>
              </div>
            )}
            
            {/* Stream Overlay Controls */}
            {isStreaming && (
              <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex items-center gap-2 bg-[#0d0b14]/80 backdrop-blur-md p-2 rounded-2xl border border-white/10">
                <button onClick={handleStopStream} className="p-3 bg-red-500/20 text-red-400 rounded-xl hover:bg-red-500/30 transition-all">
                  <Square size={18} fill="currentColor" />
                </button>
                <button onClick={handleScreenshot} className="p-3 bg-white/5 text-white/60 rounded-xl hover:bg-white/10 transition-all">
                  <Camera size={18} />
                </button>
              </div>
            )}
          </div>

          {/* Sidebar Controls */}
          <div className="flex flex-col gap-4 overflow-y-auto pr-2 custom-scrollbar">
            {/* Quick Actions */}
            <div className="glass rounded-3xl p-5 border border-white/5">
              <h3 className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em] mb-4">Security Protocol</h3>
              <div className="grid grid-cols-2 gap-3">
                <button
                  onClick={handleLock}
                  className="py-4 bg-red-600/20 text-red-400 rounded-2xl border border-red-500/20 hover:bg-red-600 hover:text-white transition-all flex flex-col items-center gap-2"
                >
                  <Lock size={20} />
                  <span className="text-[10px] font-bold uppercase">Lock PC</span>
                </button>
                <button
                  onClick={handleUnlock}
                  className="py-4 bg-green-600/20 text-green-400 rounded-2xl border border-green-500/20 hover:bg-green-600 hover:text-white transition-all flex flex-col items-center gap-2"
                >
                  <Unlock size={20} />
                  <span className="text-[10px] font-bold uppercase">Unlock PC</span>
                </button>
              </div>
            </div>

            {/* Interaction */}
            <div className="glass rounded-3xl p-5 border border-white/5">
              <h3 className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em] mb-4">Remote Message</h3>
              <div className="space-y-3">
                <input
                  type="text"
                  value={textInput}
                  onChange={(e) => setTextInput(e.target.value)}
                  placeholder="Type message..."
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-white/20 focus:outline-none focus:border-purple-500/50 focus:bg-white/10 transition-all text-xs"
                />
                <button
                  onClick={handleSendText}
                  className="w-full py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-bold text-xs transition-all"
                >
                  Send Overlay
                </button>
              </div>
            </div>

            {/* Logs */}
            <div className="flex-1 glass rounded-3xl p-5 border border-white/5 flex flex-col min-h-[250px]">
              <h3 className="text-[10px] font-bold text-white/30 uppercase tracking-[0.2em] mb-4 flex items-center justify-between">
                System Logs
                <Terminal size={12} />
              </h3>
              <div className="flex-1 overflow-y-auto space-y-2 font-mono">
                {logs.slice(-20).map((log, i) => (
                  <div key={i} className="text-[10px] leading-relaxed">
                    <span className="text-white/10">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                    <span className={`ml-2 ${log.type === 'error' ? 'text-red-400' : 'text-purple-400'}`}>
                      {log.message}
                    </span>
                  </div>
                ))}
                {logs.length === 0 && (
                  <div className="flex flex-col items-center justify-center h-full opacity-10">
                    <Terminal size={24} className="mb-2" />
                    <p className="text-[10px] font-bold uppercase tracking-widest">Awaiting Logs</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  );
};

export default LiveViewModal;