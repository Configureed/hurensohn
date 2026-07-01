import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Copy, Check, Key, User, Server, RefreshCw } from 'lucide-react';
import toast from 'react-hot-toast';
import { useAuth } from '../../context/AuthContext';
import api from '../../utils/api';

const InfosPage = () => {
  const { user } = useAuth();
  const [copied, setCopied] = useState({});
  const [apiKey, setApiKey] = useState(user?.apiKey || '');
  const [regenerating, setRegenerating] = useState(false);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopied({ ...copied, [key]: true });
    toast.success('Copied to clipboard!');
    setTimeout(() => setCopied({ ...copied, [key]: false }), 2000);
  };

  const regenerateApiKey = async () => {
    setRegenerating(true);
    try {
      const response = await api.post('/v1/user/regenerate-key');
      setApiKey(response.data.apiKey);
      toast.success('API key regenerated successfully!');
    } catch (error) {
      toast.error('Failed to regenerate API key');
    } finally {
      setRegenerating(false);
    }
  };

  const infoItems = [
    {
      icon: User,
      label: 'Account ID',
      value: user?.accountId || 'N/A',
      key: 'accountId',
    },
    {
      icon: Key,
      label: 'API Key',
      value: apiKey,
      key: 'apiKey',
      isApiKey: true,
    },
    {
      icon: Server,
      label: 'API Base URL',
      value: 'http://localhost:5000/api/v1',
      key: 'apiUrl',
    },
  ];

  const endpoints = [
    { method: 'GET', path: '/devices', description: 'List all devices' },
    { method: 'POST', path: '/devices', description: 'Register new device' },
    { method: 'GET', path: '/devices/:id', description: 'Get device details' },
    { method: 'PUT', path: '/devices/:id', description: 'Update device' },
    { method: 'DELETE', path: '/devices/:id', description: 'Delete device' },
    { method: 'POST', path: '/devices/:id/command', description: 'Send command' },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Infos</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {infoItems.map((item) => (
          <motion.div
            key={item.key}
            whileHover={{ scale: 1.02 }}
            className="glass rounded-xl p-6"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2 mb-2">
                  <item.icon size={16} className="text-primary" />
                  <span className="text-sm text-gray-400">{item.label}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <p className="text-lg font-mono text-white truncate">
                    {item.isApiKey ? '•'.repeat(32) : item.value}
                  </p>
                  {item.isApiKey && (
                    <button
                      onClick={() => setCopied({ ...copied, [item.key]: !copied[item.key] })}
                      className="p-1 hover:bg-white/10 rounded transition-colors"
                    >
                      {copied[item.key] ? (
                        <Check size={16} className="text-green-500" />
                      ) : (
                        <Copy size={16} className="text-gray-400 hover:text-white" />
                      )}
                    </button>
                  )}
                </div>
              </div>
              {item.isApiKey && (
                <button
                  onClick={regenerateApiKey}
                  disabled={regenerating}
                  className="px-3 py-1 bg-primary/20 text-primary rounded-lg hover:bg-primary/30 transition-colors flex items-center space-x-1 text-sm disabled:opacity-50"
                >
                  <RefreshCw size={14} className={regenerating ? 'animate-spin' : ''} />
                  <span>Regenerate</span>
                </button>
              )}
            </div>
          </motion.div>
        ))}
      </div>

      <div className="glass rounded-2xl p-6">
        <h2 className="text-xl font-bold text-white mb-4">API Documentation</h2>
        <p className="text-gray-400 mb-4">
          Use your API key in the <code className="bg-white/5 px-2 py-1 rounded text-primary">X-API-Key</code> header for all requests.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-white/10">
                <th className="text-left py-3 px-4 text-sm text-gray-400">Method</th>
                <th className="text-left py-3 px-4 text-sm text-gray-400">Endpoint</th>
                <th className="text-left py-3 px-4 text-sm text-gray-400">Description</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint, index) => (
                <tr key={index} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      endpoint.method === 'GET' ? 'bg-blue-500/20 text-blue-400' :
                      endpoint.method === 'POST' ? 'bg-green-500/20 text-green-400' :
                      endpoint.method === 'PUT' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-red-500/20 text-red-400'
                    }`}>
                      {endpoint.method}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm font-mono text-gray-300">
                    {endpoint.path}
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-400">
                    {endpoint.description}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="mt-6 glass rounded-xl p-4">
          <h3 className="text-sm font-medium text-gray-400 mb-2">Example Usage</h3>
          <pre className="text-xs text-green-400 font-mono bg-black/50 p-4 rounded-lg overflow-x-auto">
            {`curl -X GET http://localhost:5000/api/v1/devices \\
  -H "X-API-Key: ${apiKey || 'YOUR_API_KEY'}"`}
          </pre>
        </div>
      </div>
    </div>
  );
};

export default InfosPage;