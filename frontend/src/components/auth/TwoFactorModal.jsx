import React, { useState } from 'react';
import toast from 'react-hot-toast';
import { motion } from 'framer-motion';
import api from '../../utils/api';

const TwoFactorModal = ({ username, onSuccess, onClose }) => {
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await api.post('/auth/verify-2fa', {
        username,
        token,
      });
      onSuccess(response.data.token, response.data.user);
      toast.success('2FA verified successfully!');
    } catch (error) {
      toast.error(error.response?.data?.message || 'Invalid 2FA code');
    } finally {
      setLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4"
    >
      <motion.div
        initial={{ scale: 0.9 }}
        animate={{ scale: 1 }}
        className="glass rounded-2xl p-8 w-full max-w-md"
      >
        <h2 className="text-2xl font-bold text-center mb-4">Two-Factor Authentication</h2>
        <p className="text-gray-400 text-center mb-6">
          Enter the 6-digit code from your authenticator app
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="text"
            value={token}
            onChange={(e) => setToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
            maxLength={6}
            className="w-full px-4 py-3 text-center text-2xl bg-white/5 border border-white/10 rounded-lg text-white focus:outline-none focus:border-primary transition-colors"
            placeholder="000000"
          />

          <button
            type="submit"
            disabled={loading || token.length !== 6}
            className="w-full py-3 bg-gradient-to-r from-primary to-secondary rounded-lg text-white font-semibold hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            {loading ? 'Verifying...' : 'Verify'}
          </button>

          <button
            type="button"
            onClick={onClose}
            className="w-full py-2 text-gray-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
        </form>
      </motion.div>
    </motion.div>
  );
};

export default TwoFactorModal;