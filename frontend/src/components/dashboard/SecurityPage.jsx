import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, QrCode, Check, Copy, Key, Lock } from 'lucide-react';
import toast from 'react-hot-toast';
import QRCode from 'qrcode.react';
import { useAuth } from '../../context/AuthContext';
import api from '../../utils/api';

const SecurityPage = () => {
  const { user } = useAuth();
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(user?.twoFactorEnabled || false);
  const [setupMode, setSetupMode] = useState(false);
  const [qrCode, setQrCode] = useState(null);
  const [secret, setSecret] = useState('');
  const [backupCodes, setBackupCodes] = useState([]);
  const [verificationCode, setVerificationCode] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [loading, setLoading] = useState(false);

  const enableTwoFactor = async () => {
    setLoading(true);
    try {
      const response = await api.post('/v1/user/enable-2fa');
      setQrCode(response.data.qrCode);
      setSecret(response.data.secret);
      setBackupCodes(response.data.backupCodes);
      setSetupMode(true);
      toast.success('Scan QR code with authenticator app');
    } catch (error) {
      toast.error('Failed to enable 2FA');
    } finally {
      setLoading(false);
    }
  };

  const verifyTwoFactor = async () => {
    if (!verificationCode || verificationCode.length !== 6) {
      toast.error('Please enter a valid 6-digit code');
      return;
    }

    setVerifying(true);
    try {
      await api.post('/v1/user/verify-2fa', { token: verificationCode });
      setTwoFactorEnabled(true);
      setSetupMode(false);
      toast.success('2FA enabled successfully!');
    } catch (error) {
      toast.error('Invalid verification code');
    } finally {
      setVerifying(false);
    }
  };

  const disableTwoFactor = async () => {
    if (!confirm('Are you sure you want to disable 2FA?')) return;

    try {
      await api.post('/v1/user/disable-2fa');
      setTwoFactorEnabled(false);
      setSetupMode(false);
      toast.success('2FA disabled');
    } catch (error) {
      toast.error('Failed to disable 2FA');
    }
  };

  const getBackupCodes = async () => {
    try {
      const response = await api.get('/v1/user/backup-codes');
      setBackupCodes(response.data.backupCodes);
      toast.success('Backup codes generated');
    } catch (error) {
      toast.error('Failed to generate backup codes');
    }
  };

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">Security</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="glass rounded-2xl p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Shield size={24} className="text-primary" />
            <h2 className="text-xl font-bold text-white">Two-Factor Authentication</h2>
          </div>

          {!twoFactorEnabled && !setupMode && (
            <div>
              <p className="text-gray-400 mb-4">
                Add an extra layer of security to your account by enabling two-factor authentication.
              </p>
              <button
                onClick={enableTwoFactor}
                disabled={loading}
                className="px-4 py-2 bg-gradient-to-r from-primary to-secondary rounded-lg text-white font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {loading ? 'Enabling...' : 'Enable 2FA'}
              </button>
            </div>
          )}

          {setupMode && (
            <div>
              <p className="text-gray-400 mb-4">
                Scan the QR code with Google Authenticator or Authy, then enter the 6-digit code.
              </p>
              {qrCode && (
                <div className="flex justify-center mb-4">
                  <img src={qrCode} alt="2FA QR Code" className="w-48 h-48" />
                </div>
              )}
              <div className="mb-4">
                <p className="text-sm text-gray-400 mb-2">Secret Key (manual entry)</p>
                <div className="flex items-center space-x-2">
                  <code className="flex-1 bg-black/50 p-2 rounded text-sm font-mono text-primary break-all">
                    {secret}
                  </code>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(secret);
                      toast.success('Copied!');
                    }}
                    className="p-2 hover:bg-white/10 rounded transition-colors"
                  >
                    <Copy size={16} className="text-gray-400" />
                  </button>
                </div>
              </div>
              <div className="mb-4">
                <input
                  type="text"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="Enter 6-digit code"
                  className="w-full px-4 py-3 bg-white/5 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-primary transition-colors text-center text-2xl"
                  maxLength={6}
                />
              </div>
              <div className="flex space-x-3">
                <button
                  onClick={verifyTwoFactor}
                  disabled={verifying || verificationCode.length !== 6}
                  className="flex-1 px-4 py-2 bg-green-500/20 text-green-500 rounded-lg hover:bg-green-500/30 transition-colors disabled:opacity-50"
                >
                  {verifying ? 'Verifying...' : 'Verify'}
                </button>
                <button
                  onClick={() => setSetupMode(false)}
                  className="flex-1 px-4 py-2 bg-white/5 text-gray-400 rounded-lg hover:bg-white/10 transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {twoFactorEnabled && (
            <div>
              <div className="flex items-center space-x-2 mb-4">
                <Check size={20} className="text-green-500" />
                <span className="text-green-500 font-medium">2FA is enabled</span>
              </div>
              <div className="space-y-3">
                <button
                  onClick={getBackupCodes}
                  className="w-full px-4 py-2 bg-white/5 rounded-lg text-gray-300 hover:bg-white/10 transition-colors flex items-center justify-center space-x-2"
                >
                  <Key size={16} />
                  <span>Get Backup Codes</span>
                </button>
                {backupCodes.length > 0 && (
                  <div className="bg-black/30 rounded-lg p-4">
                    <p className="text-sm text-gray-400 mb-2">Save these backup codes:</p>
                    <div className="grid grid-cols-2 gap-2">
                      {backupCodes.map((code, i) => (
                        <code key={i} className="bg-black/50 p-2 rounded text-sm font-mono text-primary text-center">
                          {code}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
                <button
                  onClick={disableTwoFactor}
                  className="w-full px-4 py-2 bg-red-500/20 text-red-500 rounded-lg hover:bg-red-500/30 transition-colors"
                >
                  Disable 2FA
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="glass rounded-2xl p-6">
          <div className="flex items-center space-x-3 mb-4">
            <Lock size={24} className="text-primary" />
            <h2 className="text-xl font-bold text-white">Security Tips</h2>
          </div>
          <ul className="space-y-3 text-gray-400">
            <li className="flex items-start space-x-3">
              <span className="text-primary text-sm">•</span>
              <span>Use a strong, unique password</span>
            </li>
            <li className="flex items-start space-x-3">
              <span className="text-primary text-sm">•</span>
              <span>Enable 2FA for extra security</span>
            </li>
            <li className="flex items-start space-x-3">
              <span className="text-primary text-sm">•</span>
              <span>Never share your API key publicly</span>
            </li>
            <li className="flex items-start space-x-3">
              <span className="text-primary text-sm">•</span>
              <span>Regularly regenerate your API key</span>
            </li>
            <li className="flex items-start space-x-3">
              <span className="text-primary text-sm">•</span>
              <span>Keep backup codes in a safe place</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default SecurityPage;