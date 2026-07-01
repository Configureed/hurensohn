import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import crypto from 'crypto';

export const generateTwoFactorSecret = (username) => {
  const secret = speakeasy.generateSecret({
    name: `OathNet (${username})`,
    length: 20
  });
  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url
  };
};

export const generateQRCode = async (otpauthUrl) => {
  try {
    return await QRCode.toDataURL(otpauthUrl);
  } catch (error) {
    throw new Error('Failed to generate QR code');
  }
};

export const verifyTwoFactorToken = (secret, token) => {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 1
  });
};

export const generateBackupCodes = (count = 10) => {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    codes.push(code);
  }
  return codes;
};