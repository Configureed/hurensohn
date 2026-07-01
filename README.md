# OathNet | Enterprise OSINT & Remote Control

OathNet is a professional-grade defensive platform designed for OSINT researchers and enterprise device management. It provides a secure, encrypted infrastructure for remote device control, real-time monitoring, and automated security protocols.

## ⚡ Core Features

- **Advanced OSINT Hub**: Centralized search for logs, breach records, and digital signatures.
- **Enterprise Auth**: Custom JS-based authentication system with prioritized owner rights.
- **Remote Security Protocol**: Real-time PC locking with fullscreen overlay and key blocking.
- **Encrypted Transmission**: AES-256-GCM encrypted communication between server and clients.
- **Client Builder**: On-the-fly generation of customized Python clients with embedded keys.
- **Live Stream & Control**: Low-latency screen monitoring and remote command execution.

## 🛠️ Infrastructure Setup

### Backend (Node.js/Express)
1. Navigate to `backend/`
2. Install dependencies: `npm install`
3. Configure `.env` with your MongoDB URI and JWT secrets.
4. Start server: `npm start` or use `backend.bat`

### Frontend (React/Vite)
1. Navigate to `frontend/`
2. Install dependencies: `npm install`
3. Start development server: `npm run dev` or use `install.bat`

### Client Deployment
1. Log in to the OathNet dashboard.
2. Navigate to the **Generator** tab.
3. Enter a device name and download the generated `.py` client.
4. Run the client on the target machine (requires Administrator for key blocking).

## 🚀 GitHub Deployment

1. **Push to GitHub**: Upload the entire folder to your repository. The `.gitignore` will ensure your private keys and `.env` files are not leaked.
2. **Domain Connection**: 
   - Deploy the **Backend** to a provider like Heroku, Railway, or a VPS.
   - Deploy the **Frontend** to Vercel, Netlify, or similar.
3. **Environment Setup**:
   - In your hosting provider settings, add the environment variables from `.env.example`.
   - **CRITICAL**: Set `VITE_API_URL` to your backend URL + `/api` and `CLIENT_URL` to your frontend domain.

## 🛡️ Security Logic
- **Owner System**: Registering with the username `voip` automatically grants global owner permissions.
- **Key System**: Custom-built licensing and authentication (No KeyAuth dependency).
- **Communication**: Uses Socket.IO with a secondary encryption layer (AES-GCM).

---
*Developed for solo researchers and enterprise teams who demand raw, high-performance security tools.*