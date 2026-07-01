import dotenv from 'dotenv';
import app from './app.js';
import { connectDatabase } from './config/database.js';
import { initializeSocket } from './sockets/deviceSocket.js';
import logger from './utils/logger.js';

dotenv.config();

const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    await connectDatabase();
    
    const server = app.listen(PORT, () => {
      logger.info(`NEXUS-IOT Backend running on port ${PORT}`);
      logger.info(`API URL: http://localhost:${PORT}`);
    });

    initializeSocket(server);
    app.set('io', initializeSocket(server));

    process.on('SIGTERM', () => {
      logger.info('SIGTERM received, closing server...');
      server.close(() => {
        logger.info('Server closed');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Server startup error:', error);
    process.exit(1);
  }
};

startServer();