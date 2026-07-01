import { useEffect, useRef, useState } from 'react';
import io from 'socket.io-client';

export const useWebSocket = (deviceId) => {
  const [socket, setSocket] = useState(null);
  const socketRef = useRef(null);

  useEffect(() => {
    if (!deviceId) return;

    const wsUrl = import.meta.env.VITE_WS_URL || 'http://localhost:5000';
    const newSocket = io(wsUrl, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
    });

    socketRef.current = newSocket;
    setSocket(newSocket);

    newSocket.on('connect', () => {
      console.log('WebSocket connected');
      newSocket.emit('device:auth', { deviceId });
    });

    newSocket.on('disconnect', () => {
      console.log('WebSocket disconnected');
    });

    return () => {
      if (newSocket) {
        newSocket.disconnect();
      }
    };
  }, [deviceId]);

  return socket;
};