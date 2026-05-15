import { useState, useEffect, useCallback, useRef } from 'react';
import useAuthStore from '../stores/authStore';
import useNotificationStore from '../stores/notificationStore';

// When behind nginx proxy (Docker): use same-origin host
// When running locally (dev): set VITE_WS_URL=localhost:8000
const WS_HOST = import.meta.env.VITE_WS_URL || window.location.host;

const useWebSocket = (scansToWatch = []) => {
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected'); // disconnected | connecting | connected | error
  const [lastMessage, setLastMessage] = useState(null);
  const [scanProgress, setScanProgress] = useState({});
  const [scanLogs, setScanLogs] = useState({});  // scan_id -> [log lines]
  const [latestFindings, setLatestFindings] = useState([]);

  const ws = useRef(null);
  const reconnectTimer = useRef(null);
  const reconnectAttempts = useRef(0);

  const token = useAuthStore.getState().token;
  const addNotification = useNotificationStore.getState().addNotification;

  const connect = useCallback(() => {
    if (!token) {
      setConnectionStatus('disconnected');
      return;
    }

    // Clean up existing connection
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      return;
    }

    setConnectionStatus('connecting');
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const clientId = `client-${Math.random().toString(36).substring(2, 9)}`;

    try {
      ws.current = new WebSocket(`${protocol}//${WS_HOST}/ws/${clientId}?token=${token}`);
    } catch {
      setConnectionStatus('error');
      return;
    }

    ws.current.onopen = () => {
      setIsConnected(true);
      setConnectionStatus('connected');
      reconnectAttempts.current = 0;
      console.log('[WS] ✅ Connected to SENTINEL AI Gateway');

      // Subscribe to any active scans
      scansToWatch.forEach((scanId) => {
        ws.current.send(JSON.stringify({ type: 'subscribe_scan', scan_id: scanId }));
      });
    };

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        setLastMessage(data);

        switch (data.type) {
          case 'scan_progress':
            setScanProgress((prev) => ({
              ...prev,
              [data.scan_id]: data.progress,
            }));
            break;

          case 'scan_log':
            setScanLogs((prev) => ({
              ...prev,
              [data.scan_id]: [
                ...(prev[data.scan_id] || []).slice(-500), // Keep last 500 lines
                { tool: data.tool, level: data.level, message: data.message, ts: Date.now() },
              ],
            }));
            break;

          case 'new_finding':
            setLatestFindings((prev) => [data.finding, ...prev].slice(0, 50));
            addNotification({
              title: `New Finding: ${data.finding?.title || 'Unknown'}`,
              message: `Severity: ${data.finding?.severity} | Tool: ${data.finding?.tool_name}`,
              type: 'finding',
            });
            break;

          case 'scan_completed':
            addNotification({
              title: 'Scan Completed',
              message: `${data.total_findings} findings — Critical: ${data.critical || 0}`,
              type: 'scan',
            });
            setScanProgress((prev) => ({ ...prev, [data.scan_id]: 100 }));
            break;

          case 'threat_alert':
            addNotification({
              title: data.title || 'Threat Alert',
              message: data.message || '',
              type: 'critical',
            });
            break;

          default:
            break;
        }
      } catch {
        // Non-JSON message — ignore
      }
    };

    ws.current.onclose = (event) => {
      setIsConnected(false);
      setConnectionStatus('disconnected');
      console.log(`[WS] Disconnected (code: ${event.code})`);

      // Exponential backoff reconnect
      const delay = Math.min(1000 * 2 ** reconnectAttempts.current, 30000);
      reconnectAttempts.current += 1;
      reconnectTimer.current = setTimeout(connect, delay);
    };

    ws.current.onerror = () => {
      setConnectionStatus('error');
      // onclose will fire next and trigger reconnect
    };
  }, [token, addNotification]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (ws.current) {
        ws.current.onclose = null; // Prevent reconnect on unmount
        ws.current.close();
      }
    };
  }, [connect]);

  // Subscribe to a new scan at runtime
  const subscribeToScan = useCallback((scanId) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({ type: 'subscribe_scan', scan_id: scanId }));
    }
  }, []);

  return {
    isConnected,
    connectionStatus,
    lastMessage,
    scanProgress,
    scanLogs,
    latestFindings,
    subscribeToScan,
  };
};

export default useWebSocket;
