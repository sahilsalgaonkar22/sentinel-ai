import { useState, useCallback } from 'react';
import { scanAPI } from '../api/client';

const useScans = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await scanAPI.listScans();
      setScans(Array.isArray(res.data) ? res.data : res.data?.items || []);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  }, []);

  const createScan = useCallback(async (scanData) => {
    setLoading(true);
    setError(null);
    try {
      const res = await scanAPI.createScan(scanData);
      setScans((prev) => [res.data, ...prev]);
      return res.data;
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create scan');
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const cancelScan = useCallback(async (scanId) => {
    try {
      await scanAPI.cancelScan(scanId);
      setScans((prev) =>
        prev.map((s) => (s.id === scanId ? { ...s, status: 'cancelled' } : s))
      );
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to cancel scan');
      throw err;
    }
  }, []);

  const getScanFindings = useCallback(async (scanId) => {
    const res = await scanAPI.getScanFindings(scanId);
    return res.data;
  }, []);

  return { scans, loading, error, fetchScans, createScan, cancelScan, getScanFindings };
};

export default useScans;
