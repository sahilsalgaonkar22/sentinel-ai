import axios from 'axios';

// When behind nginx proxy (Docker): VITE_API_URL is empty → same-origin requests
// When running locally (dev): VITE_API_URL=http://localhost:8000
const BACKEND_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: BACKEND_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 15000,
});

// ── Request interceptor: attach JWT ─────────────────────────
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('sentinel_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// ── Response interceptor: handle auth failures ───────────────
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('sentinel_token');
      // Redirect to login only if not already there
      if (!window.location.pathname.includes('/login')) {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ── Auth ─────────────────────────────────────────────────────
export const authAPI = {
  login: (email, password) => {
    const form = new URLSearchParams();
    form.append('username', email);  // OAuth2PasswordRequestForm expects 'username'
    form.append('password', password);
    return api.post('/auth/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
  },
  register: (data) => api.post('/auth/register', data),
  getMe: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
};

// ── Scans ─────────────────────────────────────────────────────
export const scanAPI = {
  listScans: (params) => api.get('/scans', { params }),
  list: (params) => api.get('/scans', { params }),  // alias for backward compat
  getScan: (id) => api.get(`/scans/${id}`),
  createScan: (data) => api.post('/scans', data),
  getScanFindings: (id) => api.get(`/scans/${id}/findings`),
  cancelScan: (id) => api.post(`/scans/${id}/cancel`),
  getAttackPaths: (id) => api.get(`/scans/${id}/attack-paths`),
  compareScans: (beforeId, afterId) => api.post('/scans/compare', { scan_id_before: beforeId, scan_id_after: afterId }),
};

// ── Vulnerabilities ───────────────────────────────────────────
export const vulnAPI = {
  listVulns: (params) => api.get('/vulnerabilities/', { params }),
  list: (params) => api.get('/vulnerabilities/', { params }),  // alias for backward compat
  getVuln: (id) => api.get(`/vulnerabilities/${id}`),
  updateVuln: (id, data) => api.put(`/vulnerabilities/${id}`, data),
  getStats: () => api.get('/vulnerabilities/stats/summary'),
  listAttackPaths: () => api.get('/vulnerabilities/attack-paths/'),
};

// ── Assets ────────────────────────────────────────────────────
export const assetAPI = {
  listAssets: (params) => api.get('/assets/', { params }),
  getAsset: (id) => api.get(`/assets/${id}`),
  createAsset: (data) => api.post('/assets/', data),
  updateAsset: (id, data) => api.put(`/assets/${id}`, data),
  getStats: () => api.get('/assets/stats/summary'),
};

// ── Dashboard ─────────────────────────────────────────────────
export const dashboardAPI = {
  getStats: () => api.get('/dashboard/stats'),
  getAnalytics: () => api.get('/dashboard/analytics'),
  getCommandCenterData: () => api.get('/dashboard/command-center'),
  getAIInsights: () => api.get('/dashboard/ai-insights'),
  getThreatFeed: () => api.get('/dashboard/threat-feed'),
};

// ── AI Intelligence ───────────────────────────────────────────
export const aiAPI = {
  search: (query) => api.get('/ai/search', { params: { q: query } }),
  chat: (query) => api.post('/ai/chat', { query }),
  getAttackGraph: () => api.get('/ai/attack-graph'),
  getRiskScore: (data) => api.post('/ai/risk-score', data),
  checkFalsePositive: (data) => api.post('/ai/false-positive', data),
  submitFeedback: (data) => api.post('/ai/feedback', data),
  getMetrics: () => api.get('/ai/metrics'),
};

// ── Reporting ─────────────────────────────────────────────────
export const reportingAPI = {
  listReports: () => api.get('/reporting/'),
  generateReport: (data) => api.post('/reporting/generate', data),
  downloadReport: (id) => api.get(`/reporting/${id}/download`, { responseType: 'blob' }),
};

// ── Live Scan Monitoring ───────────────────────────────────────
export const liveAPI = {
  getToolStatuses: () => api.get('/live-scan/tools'),
  getActiveScans: () => api.get('/live-scan/active'),
  getScanLogs: (scanId, tool) => api.get(`/live-scan/logs/${scanId}`, { params: { tool } }),
  getToolLogs: (toolId) => api.get(`/live-scan/logs/tool/${toolId}`),
};

// ── Settings ──────────────────────────────────────────────────
export const settingsAPI = {
  getSettings: () => api.get('/settings/'),
  updateAlerts: (data) => api.patch('/settings/alerts', data),
  updateScanning: (data) => api.patch('/settings/scanning', data),
  updateAI: (data) => api.patch('/settings/ai', data),
  getProfile: () => api.get('/settings/profile'),
  listUsers: () => api.get('/settings/users'),
  updateUserRole: (userId, role) => api.patch(`/settings/users/${userId}/role`, { role }),
};

// ── Compliance ────────────────────────────────────────────────
export const complianceAPI = {
  getReport: (scanId) => api.get(`/compliance/${scanId}`),
  listFrameworks: () => api.get('/compliance/frameworks/list'),
};

// ── Scheduling ────────────────────────────────────────────────
export const scheduleAPI = {
  schedule: (scanId, cron) => api.post(`/scans/${scanId}/schedule`, { cron }),
  unschedule: (scanId) => api.delete(`/scans/${scanId}/schedule`),
  listScheduled: () => api.get('/scans/scheduled/list'),
  getDrift: (scanId) => api.get(`/scans/${scanId}/drift`),
};

// ── Health ────────────────────────────────────────────────────
export const healthAPI = {
  check: () => api.get('/health'),
};

export default api;
