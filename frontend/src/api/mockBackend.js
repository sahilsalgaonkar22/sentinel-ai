/**
 * SENTINEL AI — Offline Fallback
 *
 * This module is NO LONGER an axios interceptor.
 * It provides static fallback data ONLY when the backend is unreachable
 * (network error). The calling component decides whether to show this.
 *
 * Interceptor has been removed. All API calls go to the real backend.
 */

// date-fns not needed in offline fallback module

// ─── Static fallback data (used only for offline mode) ───────

export const OFFLINE_FALLBACK = {
  health: { status: 'offline', service: 'gateway', version: '4.0.0' },

  commandCenter: {
    risk_score: 0,
    changes_24h: { new_vulns: 0, resolved_vulns: 0, new_assets: 0, total_assets: 0 },
    top_vulnerabilities: [],
    threat_stream: [],
  },

  scans: [],

  vulnerabilities: {
    items: [],
    total: 0,
    page: 1,
    per_page: 20,
  },

  vulnStats: { total: 0, critical: 0, high: 0, medium: 0, low: 0 },

  assets: { items: [], total: 0 },

  assetStats: { total: 0, critical: 0, high: 0, medium: 0 },

  aiInsights: {
    insights: [],
    risk_forecast: { next_24h: 'unknown', trend: 'unknown' },
  },
};

/**
 * Check if we are in demo/offline mode by pinging the backend.
 * Returns true if backend is reachable.
 */
export async function checkBackendHealth() {
  try {
    // Use same-origin /health — nginx proxies this to the gateway
    const baseUrl = import.meta.env.VITE_API_URL || '';
    const res = await fetch(`${baseUrl}/health`, {
      signal: AbortSignal.timeout(3000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
