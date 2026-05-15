import { create } from 'zustand';
import { jwtDecode } from 'jwt-decode';

const useAuthStore = create((set) => ({
  token: localStorage.getItem('sentinel_token') || null,
  user: null,
  isAuthenticated: false,
  role: null,
  orgId: null,

  login: (token) => {
    const decoded = jwtDecode(token);
    set({ 
      token, 
      user: decoded, 
      isAuthenticated: true,
      role: decoded.role || 'viewer',
      orgId: decoded.org_id
    });
    localStorage.setItem('sentinel_token', token);
  },

  logout: async () => {
    // Revoke JWT on the server (Redis blacklist) before clearing local state
    try {
      const { authAPI } = await import('../api/client');
      await authAPI.logout();
    } catch {
      // Server revocation failed — still clear local state
    }
    set({ 
      token: null, 
      user: null, 
      isAuthenticated: false,
      role: null,
      orgId: null
    });
    localStorage.removeItem('sentinel_token');
  },

  checkAuth: () => {
    const token = localStorage.getItem('sentinel_token');
    if (token) {
      try {
        const decoded = jwtDecode(token);
        if (decoded.exp * 1000 > Date.now()) {
          set({ 
            token, 
            user: decoded, 
            isAuthenticated: true,
            role: decoded.role || 'viewer',
            orgId: decoded.org_id
          });
        } else {
          localStorage.removeItem('sentinel_token');
        }
      } catch (e) {
        localStorage.removeItem('sentinel_token');
      }
    }
  }
}));

export default useAuthStore;
