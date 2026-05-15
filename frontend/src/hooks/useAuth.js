import { useCallback } from 'react';
import { authAPI } from '../api/client';
import useAuthStore from '../stores/authStore';

const useAuth = () => {
  const { setUser, setToken, logout: storeLogout, isAuthenticated, user, token } = useAuthStore();

  const login = useCallback(async (email, password) => {
    const res = await authAPI.login(email, password);
    const { access_token } = res.data;
    localStorage.setItem('sentinel_token', access_token);
    setToken(access_token);

    // Fetch user profile
    const meRes = await authAPI.getMe();
    setUser(meRes.data);
    return meRes.data;
  }, [setToken, setUser]);

  const logout = useCallback(() => {
    localStorage.removeItem('sentinel_token');
    storeLogout();
  }, [storeLogout]);

  return { login, logout, isAuthenticated, user, token };
};

export default useAuth;
