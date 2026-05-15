import useAuthStore from '../stores/authStore';

const useRBAC = () => {
  const { role, isAuthenticated } = useAuthStore();

  const hasRole = (requiredRoles) => {
    if (!isAuthenticated || !role) return false;
    if (Array.isArray(requiredRoles)) {
      return requiredRoles.includes(role);
    }
    return role === requiredRoles;
  };

  const isAdmin = role === 'admin';
  const isAnalyst = role === 'analyst' || role === 'admin';
  const isViewer = true; // Everyone can view if authenticated

  return { hasRole, isAdmin, isAnalyst, isViewer, role };
};

export default useRBAC;
