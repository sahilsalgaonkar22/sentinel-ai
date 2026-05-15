import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useAuthStore from '../stores/authStore';
import { authAPI } from '../api/client';
import { ShieldCheck, Loader2, AlertCircle, Zap, UserPlus } from 'lucide-react';

const LoginPage = () => {
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const login = useAuthStore((state) => state.login);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const navigate = useNavigate();

  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (mode === 'register') {
        await authAPI.register({
          email,
          password,
          full_name: fullName || 'Operator',
          org_name: orgName || 'Default Org',
        });
        // Auto-login after registration
      }
      const response = await authAPI.login(email, password);
      login(response.data.access_token);
      navigate('/', { replace: true });
    } catch (err) {
      if (err.response) {
        setError(err.response.data?.detail || (mode === 'register' ? 'Registration failed' : 'Invalid credentials'));
      } else if (err.request) {
        setError('Network error: Cannot reach security gateway');
      } else {
        setError('System error: Authentication failed');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#050709] relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(189,157,255,0.05)_0%,transparent_50%)]"></div>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,rgba(54,188,253,0.03)_0%,transparent_50%)]"></div>
        <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'linear-gradient(rgba(189, 157, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(189, 157, 255, 0.03) 1px, transparent 1px)', backgroundSize: '60px 60px' }}></div>
      </div>

      <div className="relative z-10 w-full max-w-md">
        {/* Brand */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center gap-3 mb-4">
            <div className="w-2 h-8 bg-primary rounded-full shadow-[0_0_15px_rgba(189,157,255,0.6)]"></div>
            <h1 className="text-3xl font-bold tracking-tighter text-white font-headline">SENTINEL</h1>
          </div>
          <p className="text-[10px] uppercase tracking-[0.4em] text-slate-500 font-bold">Sovereign Observer System</p>
        </div>

        {/* Login/Register Card */}
        <div className="glass-panel rounded-[32px] p-10 border border-white/10 shadow-2xl bg-slate-950/60 backdrop-blur-3xl">
          <div className="flex items-center gap-3 mb-8">
            <div className="p-2.5 rounded-xl bg-primary/10 text-primary">
              {mode === 'login' ? <ShieldCheck className="w-5 h-5" /> : <UserPlus className="w-5 h-5" />}
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-widest font-headline">
                {mode === 'login' ? 'Security Gate' : 'Create Account'}
              </h2>
              <p className="text-[9px] text-slate-500 font-bold uppercase tracking-tighter">
                {mode === 'login' ? 'Authenticate to access terminal' : 'Register a new operator identity'}
              </p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {mode === 'register' && (
              <>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1 block">Full Name</label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="John Doe"
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:ring-1 focus:ring-primary/50 focus:border-primary/30 outline-none transition-all placeholder:text-slate-600"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1 block">Organization</label>
                  <input
                    type="text"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    placeholder="Acme Corp"
                    className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:ring-1 focus:ring-primary/50 focus:border-primary/30 outline-none transition-all placeholder:text-slate-600"
                  />
                </div>
              </>
            )}

            <div className="space-y-2">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1 block">
                {mode === 'login' ? 'Operator Identity' : 'Email Address'}
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@sentinel.ai"
                className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:ring-1 focus:ring-primary/50 focus:border-primary/30 outline-none transition-all placeholder:text-slate-600"
              />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1 block">
                {mode === 'login' ? 'Access Key' : 'Password'}
              </label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                minLength={mode === 'register' ? 8 : undefined}
                className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-3.5 text-sm text-white focus:ring-1 focus:ring-primary/50 focus:border-primary/30 outline-none transition-all placeholder:text-slate-600"
              />
            </div>

            {error && (
              <div className="flex items-center gap-3 p-4 rounded-2xl bg-error/10 border border-error/20 text-error">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <p className="text-xs font-bold">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-4 rounded-2xl bg-primary text-black font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(189,157,255,0.3)] hover:shadow-[0_0_50px_rgba(189,157,255,0.5)] transition-all active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-3"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  {mode === 'login' ? <Zap className="w-4 h-4" /> : <UserPlus className="w-4 h-4" />}
                  {mode === 'login' ? 'Initialize Session' : 'Create Account'}
                </>
              )}
            </button>
          </form>

          <div className="mt-6 pt-5 border-t border-white/5 text-center">
            <button
              type="button"
              onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(''); }}
              className="text-[10px] text-primary/80 font-bold uppercase tracking-widest hover:text-primary transition-colors"
            >
              {mode === 'login' ? 'Create new account' : 'Already have an account? Sign in'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
