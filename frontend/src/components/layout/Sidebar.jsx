import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import clsx from 'clsx';
import {
  LayoutDashboard,
  ShieldAlert,
  ShieldCheck,
  Bug,
  Database,
  Globe,
  BrainCircuit,
  Settings,
  LogOut,
  Activity,
  BarChart,
  Rocket,
  FileText,
  Radio,
  GitBranch,
  Zap,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import useAuthStore from '../../stores/authStore';

// ── Real-time system health hook ──────────────────────────────────────────────
import { healthAPI } from '../../api/client';

function useSystemHealth() {
  const [health, setHealth] = useState({ status: 'unknown', score: 0, label: '...' });

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const res = await healthAPI.check();
        const data = res.data;

        // Compute health score from dependencies
        const deps = Object.values(data.dependencies || {});
        const total = deps.length || 1;
        const ok = deps.filter(d => d.status === 'ok').length;
        const score = Math.round((ok / total) * 100);

        setHealth({
          status: data.status,
          score,
          label: `${score}%`,
          ok,
          total,
        });
      } catch {
        setHealth({ status: 'offline', score: 0, label: 'Offline' });
      }
    };

    fetchHealth();
    const id = setInterval(fetchHealth, 15000); // poll every 15s
    return () => clearInterval(id);
  }, []);

  return health;
}

const Sidebar = () => {
  const logout = useAuthStore((state) => state.logout);
  const navigate = useNavigate();
  const health = useSystemHealth();

  const navItems = [
    { to: '/', label: 'Command Center', icon: LayoutDashboard },
    { to: '/threat-intel', label: 'Threat Intel', icon: ShieldAlert },
    { to: '/vulnerabilities', label: 'Vulnerability Lab', icon: Bug },
    { to: '/attack-graph', label: 'Attack Graph', icon: GitBranch },
    { to: '/network', label: 'Network Map', icon: Globe },
    { to: '/ai-insights', label: 'AI Insights', icon: BrainCircuit },
    { to: '/assets', label: 'Asset Cluster', icon: Database },
    { to: '/scans', label: 'Scan Management', icon: Activity },
    { to: '/live-monitor', label: 'Live Monitor', icon: Radio },
    { to: '/ai-monitor', label: 'MLOps Dashboard', icon: Zap },
    { to: '/analytics', label: 'Analytics', icon: BarChart },
    { to: '/reporting', label: 'Reporting', icon: FileText },
    { to: '/compliance', label: 'Compliance', icon: ShieldCheck },
  ];

  // Colour‑code the health bar
  const barColor =
    health.status === 'healthy' ? 'bg-emerald-500 shadow-[0_0_10px_#10b981]'
    : health.status === 'degraded' ? 'bg-amber-500 shadow-[0_0_10px_#f59e0b]'
    : health.status === 'offline' ? 'bg-red-500 shadow-[0_0_10px_#ef4444]'
    : 'bg-primary shadow-[0_0_10px_#bd9dff]';

  const labelColor =
    health.status === 'healthy' ? 'text-emerald-400'
    : health.status === 'degraded' ? 'text-amber-400'
    : health.status === 'offline' ? 'text-red-400'
    : 'text-primary';

  const handleInitiateScan = () => navigate('/scans');

  return (
    <aside className="bg-slate-950/60 backdrop-blur-3xl rounded-2xl m-4 h-[calc(100vh-2rem)] w-64 fixed left-0 top-0 flex flex-col p-4 z-50 border border-white/5 shadow-[0_30px_60px_rgba(0,0,0,0.8)]">
      <div className="mb-10 px-4">
        <div className="flex items-center gap-2 mb-1">
          <div className="w-2 h-6 bg-primary rounded-full shadow-[0_0_15px_rgba(189,157,255,0.6)]"></div>
          <h1 className="text-xl font-bold tracking-tighter text-white font-headline">SENTINEL</h1>
        </div>
        <p className="text-[9px] uppercase tracking-[0.3em] text-slate-500 font-label">Sovereign Observer System</p>
      </div>

      <nav className="flex-1 flex flex-col gap-1 overflow-y-auto custom-scrollbar">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            className={({ isActive }) =>
              clsx(
                "magnetic-item flex items-center gap-3 px-4 py-3 rounded-xl transition-all group",
                isActive
                  ? "text-primary bg-primary/10 border-l-2 border-primary"
                  : "text-slate-400 hover:text-white hover:bg-white/5"
              )
            }
          >
            <item.icon className="w-[20px] h-[20px]" />
            <span className="text-[11px] font-bold uppercase tracking-wider font-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="mt-4 px-2">
        <button
          onClick={handleInitiateScan}
          className="magnetic-item w-full py-3 rounded-xl bg-gradient-to-br from-primary to-primary-dim text-black font-bold text-sm flex items-center justify-center gap-2 hover:shadow-[0_0_25px_rgba(189,157,255,0.5)] transition-all active:scale-[0.97]"
        >
          <Rocket className="w-4 h-4" />
          INITIATE SCAN
        </button>
      </div>

      <div className="mt-auto pt-6 border-t border-white/5">
        {/* ── Real-time System Health ── */}
        <div className="px-4 mb-6">
          <div className="flex justify-between items-center mb-1.5">
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest flex items-center gap-1.5">
              {health.status === 'healthy'
                ? <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                : <AlertTriangle className="w-3 h-3 text-amber-400" />}
              Sys Health
            </span>
            <span className={`text-[9px] font-bold ${labelColor}`}>{health.label}</span>
          </div>
          <div className="h-1 bg-slate-900 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${barColor}`}
              style={{ width: `${health.score}%` }}
            />
          </div>
          {health.total > 0 && (
            <p className="text-[8px] text-slate-600 mt-1">
              {health.ok ?? 0}/{health.total} services ok
            </p>
          )}
        </div>

        <NavLink
          to="/settings"
          className={({ isActive }) =>
            clsx(
              "flex items-center gap-3 px-4 py-2 transition-colors cursor-pointer group rounded-xl",
              isActive
                ? "text-primary bg-primary/10"
                : "text-slate-400 hover:text-white"
            )
          }
        >
          <Settings className="w-[18px] h-[18px] group-hover:rotate-90 transition-transform" />
          <span className="text-[10px] font-bold uppercase tracking-widest font-label">System Config</span>
        </NavLink>
        <button onClick={logout} className="w-full flex items-center gap-3 px-4 py-2 text-slate-400 hover:text-error transition-colors cursor-pointer group">
          <LogOut className="w-[18px] h-[18px]" />
          <span className="text-[10px] font-bold uppercase tracking-widest font-label">Terminal Exit</span>
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
