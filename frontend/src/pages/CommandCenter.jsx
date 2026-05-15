import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { dashboardAPI } from '../api/client';
import { ShieldAlert, Activity, Globe, Zap, AlertTriangle, TrendingUp, Cpu, Server } from 'lucide-react';

const CommandCenter = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await dashboardAPI.getCommandCenterData();
        setData(response.data);
      } catch (error) {
        console.error("Failed to fetch command center data:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 30000); // Auto-refresh every 30s
    return () => clearInterval(interval);
  }, []);

  if (loading || !data) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <Activity className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Syncing with Sovereign AI...</span>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-12 gap-6 h-full page-entry">
      {/* Left Column - Main Dashboard */}
      <div className="col-span-12 lg:col-span-8 space-y-6">
        {/* Main Risk Display */}
        <motion.div 
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass-panel rounded-3xl p-10 min-h-[500px] flex flex-col items-center justify-center relative group overflow-hidden"
        >
          <div className="hud-bracket bracket-tl"></div>
          <div className="hud-bracket bracket-tr"></div>
          <div className="hud-bracket bracket-bl"></div>
          <div className="hud-bracket bracket-br"></div>
          
          <div className="absolute top-6 left-1/2 -translate-x-1/2 text-[9px] font-mono text-primary/40 uppercase tracking-[0.5em]">Sector Monitoring Active</div>
          
          <div className="orb-3d-scene relative cursor-pointer">
            {/* 3D Orb Implementation */}
            <div className="orb-core-3d">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(255,255,255,0.1)_0%,transparent_70%)] rounded-full animate-pulse"></div>
            </div>
            <div className="orb-ring-3d" style={{'--rx': '75deg', '--ry': '15deg', '--duration': '12s'}}></div>
            <div className="orb-ring-3d opacity-40" style={{'--rx': '75deg', '--ry': '-30deg', '--duration': '18s'}}></div>
            
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
              <div className="text-center">
                <span className="block text-7xl font-black font-headline text-white drop-shadow-[0_0_30px_rgba(255,255,255,0.3)] counter-anim">
                  {data.risk_score}
                </span>
                <span className="text-[10px] font-bold text-primary/80 uppercase tracking-[0.3em] font-label">Global Risk Index</span>
              </div>
            </div>
          </div>

          <div className="mt-12 text-center relative z-10 max-w-2xl">
            <h2 className="text-4xl font-bold font-headline mb-3 text-white tracking-tight">System Health: <span className={data.risk_score < 50 ? 'text-green-400' : 'text-primary'}>Stable</span></h2>
            <p className="text-slate-400 text-sm leading-relaxed">
              Neural patterns suggest a <span className="text-primary font-bold">{(data.risk_score / 10).toFixed(1)}%</span> risk delta. 
              {data.changes_24h.new_vulns} new vectors identified. Sovereign AI is modulating active encryption layers across all clusters.
            </p>
            
            <div className="mt-10 flex gap-12 justify-center">
              <div className="flex flex-col items-center">
                <span className="text-[9px] text-primary/60 font-bold mb-3 tracking-widest uppercase">Stability</span>
                <div className="flex gap-1.5 h-6 items-end">
                  <div className="w-1.5 bg-primary/20 h-2"></div>
                  <div className="w-1.5 bg-primary/40 h-4"></div>
                  <div className="w-1.5 bg-primary h-6 shadow-[0_0_10px_#bd9dff]"></div>
                  <div className="w-1.5 bg-primary/40 h-3"></div>
                </div>
              </div>
              <div className="flex flex-col items-center">
                <span className="text-[9px] text-primary/60 font-bold mb-3 tracking-widest uppercase">Scan Depth</span>
                <div className="flex gap-1.5 h-6 items-end">
                  <div className="w-1.5 bg-primary h-3"></div>
                  <div className="w-1.5 bg-primary h-5"></div>
                  <div className="w-1.5 bg-primary h-6 shadow-[0_0_10px_#bd9dff]"></div>
                  <div className="w-1.5 bg-primary h-4"></div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Stats Grid */}
        <motion.div
          className="grid grid-cols-2 gap-6"
          initial="hidden"
          animate="visible"
          variants={{
            hidden: {},
            visible: { transition: { staggerChildren: 0.08, delayChildren: 0.15 } },
          }}
        >
          <motion.div
            variants={{ hidden: { opacity: 0, y: 24 }, visible: { opacity: 1, y: 0 } }}
            className="glass-panel rounded-3xl p-8 border border-white/5 relative group hover:border-primary/20 transition-all"
          >
            <div className="flex justify-between items-start mb-8">
              <h3 className="text-[10px] font-bold font-headline tracking-[0.2em] uppercase text-primary/80">Vulnerability Distribution</h3>
              <ShieldAlert className="w-4 h-4 text-primary opacity-40" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              {data.top_vulnerabilities.slice(0, 4).map((vuln, i) => (
                <motion.div
                  key={i}
                  whileHover={{ scale: 1.03 }}
                  className="bg-white/5 p-4 rounded-2xl border border-white/5 hover:bg-white/10 transition-all cursor-pointer"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className={`w-1.5 h-1.5 rounded-full ${vuln.severity === 'critical' ? 'bg-error shadow-[0_0_10px_#ff6e84]' : 'bg-primary shadow-[0_0_10px_#bd9dff]'}`}></span>
                    <span className="text-[9px] font-bold text-slate-500 uppercase">{vuln.severity}</span>
                  </div>
                  <p className="text-xs font-bold text-white truncate">{vuln.title}</p>
                </motion.div>
              ))}
            </div>
          </motion.div>

          <motion.div
            variants={{ hidden: { opacity: 0, y: 24 }, visible: { opacity: 1, y: 0 } }}
            className="glass-panel rounded-3xl p-8 border border-white/5 relative group hover:border-secondary/20 transition-all"
          >
            <div className="flex justify-between items-start mb-8">
              <h3 className="text-[10px] font-bold font-headline tracking-[0.2em] uppercase text-secondary/80">Asset Intelligence</h3>
              <Globe className="w-4 h-4 text-secondary opacity-40" />
            </div>
            <div className="space-y-6">
              <div className="flex justify-between items-end">
                <div>
                  <p className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-1">Total Assets</p>
                  <p className="text-3xl font-black text-white">{data.changes_24h.total_assets ?? 0}</p>
                </div>
                <div className="text-right">
                  <p className="text-[9px] font-bold text-green-400 uppercase flex items-center gap-1">
                    <TrendingUp className="w-3 h-3" />
                    +{data.changes_24h.new_assets} New
                  </p>
                  <p className="text-[8px] text-slate-500 uppercase tracking-tighter">Last 24 Hours</p>
                </div>
              </div>
              <div className="h-1.5 bg-slate-900 rounded-full overflow-hidden flex">
                <div className="h-full bg-primary w-2/3 shadow-[0_0_10px_#bd9dff]"></div>
                <div className="h-full bg-secondary w-1/4 shadow-[0_0_10px_#36bcfd]"></div>
              </div>
              <div className="flex gap-4">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-primary"></div>
                  <span className="text-[9px] font-bold text-slate-400 uppercase">Production</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-secondary"></div>
                  <span className="text-[9px] font-bold text-slate-400 uppercase">Staging</span>
                </div>
              </div>
            </div>
          </motion.div>
        </motion.div>
      </div>

      {/* Right Column - Threat Stream */}
      <div className="col-span-12 lg:col-span-4 space-y-6">
        <div className="glass-panel rounded-3xl border border-white/5 flex flex-col h-full shadow-2xl overflow-hidden bg-slate-950/40">
          <div className="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-white/5">
            <div className="flex items-center gap-3">
              <Activity className="w-4 h-4 text-error animate-pulse" />
              <h3 className="text-xs font-bold tracking-[0.2em] text-white uppercase font-headline">Threat Stream</h3>
            </div>
            <div className="flex gap-1.5">
              <div className="w-1 h-1 rounded-full bg-error"></div>
              <div className="w-1 h-1 rounded-full bg-error opacity-40"></div>
              <div className="w-1 h-1 rounded-full bg-error opacity-20"></div>
            </div>
          </div>

          <div className="flex-1 p-6 space-y-4 overflow-y-auto custom-scrollbar">
            <AnimatePresence initial={false}>
              {data.threat_stream.map((finding, idx) => (
                <motion.div 
                  key={finding.id || idx}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="p-5 rounded-2xl bg-[#0b0e15] border border-white/5 hover:border-primary/20 transition-all cursor-pointer group relative overflow-hidden"
                >
                  <div className="absolute top-0 right-0 p-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Zap className="w-3 h-3 text-primary" />
                  </div>
                  <div className="flex justify-between items-start mb-2">
                    <div className={`px-2 py-0.5 rounded text-[8px] font-black uppercase ${
                      finding.severity === 'critical' ? 'bg-error/20 text-error' : 'bg-primary/20 text-primary'
                    }`}>
                      {finding.severity}
                    </div>
                    <span className="text-[8px] font-mono text-slate-600">{finding.timestamp || 'Just now'}</span>
                  </div>
                  <h4 className="text-xs font-bold text-white mb-1 group-hover:text-primary transition-colors">{finding.title}</h4>
                  <p className="text-[10px] text-slate-500 leading-relaxed line-clamp-2">{finding.description}</p>
                  
                  <div className="mt-4 pt-4 border-t border-white/5 flex items-center gap-4 text-[9px] font-bold uppercase tracking-widest text-slate-600">
                    <div className="flex items-center gap-1">
                      <Server className="w-3 h-3" />
                      {finding.asset_type || 'Internal Node'}
                    </div>
                    <div className="flex items-center gap-1">
                      <Cpu className="w-3 h-3" />
                      v.{finding.version || '2.4.1'}
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>

          <div className="p-4 bg-slate-950/60 border-t border-white/5 text-center">
            <button className="text-[9px] font-bold text-primary uppercase tracking-[0.3em] hover:text-white transition-colors">
              Access Threat Database →
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CommandCenter;
