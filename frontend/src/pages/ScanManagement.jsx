import React, { useEffect, useState } from 'react';
import { scanAPI } from '../api/client';
import useRBAC from '../hooks/useRBAC';
import { 
  Activity, 
  Play, 
  Plus, 
  Search, 
  Filter, 
  MoreVertical, 
  CheckCircle2, 
  Clock, 
  AlertCircle, 
  ChevronRight, 
  Zap,
  Calendar,
  Target,
  Shield,
  Loader2,
  X,
  PlayCircle,
  PauseCircle,
  StopCircle,
  RefreshCw
} from 'lucide-react';
import { motion as _motion, AnimatePresence } from 'framer-motion';

const ScanManagement = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [createError, setCreateError] = useState(null);
  const [activeScanStats, setActiveScanStats] = useState({ findings: 0 });
  const [newScan, setNewScan] = useState({
    name: '',
    target_raw: '',
    scan_type: 'full',
    schedule: 'manual'
  });
  const { isAnalyst } = useRBAC();

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, []);

  const fetchScans = async () => {
    try {
      const response = await scanAPI.listScans();
      const items = response.data.items || response.data || [];
      setScans(items);
      // Fetch findings count for active scan
      const active = items.find(s => s.status === 'running' || s.status === 'queued');
      if (active) {
        try {
          const findingsResp = await scanAPI.getScanFindings(active.id);
          const findingsData = findingsResp.data;
          const count = Array.isArray(findingsData) ? findingsData.length
            : findingsData.total || findingsData.findings?.length || 0;
          setActiveScanStats({ findings: count });
        } catch (err) {
          console.warn('Could not fetch findings count:', err?.message);
        }
      }
    } catch (error) {
      console.error("Failed to fetch scans:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleCancelScan = async (scanId) => {
    try {
      await scanAPI.cancelScan(scanId);
      fetchScans();
    } catch (err) {
      console.error('Cancel scan failed:', err);
    }
  };

  const handleCreateScan = async (e) => {
    e.preventDefault();
    setCreateError(null);
    try {
      await scanAPI.createScan(newScan);
      setIsModalOpen(false);
      setNewScan({ name: '', target_raw: '', scan_type: 'full', schedule: 'manual' });
      fetchScans();
    } catch (error) {
      setCreateError(error.response?.data?.detail || 'Failed to create scan. Check target format.');
    }
  };

  const activeScan = scans.find(s => s.status === 'running' || s.status === 'queued');

  if (loading && scans.length === 0) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <Activity className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Synchronizing Scan Fleet...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 page-entry">
      {/* Header section */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Scan Fleet</h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Orchestrate and monitor automated vulnerability assessments across the global node infrastructure.
          </p>
        </div>
        <div className="flex gap-8">
          <div className="text-right">
            <span className="block text-4xl font-black text-primary font-headline drop-shadow-[0_0_15px_rgba(189,157,255,0.3)]">
              {scans.filter(s => s.status === 'completed').length}
            </span>
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">Audit Success</span>
          </div>
          <div className="text-right">
            <span className="block text-4xl font-black text-secondary font-headline drop-shadow-[0_0_15px_rgba(54,188,253,0.3)]">
              {scans.filter(s => s.status === 'running').length}
            </span>
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">Active Now</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Active Scan Display */}
        <div className="col-span-12 lg:col-span-8">
          <div className="glass-panel rounded-3xl p-10 min-h-[400px] flex flex-col justify-center relative group overflow-hidden bg-slate-950/40">
            <div className="hud-bracket bracket-tl"></div>
            <div className="hud-bracket bracket-tr"></div>
            <div className="hud-bracket bracket-bl"></div>
            <div className="hud-bracket bracket-br"></div>
            
            {activeScan ? (
              <div className="space-y-12">
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-3 mb-4">
                      <span className="px-3 py-1 rounded-full bg-secondary/10 text-secondary text-[9px] font-black uppercase tracking-widest border border-secondary/20 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 rounded-full bg-secondary animate-pulse"></span>
                        {activeScan.status.toUpperCase()}
                      </span>
                      <span className="text-[9px] font-mono text-slate-500 uppercase tracking-widest">ID: {activeScan.id.slice(0, 8)}</span>
                    </div>
                    <h3 className="text-4xl font-headline font-bold text-white leading-tight">
                      {activeScan.name}
                    </h3>
                    <p className="text-slate-400 text-sm mt-2 flex items-center gap-2">
                      <Target className="w-4 h-4" />
                      Targeting Cluster: <span className="text-white font-bold">{activeScan.target_raw || 'Global Edge'}</span>
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="text-6xl font-black text-secondary font-headline drop-shadow-[0_0_20px_rgba(54,188,253,0.4)]">
                      {activeScan.progress || 74}%
                    </div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mt-1">Audit Saturation</span>
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="h-2 w-full bg-slate-900 rounded-full overflow-hidden relative border border-white/5">
                    <div 
                      className="h-full bg-secondary shadow-[0_0_20px_rgba(54,188,253,0.6)] transition-all duration-1000" 
                      style={{ width: `${activeScan.progress || 74}%` }}
                    />
                  </div>
                  <div className="grid grid-cols-3 gap-8">
                    <div className="flex items-center gap-4">
                      <div className="p-2.5 rounded-xl bg-white/5 text-slate-400">
                        <Shield className="w-5 h-5" />
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-0.5">Vulns Found</p>
                        <p className="text-lg font-bold text-white">{activeScanStats.findings}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="p-2.5 rounded-xl bg-white/5 text-slate-400">
                        <Activity className="w-5 h-5" />
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-0.5">Scan Type</p>
                        <p className="text-lg font-bold text-white capitalize">{activeScan.scan_type || 'full'}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="p-2.5 rounded-xl bg-white/5 text-slate-400">
                        <Clock className="w-5 h-5" />
                      </div>
                      <div>
                        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-0.5">Started</p>
                        <p className="text-lg font-bold text-white">
                          {activeScan.created_at ? new Date(activeScan.created_at).toLocaleTimeString() : '—'}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex gap-4 pt-4">
                  <button
                    onClick={() => handleCancelScan(activeScan.id)}
                    className="flex-1 py-4 rounded-2xl bg-white/5 border border-white/10 text-white font-bold text-xs uppercase tracking-widest hover:bg-white/10 transition-all flex items-center justify-center gap-3"
                  >
                    <PauseCircle className="w-5 h-5" />
                    Suspend Audit
                  </button>
                  <button
                    onClick={() => handleCancelScan(activeScan.id)}
                    className="flex-1 py-4 rounded-2xl bg-error/10 border border-error/20 text-error font-bold text-xs uppercase tracking-widest hover:bg-error/20 transition-all flex items-center justify-center gap-3"
                  >
                    <StopCircle className="w-5 h-5" />
                    Terminate
                  </button>
                </div>
              </div>
            ) : (
              <div className="text-center py-20">
                <div className="w-20 h-20 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-all">
                  <Play className="w-8 h-8 text-slate-500 group-hover:text-primary transition-colors" />
                </div>
                <h3 className="text-2xl font-bold text-white mb-2">Fleet Idle</h3>
                <p className="text-slate-500 text-sm max-w-md mx-auto mb-10">
                  No active audits are currently running. Initiate a new scan or schedule a periodic assessment.
                </p>
                {isAnalyst && (
                  <button 
                    onClick={() => setIsModalOpen(true)}
                    className="px-8 py-4 bg-primary text-black rounded-2xl font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(189,157,255,0.3)] hover:shadow-[0_0_50px_rgba(189,157,255,0.6)] transition-all active:scale-95"
                  >
                    Initiate Audit
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Scan History Table */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="glass-panel rounded-3xl border border-white/5 flex flex-col h-full bg-slate-950/40 overflow-hidden">
            <div className="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-white/5">
              <div className="flex items-center gap-3">
                <Clock className="w-4 h-4 text-primary" />
                <h3 className="text-xs font-bold tracking-[0.2em] text-white uppercase font-headline">Audit Log</h3>
              </div>
              <button onClick={fetchScans} className="p-2 hover:bg-white/5 rounded-lg text-slate-500 transition-all">
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="flex-1 p-6 space-y-4 overflow-y-auto custom-scrollbar">
              {scans.slice(0, 10).map((scan) => (
                <div key={scan.id} className="p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-primary/20 transition-all cursor-pointer group">
                  <div className="flex justify-between items-start mb-2">
                    <span className={`px-2 py-0.5 rounded text-[8px] font-black uppercase ${
                      scan.status === 'completed' ? 'bg-green-500/20 text-green-400' :
                      scan.status === 'failed' ? 'bg-error/20 text-error' :
                      'bg-slate-500/20 text-slate-400'
                    }`}>
                      {scan.status}
                    </span>
                    <span className="text-[8px] font-mono text-slate-600">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <h4 className="text-xs font-bold text-white mb-1 group-hover:text-primary transition-colors truncate">{scan.name}</h4>
                  <div className="flex items-center justify-between mt-3">
                    <div className="flex items-center gap-2 text-[9px] text-slate-500 font-bold uppercase tracking-widest">
                      <Target className="w-3 h-3" />
                      {scan.target_raw?.slice(0, 15) || 'Global'}
                    </div>
                    {scan.security_score !== null && scan.security_score !== undefined && (
                      <span className={`text-[10px] font-black px-2 py-0.5 rounded ${
                        scan.security_score >= 81 ? 'bg-green-500/10 text-green-400' :
                        scan.security_score >= 61 ? 'bg-yellow-500/10 text-yellow-400' :
                        scan.security_score >= 41 ? 'bg-orange-500/10 text-orange-400' :
                        'bg-red-500/10 text-red-400'
                      }`}>
                        {scan.security_score}/100
                      </span>
                    )}
                    <ChevronRight className="w-3 h-3 text-slate-700 group-hover:text-primary transition-colors" />
                  </div>
                </div>
              ))}
            </div>
            
            <div className="p-4 bg-slate-950/60 border-t border-white/5 text-center">
              <button className="text-[9px] font-bold text-primary uppercase tracking-[0.3em] hover:text-white transition-colors">
                View All History →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Create Scan Modal */}
      <AnimatePresence>
        {isModalOpen && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-6">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/80 backdrop-blur-md" 
              onClick={() => setIsModalOpen(false)} 
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0, y: 20 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.9, opacity: 0, y: 20 }}
              className="glass-panel w-full max-w-2xl rounded-3xl border border-white/10 shadow-2xl relative z-10 overflow-hidden bg-slate-950/90"
            >
              <div className="p-8 border-b border-white/5 bg-white/5 flex justify-between items-center">
                <div className="flex items-center gap-4">
                  <div className="p-2.5 rounded-xl bg-primary/10 text-primary">
                    <Plus className="w-6 h-6" />
                  </div>
                  <h3 className="text-2xl font-headline font-bold text-white uppercase tracking-tight">Initiate Sovereign Audit</h3>
                </div>
                <button onClick={() => setIsModalOpen(false)} className="p-2 hover:bg-white/10 rounded-xl transition-all">
                  <X className="w-6 h-6 text-slate-500" />
                </button>
              </div>

              <form onSubmit={handleCreateScan} className="p-8 space-y-8">
                {createError && (
                  <div className="px-5 py-3 rounded-xl bg-error/10 border border-error/20 text-error text-xs">
                    {createError}
                  </div>
                )}
                <div className="grid grid-cols-2 gap-8">
                  <div className="space-y-3">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Audit Designation</label>
                    <input 
                      type="text"
                      required
                      placeholder="e.g. Q4 PERIMETER_SCAN"
                      value={newScan.name}
                      onChange={(e) => setNewScan({...newScan, name: e.target.value})}
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm text-white focus:ring-1 focus:ring-primary/50 outline-none"
                    />
                  </div>
                  <div className="space-y-3">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Target Cluster / IP</label>
                    <input 
                      type="text"
                      required
                      placeholder="IP, domain, URL, git repo, path, or image:tag"
                      value={newScan.target_raw}
                      onChange={(e) => setNewScan({...newScan, target_raw: e.target.value})}
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm text-white focus:ring-1 focus:ring-primary/50 outline-none"
                    />
                    <p className="text-[9px] text-slate-600 ml-1 mt-1">Examples: 192.168.1.1, example.com, https://site.com, github.com/user/repo, ./project, nginx:latest</p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-8">
                  <div className="space-y-3">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Scan Type</label>
                    <div className="grid grid-cols-3 gap-2">
                      {['full', 'network', 'code', 'web', 'container'].map(t => (
                        <button 
                          key={t}
                          type="button"
                          onClick={() => setNewScan({...newScan, scan_type: t})}
                          className={`py-4 rounded-2xl text-[10px] font-bold uppercase tracking-widest border transition-all ${
                            newScan.scan_type === t ? 'bg-primary/10 border-primary text-primary' : 'bg-white/5 border-transparent text-slate-500 hover:text-white'
                          }`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-3">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Execution Schedule</label>
                    <div className="grid grid-cols-2 gap-2">
                      {['manual', 'periodic'].map(s => (
                        <button 
                          key={s}
                          type="button"
                          onClick={() => setNewScan({...newScan, schedule: s})}
                          className={`py-4 rounded-2xl text-[10px] font-bold uppercase tracking-widest border transition-all ${
                            newScan.schedule === s ? 'bg-secondary/10 border-secondary text-secondary' : 'bg-white/5 border-transparent text-slate-500 hover:text-white'
                          }`}
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {newScan.schedule === 'periodic' && (
                  <div className="p-6 rounded-3xl bg-secondary/5 border border-secondary/20 flex items-center gap-6 animate-entry">
                    <Calendar className="w-8 h-8 text-secondary" />
                    <div className="flex-1">
                      <p className="text-xs font-bold text-white mb-1 uppercase tracking-widest">Cron Configuration</p>
                      <p className="text-xs text-slate-400">Scan will execute every 24 hours at 00:00 UTC.</p>
                    </div>
                    <button type="button" className="text-[10px] font-bold text-secondary uppercase tracking-widest hover:text-white">Modify Schedule</button>
                  </div>
                )}

                <div className="pt-4 flex gap-4">
                  <button 
                    type="button"
                    onClick={() => setIsModalOpen(false)}
                    className="flex-1 py-5 rounded-2xl bg-white/5 border border-white/10 text-slate-500 font-bold text-xs uppercase tracking-widest hover:bg-white/10 hover:text-white transition-all"
                  >
                    Cancel
                  </button>
                  <button 
                    type="submit"
                    className="flex-1 py-5 rounded-2xl bg-primary text-black font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(189,157,255,0.3)] hover:shadow-[0_0_50px_rgba(189,157,255,0.6)] transition-all active:scale-95 flex items-center justify-center gap-3"
                  >
                    <PlayCircle className="w-5 h-5" />
                    Deploy Audit
                  </button>
                </div>
              </form>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default ScanManagement;