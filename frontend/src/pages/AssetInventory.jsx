import React, { useEffect, useState } from 'react';
import { assetAPI } from '../api/client';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Database, 
  Server, 
  Globe, 
  Shield, 
  Activity, 
  Search, 
  Filter, 
  ChevronRight, 
  MoreVertical,
  Cpu,
  Network,
  Clock,
  AlertTriangle,
  X
} from 'lucide-react';

const AssetInventory = () => {
  const [assets, setAssets] = useState([]);
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0 });
  const [loading, setLoading] = useState(true);
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [assetsRes, statsRes] = await Promise.all([
          assetAPI.listAssets(),
          assetAPI.getStats()
        ]);
        setAssets(assetsRes.data.items || []);
        setStats(statsRes.data);
      } catch (error) {
        console.error("Failed to fetch assets:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const filteredAssets = assets.filter(asset => 
    asset.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    asset.target.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-secondary">
        <Database className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Scanning Asset Clusters...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 page-entry">
      {/* Header section */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Asset Cluster</h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Real-time inventory of all protected nodes across the global infrastructure.
          </p>
        </div>
        <div className="flex gap-8">
          <div className="text-right">
            <span className="block text-4xl font-black text-secondary font-headline drop-shadow-[0_0_15px_rgba(54,188,253,0.3)]">{stats.total}</span>
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">Total Nodes</span>
          </div>
          <div className="text-right">
            <span className="block text-4xl font-black text-error font-headline drop-shadow-[0_0_15px_rgba(255,110,132,0.3)]">{stats.critical}</span>
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">At Risk</span>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="glass-panel p-4 rounded-2xl border border-white/5 flex items-center justify-between">
        <div className="relative flex-1 max-w-md group">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-secondary transition-colors" />
          <input 
            type="text"
            placeholder="Filter by name, IP, or type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-white/5 border border-white/5 rounded-xl py-2.5 pl-12 pr-4 text-xs focus:ring-1 focus:ring-secondary/40 focus:bg-white/10 transition-all outline-none text-white"
          />
        </div>
        <div className="flex gap-3">
          <button className="flex items-center gap-2 px-4 py-2.5 bg-white/5 hover:bg-white/10 rounded-xl text-[10px] font-bold text-slate-300 transition-all uppercase tracking-widest border border-white/5">
            <Filter className="w-4 h-4" />
            Filters
          </button>
          <button className="flex items-center gap-2 px-4 py-2.5 bg-secondary text-black rounded-xl text-[10px] font-black transition-all uppercase tracking-widest shadow-[0_0_20px_rgba(54,188,253,0.3)] hover:shadow-[0_0_30px_rgba(54,188,253,0.5)] active:scale-95">
            Register Asset
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        <div className="col-span-12 lg:col-span-9">
          <div className="glass-panel rounded-3xl border border-white/5 overflow-hidden shadow-2xl">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-white/5 border-b border-white/5">
                  <th className="px-8 py-5 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase">Node Identity</th>
                  <th className="px-8 py-5 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase">Environment</th>
                  <th className="px-8 py-5 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase">Risk Score</th>
                  <th className="px-8 py-5 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase">Vulns</th>
                  <th className="px-8 py-5 text-[10px] font-bold text-slate-500 tracking-[0.2em] uppercase text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {filteredAssets.map((asset) => (
                  <tr 
                    key={asset.id} 
                    className="group hover:bg-white/5 transition-all cursor-pointer"
                    onClick={() => setSelectedAsset(asset)}
                  >
                    <td className="px-8 py-6">
                      <div className="flex items-center gap-4">
                        <div className={`p-2 rounded-xl ${asset.risk_score > 70 ? 'bg-error/10 text-error' : 'bg-secondary/10 text-secondary'}`}>
                          {asset.asset_type === 'server' ? <Server className="w-5 h-5" /> : <Globe className="w-5 h-5" />}
                        </div>
                        <div>
                          <p className="text-sm font-bold text-white group-hover:text-secondary transition-colors">{asset.name}</p>
                          <p className="text-[9px] font-mono text-slate-500 mt-1 uppercase">{asset.target}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-8 py-6">
                      <span className="px-3 py-1 rounded bg-white/5 text-[10px] font-bold text-slate-400 uppercase border border-white/5">
                        {asset.environment}
                      </span>
                    </td>
                    <td className="px-8 py-6">
                      <div className="flex flex-col gap-1.5">
                        <div className="w-32 h-1 bg-white/5 rounded-full overflow-hidden">
                          <div 
                            className={`h-full ${asset.risk_score > 70 ? 'bg-error' : 'bg-secondary'}`} 
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                        <span className={`text-[9px] font-bold uppercase tracking-widest ${asset.risk_score > 70 ? 'text-error' : 'text-secondary'}`}>
                          {asset.risk_score}% Risk
                        </span>
                      </div>
                    </td>
                    <td className="px-8 py-6">
                      <div className="flex items-center gap-2">
                        <Shield className="w-3.5 h-3.5 text-error" />
                        <span className="text-sm font-bold text-white">{asset.vulnerability_count || 0}</span>
                      </div>
                    </td>
                    <td className="px-8 py-6 text-right">
                      <div className="flex items-center justify-end gap-2 text-green-400">
                        <Activity className="w-3.5 h-3.5 animate-pulse" />
                        <span className="text-[10px] font-bold uppercase tracking-widest">Active</span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="col-span-12 lg:col-span-3 space-y-6">
          <div className="glass-panel p-8 rounded-3xl border border-white/5">
            <h3 className="text-[10px] font-bold tracking-[0.2em] text-slate-500 mb-8 uppercase">Cluster Distribution</h3>
            <div className="space-y-6">
              {[
                { label: 'Cloud Nodes', val: 64, color: 'bg-primary' },
                { label: 'On-Premise', val: 28, color: 'bg-secondary' },
                { label: 'Edge Devices', val: 8, color: 'bg-tertiary' }
              ].map(item => (
                <div key={item.label}>
                  <div className="flex justify-between items-center mb-2">
                    <span className="text-[10px] font-bold text-white/60">{item.label}</span>
                    <span className="text-[10px] font-bold text-white">{item.val}%</span>
                  </div>
                  <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                    <div className={`${item.color} h-full`} style={{ width: `${item.val}%` }}></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-panel p-8 rounded-3xl border border-secondary/20 relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-6 opacity-5 group-hover:opacity-20 transition-opacity">
               <Network className="w-16 h-16 text-secondary" />
            </div>
            <h3 className="font-headline font-bold text-white mb-4 flex items-center gap-3">
               <Globe className="w-4 h-4 text-secondary" />
               GEO VISUAL
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed relative z-10">
               Nodes are currently active in <span className="text-secondary font-bold">12 global regions</span>. 
               Traffic spike detected in US-East clusters.
            </p>
            <button className="mt-6 text-[10px] font-bold tracking-[0.3em] text-secondary hover:text-white transition-all flex items-center gap-2 uppercase relative z-10">
               OPEN NETWORK MAP <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {selectedAsset && (
          <div className="fixed inset-0 z-[60] flex justify-end">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm cursor-pointer"
              onClick={() => setSelectedAsset(null)}
            />
            <motion.div 
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="w-full sm:w-[600px] h-full bg-slate-950/90 backdrop-blur-3xl border-l border-white/10 relative z-10 shadow-[-50px_0_100px_rgba(0,0,0,0.5)] flex flex-col"
            >
              <div className="p-10 border-b border-white/5 flex justify-between items-start bg-white/5">
                <div>
                  <div className="flex items-center gap-4 mb-4">
                    <span className="text-secondary font-mono text-sm font-bold tracking-[0.2em]">NODE_{selectedAsset.id.slice(0, 8).toUpperCase()}</span>
                    <span className="px-3 py-1 rounded text-[9px] font-black bg-secondary/20 text-secondary uppercase tracking-widest border border-secondary/30">Verified Node</span>
                  </div>
                  <h3 className="text-3xl font-headline font-bold text-white leading-tight mb-4">
                    {selectedAsset.name}
                  </h3>
                  <div className="flex gap-4">
                    <div className="flex items-center gap-2 text-[10px] font-bold text-slate-500 uppercase">
                      <Network className="w-3.5 h-3.5" />
                      {selectedAsset.target}
                    </div>
                    <div className="flex items-center gap-2 text-[10px] font-bold text-slate-500 uppercase">
                      <Cpu className="w-3.5 h-3.5" />
                      {selectedAsset.asset_type.toUpperCase()}
                    </div>
                  </div>
                </div>
                <button onClick={() => setSelectedAsset(null)} className="p-3 hover:bg-white/10 rounded-2xl transition-all">
                  <X className="w-6 h-6 text-slate-500" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-10 custom-scrollbar space-y-12">
                <section className="grid grid-cols-2 gap-6">
                  <div className="p-6 rounded-3xl bg-white/5 border border-white/5">
                    <h5 className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-3">Risk Assessment</h5>
                    <div className="flex items-end gap-2">
                      <span className="text-4xl font-black text-white font-headline">{selectedAsset.risk_score}</span>
                      <span className="text-xs font-bold text-slate-500 mb-1">/ 100</span>
                    </div>
                  </div>
                  <div className="p-6 rounded-3xl bg-white/5 border border-white/5">
                    <h5 className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mb-3">Vulnerabilities</h5>
                    <div className="flex items-end gap-2 text-error">
                      <Shield className="w-8 h-8 mb-1" />
                      <span className="text-4xl font-black font-headline">{selectedAsset.vulnerability_count || 0}</span>
                    </div>
                  </div>
                </section>

                <section>
                  <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em] mb-6">Service Inventory</h4>
                  <div className="space-y-3">
                    {[
                      { port: 443, service: 'HTTPS', status: 'Active', protocol: 'TCP' },
                      { port: 22, service: 'SSH', status: 'Restricted', protocol: 'TCP' },
                      { port: 80, service: 'HTTP', status: 'Filtered', protocol: 'TCP' }
                    ].map(s => (
                      <div key={s.port} className="flex items-center justify-between p-4 rounded-2xl bg-white/5 border border-white/5 group hover:border-secondary/20 transition-all">
                        <div className="flex items-center gap-4">
                          <span className="text-xs font-mono font-bold text-secondary">{s.port}</span>
                          <span className="text-sm font-bold text-white">{s.service}</span>
                        </div>
                        <div className="flex items-center gap-4">
                          <span className="text-[10px] font-mono text-slate-500">{s.protocol}</span>
                          <span className="text-[10px] font-bold text-green-400 uppercase tracking-widest">{s.status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section>
                  <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em] mb-6">Last Activity</h4>
                  <div className="flex items-center gap-4 p-6 rounded-3xl bg-white/5 border border-white/5">
                    <Clock className="w-5 h-5 text-slate-500" />
                    <div>
                      <p className="text-sm text-white font-bold">Comprehensive Scan Completed</p>
                      <p className="text-xs text-slate-500 mt-1">2 hours ago • Duration: 14m 22s</p>
                    </div>
                  </div>
                </section>
              </div>

              <div className="p-8 bg-slate-950/60 border-t border-white/5 flex gap-4">
                <button className="flex-1 py-4 rounded-2xl bg-secondary text-black font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(54,188,253,0.3)] hover:shadow-[0_0_50px_rgba(54,188,253,0.6)] transition-all active:scale-95">
                  INITIATE RE-SCAN
                </button>
                <button className="p-4 rounded-2xl bg-white/5 border border-white/10 text-slate-400 hover:text-white transition-all">
                  <MoreVertical className="w-5 h-5" />
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default AssetInventory;
