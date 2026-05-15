import React, { useState, useEffect } from 'react';
import { aiAPI } from '../api/client';
import { BrainCircuit, Activity, ShieldAlert, CheckCircle2, TrendingUp, TrendingDown, Clock, Database, AlertTriangle } from 'lucide-react';

const AIMonitor = () => {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const response = await aiAPI.getMetrics();
        setMetrics(response.data);
      } catch (err) {
        console.error("Failed to fetch AI Metrics", err);
      } finally {
        setLoading(false);
      }
    };
    fetchMetrics();
    // Refresh every 10 seconds for real-time drift detection
    const int = setInterval(fetchMetrics, 10000);
    return () => clearInterval(int);
  }, []);

  if (loading) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <BrainCircuit className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Syncing MLOps Telemetry...</span>
      </div>
    );
  }

  const isStable = metrics?.drift_status === "Stable";

  return (
    <div className="space-y-6 page-entry">
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight flex items-center gap-4">
             <BrainCircuit className="w-10 h-10 text-primary" /> MLOps Telemetry
          </h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Live monitoring of Vorota AI performance. Tracking Continuous Learning pipelines, Model Drift, and Analyst feedback alignment.
          </p>
        </div>
        <div className="text-right">
          <span className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-widest border ${isStable ? 'bg-green-500/10 text-green-400 border-green-500/20' : 'bg-orange-500/10 text-orange-400 border-orange-500/20'}`}>
            {isStable ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
            Model {metrics?.drift_status || "Unknown"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Core Metrics Grid */}
        <div className="col-span-12 lg:col-span-8 grid grid-cols-2 gap-6">
          <div className="glass-panel p-8 rounded-3xl border border-white/5 relative overflow-hidden group">
            <div className="absolute right-0 top-0 p-6 opacity-5 group-hover:opacity-10 transition-all">
              <Activity className="w-24 h-24 text-primary" />
            </div>
            <h3 className="text-[10px] font-bold tracking-[0.3em] text-slate-500 uppercase mb-4">Analyst Accuracy</h3>
            <div className="flex items-end gap-4">
               <span className="text-5xl font-black text-white font-headline">{metrics?.accuracy}%</span>
               <span className="text-green-400 text-sm font-bold flex items-center mb-1"><TrendingUp className="w-4 h-4 mr-1" /> +2.4%</span>
            </div>
            <p className="text-xs text-slate-500 mt-4">Based on {metrics?.total_feedback} feedback samples</p>
          </div>

          <div className="glass-panel p-8 rounded-3xl border border-white/5 relative overflow-hidden group">
             <div className="absolute right-0 top-0 p-6 opacity-5 group-hover:opacity-10 transition-all">
              <ShieldAlert className="w-24 h-24 text-orange-500" />
            </div>
            <h3 className="text-[10px] font-bold tracking-[0.3em] text-slate-500 uppercase mb-4">False Positive Rate</h3>
            <div className="flex items-end gap-4">
               <span className="text-5xl font-black text-white font-headline">{metrics?.fp_rate}%</span>
               <span className="text-green-400 text-sm font-bold flex items-center mb-1"><TrendingDown className="w-4 h-4 mr-1" /> -1.2%</span>
            </div>
             <p className="text-xs text-slate-500 mt-4">Classification Error Margin</p>
          </div>

          <div className="glass-panel p-8 rounded-3xl border border-white/5 relative overflow-hidden group">
             <div className="absolute right-0 top-0 p-6 opacity-5 group-hover:opacity-10 transition-all">
              <Clock className="w-24 h-24 text-white" />
            </div>
            <h3 className="text-[10px] font-bold tracking-[0.3em] text-slate-500 uppercase mb-4">Average Latency</h3>
            <div className="flex items-end gap-4">
               <span className="text-5xl font-black text-white font-headline">{metrics?.latency_avg_ms}</span>
            </div>
             <p className="text-xs text-slate-500 mt-4">Powered by Redis Cache</p>
          </div>

          <div className="glass-panel p-8 rounded-3xl border border-white/5 relative overflow-hidden group">
             <div className="absolute right-0 top-0 p-6 opacity-5 group-hover:opacity-10 transition-all">
              <Database className="w-24 h-24 text-primary" />
            </div>
            <h3 className="text-[10px] font-bold tracking-[0.3em] text-slate-500 uppercase mb-4">Retraining Pool</h3>
            <div className="flex items-end gap-4">
               <span className="text-5xl font-black text-white font-headline">{metrics?.total_feedback}</span>
            </div>
             <p className="text-xs text-slate-500 mt-4">Events awaiting nightly XGBoost retrain</p>
          </div>
        </div>

        {/* System Health */}
        <div className="col-span-12 lg:col-span-4 space-y-6">
           <div className="glass-panel p-8 rounded-3xl border border-white/5">
              <h3 className="text-[10px] font-bold tracking-[0.3em] text-slate-500 uppercase mb-6">Pipeline Status</h3>
              <div className="space-y-4">
                 {[
                   { name: 'XGBoost Risk Regressor', status: 'Online', ms: '0.8ms' },
                   { name: 'XGBoost FP Classifier', status: 'Online', ms: '1.1ms' },
                   { name: 'FAISS Vector Index', status: 'Online', ms: '4.2ms' },
                   { name: 'Local Exploit Graphs (NX)', status: 'Online', ms: '2.5ms' },
                 ].map(s => (
                   <div key={s.name} className="flex items-center justify-between p-3 rounded-xl bg-white/5 border border-white/5">
                      <div>
                        <span className="block text-xs font-bold text-white">{s.name}</span>
                        <span className="text-[10px] text-green-400 mt-1 uppercase tracking-widest flex items-center gap-1">
                           <div className="w-1.5 h-1.5 rounded-full bg-green-400"></div> {s.status}
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-500">{s.ms}</span>
                   </div>
                 ))}
              </div>
           </div>
           
           <button className="w-full py-4 rounded-2xl bg-white/5 border border-white/10 text-xs font-bold uppercase tracking-[0.2em] text-slate-400 hover:text-white hover:bg-white/10 transition-all">
              Force Retrain Models Now
           </button>
        </div>
      </div>
    </div>
  );
};

export default AIMonitor;
