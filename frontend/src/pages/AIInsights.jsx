import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  BrainCircuit, 
  ShieldAlert, 
  Zap, 
  Target, 
  Search, 
  TrendingUp, 
  ShieldCheck, 
  AlertTriangle,
  Cpu,
  Globe,
  Activity,
  ChevronRight,
  Info,
  Layers,
  Sparkles,
  ScanSearch
} from 'lucide-react';
import { dashboardAPI } from '../api/client';

const AIInsights = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await dashboardAPI.getAIInsights();
        setData(response.data);
      } catch (error) {
        console.error("Failed to fetch AI insights:", error);
        setData({ has_data: false, message: "Could not connect to backend." });
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <BrainCircuit className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Loading Intelligence Data...</span>
      </div>
    );
  }

  // ── Empty State — no scan data yet ──────────────────────────────────────
  if (!data || !data.has_data) {
    return (
      <div className="space-y-8 page-entry">
        <div className="flex justify-between items-end mb-8">
          <div>
            <div className="flex items-center gap-4 mb-2">
              <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Sovereign Intelligence</h2>
            </div>
            <p className="text-slate-400 max-w-2xl text-sm leading-relaxed">
              Neural pipeline ready. Awaiting scan data to generate intelligence.
            </p>
          </div>
        </div>
        <div className="flex flex-col items-center justify-center py-24 glass-panel rounded-3xl border border-white/5 bg-slate-950/40">
          <ScanSearch className="w-16 h-16 text-slate-600 mb-6" />
          <h3 className="text-xl font-bold text-white mb-3">No Intelligence Data Available</h3>
          <p className="text-slate-400 text-sm max-w-md text-center leading-relaxed">
            {data?.message || "Run a security scan to generate AI-powered intelligence. The engine will analyze real findings to build exploit chains, threat vectors, and remediation plans."}
          </p>
          <a href="/scans" className="mt-8 px-8 py-3 rounded-2xl bg-primary text-black font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(189,157,255,0.3)] hover:shadow-[0_0_50px_rgba(189,157,255,0.5)] transition-all active:scale-95">
            Initiate Scan
          </a>
        </div>
      </div>
    );
  }

  // ── Real Data Rendering ─────────────────────────────────────────────────
  const {
    summary,
    exploit_chain = [],
    remediation_plan = [],
    neural_stream = [],
    threat_vector_strength = 0,
    remediation_readiness = 0,
    prediction_confidence = 0,
    findings_total = 0,
    findings_critical = 0,
    findings_high = 0,
  } = data;

  return (
    <div className="space-y-8 page-entry">
      {/* Header section */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <div className="flex items-center gap-4 mb-2">
            <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Sovereign Intelligence</h2>
            <div className="px-3 py-1 rounded-full bg-primary/10 border border-primary/30 text-[9px] font-black text-primary uppercase tracking-[0.2em] animate-pulse">
              Live Analysis
            </div>
          </div>
          <p className="text-slate-400 max-w-2xl text-sm leading-relaxed">
            Neural pipeline processing {findings_total} finding{findings_total !== 1 ? 's' : ''} to predict and prevent multi-vector exploitation chains.
          </p>
        </div>
        <div className="flex gap-8">
          <div className="text-right">
            <span className="block text-4xl font-black text-primary font-headline drop-shadow-[0_0_15px_rgba(189,157,255,0.3)]">{prediction_confidence}%</span>
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">Prediction Confidence</span>
          </div>
          <div className="text-right">
            <span className="block text-4xl font-black text-secondary font-headline drop-shadow-[0_0_15px_rgba(54,188,253,0.3)]">{findings_total}</span>
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest mt-1">Findings Analyzed</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Main AI Summary */}
        <div className="col-span-12 lg:col-span-8 space-y-6">
          <div className="glass-panel rounded-[40px] p-12 border border-primary/20 relative overflow-hidden group shadow-2xl bg-slate-950/40">
            <div className="absolute top-0 right-0 p-10 opacity-5 group-hover:opacity-20 transition-opacity">
               <BrainCircuit className="w-32 h-32 text-primary" />
            </div>
            
            <div className="relative z-10 max-w-2xl">
              <div className="flex items-center gap-3 mb-8">
                <Sparkles className="w-5 h-5 text-primary" />
                <h3 className="text-xs font-bold text-white uppercase tracking-[0.4em] font-headline">Executive Intelligence Summary</h3>
              </div>
              
              {summary ? (
                <>
                  <h4 className="text-3xl font-bold text-white mb-6 leading-tight">
                    {summary.title}
                  </h4>
                  <p className="text-slate-400 text-lg leading-relaxed mb-10 italic">
                    "{summary.text}"
                  </p>
                </>
              ) : (
                <p className="text-slate-400 text-lg leading-relaxed mb-10">
                  Awaiting scan results to generate executive summary.
                </p>
              )}
              
              <div className="grid grid-cols-2 gap-12">
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Threat Vector Strength</span>
                    <span className="text-[10px] font-bold text-error">{threat_vector_strength}%</span>
                  </div>
                  <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full bg-error shadow-[0_0_10px_#ff6e84] transition-all duration-1000" style={{ width: `${threat_vector_strength}%` }}></div>
                  </div>
                </div>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Remediation Readiness</span>
                    <span className="text-[10px] font-bold text-secondary">{remediation_readiness}%</span>
                  </div>
                  <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                    <div className="h-full bg-secondary shadow-[0_0_10px_#36bcfd] transition-all duration-1000" style={{ width: `${remediation_readiness}%` }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-6">
            {/* Exploit Chain — from real findings */}
            <div className="glass-panel rounded-3xl p-8 border border-white/5 bg-white/5">
              <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                <Target className="w-4 h-4 text-primary" />
                Exploit Chain Analysis
              </h4>
              <div className="space-y-6">
                {exploit_chain.length > 0 ? exploit_chain.map((s, i) => (
                  <div key={i} className="flex gap-4 relative">
                    {i < exploit_chain.length - 1 && <div className="absolute left-3.5 top-8 bottom-[-24px] w-0.5 bg-white/5"></div>}
                    <div className={`w-7 h-7 rounded-full flex items-center justify-center text-[9px] font-black border ${
                      s.status === 'DETECTED' ? 'bg-error text-white border-error shadow-[0_0_10px_#ff6e84]' :
                      s.status === 'PREDICTED' ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40 shadow-[0_0_10px_rgba(234,179,8,0.2)]' :
                      'bg-primary/20 text-primary border-primary/40'
                    }`}>
                      {s.step}
                    </div>
                    <div>
                      <p className="text-xs font-bold text-white mb-0.5">{s.label}</p>
                      <p className="text-[10px] text-slate-500">{s.desc}</p>
                    </div>
                  </div>
                )) : (
                  <p className="text-xs text-slate-500 italic">No critical/high findings to build exploit chains from.</p>
                )}
              </div>
            </div>

            {/* Remediation Blueprint — from real findings */}
            <div className="glass-panel rounded-3xl p-8 border border-white/5 bg-white/5 flex flex-col">
              <h4 className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.3em] mb-6 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-secondary" />
                Remediation Blueprint
              </h4>
              <div className="flex-1 space-y-4">
                {remediation_plan.length > 0 ? remediation_plan.map((item, i) => (
                  <div key={i} className={`p-4 rounded-2xl flex items-center gap-4 ${
                    item.priority === 'high' 
                      ? 'bg-secondary/10 border border-secondary/20' 
                      : item.priority === 'medium'
                      ? 'bg-yellow-400/10 border border-yellow-400/20'
                      : 'bg-white/5 border border-white/5'
                  }`}>
                    <div className={`w-2 h-2 rounded-full ${
                      item.priority === 'high' ? 'bg-secondary' : 
                      item.priority === 'medium' ? 'bg-yellow-400' : 'bg-slate-600'
                    }`}></div>
                    <span className={`text-[11px] font-bold ${
                      item.priority === 'high' ? 'text-white' : 
                      item.priority === 'medium' ? 'text-yellow-200' : 'text-slate-400'
                    }`}>
                      {item.action}
                    </span>
                  </div>
                )) : (
                  <p className="text-xs text-slate-500 italic">No remediation actions available yet.</p>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Neural Stream Panel — from real scan/finding activity */}
        <div className="col-span-12 lg:col-span-4 flex flex-col gap-6">
          <div className="glass-panel rounded-3xl border border-white/5 flex flex-col h-full bg-slate-950/40 overflow-hidden shadow-2xl">
            <div className="px-8 py-6 border-b border-white/5 flex justify-between items-center bg-white/5">
              <div className="flex items-center gap-3">
                <Activity className="w-4 h-4 text-primary animate-pulse" />
                <h3 className="text-xs font-bold tracking-[0.2em] text-white uppercase font-headline">Intelligence Stream</h3>
              </div>
              <div className="flex gap-1">
                <div className="w-1 h-1 rounded-full bg-primary"></div>
                <div className="w-1 h-1 rounded-full bg-primary opacity-40"></div>
                <div className="w-1 h-1 rounded-full bg-primary opacity-20"></div>
              </div>
            </div>

            <div className="flex-1 p-8 font-mono text-[11px] space-y-4 overflow-y-auto custom-scrollbar">
              {neural_stream.length > 0 ? neural_stream.map((entry, i) => (
                <div key={i} className="flex gap-4">
                  <span className="text-primary/60 shrink-0">[{entry.time}]</span>
                  <span className={`leading-relaxed ${
                    entry.level === 'critical' ? 'text-error font-bold' :
                    entry.level === 'warning' ? 'text-yellow-400' :
                    'text-slate-400'
                  }`}>
                    {entry.text}
                  </span>
                </div>
              )) : (
                <div className="flex gap-4">
                  <span className="text-primary/60 shrink-0">[--:--:--]</span>
                  <span className="text-slate-500 italic">Awaiting scan activity...</span>
                </div>
              )}
              
              <div className="pt-8 border-t border-white/5">
                <div className="flex justify-between items-center mb-4">
                  <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Analysis Load</span>
                  <span className="text-[10px] font-bold text-primary">{Math.min(99, findings_total * 5 + 10)}%</span>
                </div>
                <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                  <div className="h-full bg-primary shadow-[0_0_10px_#bd9dff] transition-all duration-1000" style={{ width: `${Math.min(99, findings_total * 5 + 10)}%` }}></div>
                </div>
              </div>
            </div>

            <div className="p-6 bg-slate-950/60 border-t border-white/5 text-center">
              <span className="text-[9px] font-bold text-slate-600 uppercase tracking-[0.3em]">
                {findings_critical > 0 ? `⚠ ${findings_critical} CRITICAL • ${findings_high} HIGH` : `${findings_total} FINDINGS PROCESSED`}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AIInsights;