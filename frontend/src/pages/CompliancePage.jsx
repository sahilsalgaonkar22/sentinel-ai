import React, { useState, useEffect } from 'react';
import { scanAPI, complianceAPI } from '../api/client';
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronRight,
  Loader2,
  FileText,
  Lock,
  Globe,
  Server,
  Eye,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const FRAMEWORK_META = {
  owasp_top_10: { name: 'OWASP Top 10', year: '2021', icon: Globe, color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/20' },
  pci_dss: { name: 'PCI-DSS', year: 'v4.0', icon: Lock, color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20' },
  iso_27001: { name: 'ISO 27001', year: '2022', icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/20' },
  nist_csf: { name: 'NIST CSF', year: '2.0', icon: Server, color: 'text-purple-400', bg: 'bg-purple-400/10', border: 'border-purple-400/20' },
};

const SEV_COLORS = {
  critical: 'text-red-400 bg-red-400/10',
  high: 'text-orange-400 bg-orange-400/10',
  medium: 'text-yellow-400 bg-yellow-400/10',
  low: 'text-blue-400 bg-blue-400/10',
  info: 'text-slate-400 bg-slate-400/10',
  pass: 'text-emerald-400 bg-emerald-400/10',
};

const CompliancePage = () => {
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState('');
  const [compliance, setCompliance] = useState(null);
  const [loading, setLoading] = useState(false);
  const [expandedFramework, setExpandedFramework] = useState(null);
  const [pageLoading, setPageLoading] = useState(true);

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const res = await scanAPI.listScans();
      const data = res.data;
      const list = Array.isArray(data) ? data : (data.items || []);
      const completed = list.filter(s => s.status === 'completed');
      setScans(completed);
      // Auto-load compliance for the most recent completed scan
      if (completed.length > 0 && !selectedScan) {
        const latest = completed[0]; // already sorted by most recent from backend
        loadCompliance(latest.id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setPageLoading(false);
    }
  };

  const loadCompliance = async (scanId) => {
    setSelectedScan(scanId);
    if (!scanId) { setCompliance(null); return; }
    setLoading(true);
    try {
      const res = await complianceAPI.getReport(scanId);
      setCompliance(res.data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const summary = compliance?.summary || {};

  if (pageLoading) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <ShieldCheck className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Loading Compliance Engine...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 page-entry">
      {/* Header */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Compliance Center</h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Map security findings to OWASP Top 10, PCI-DSS v4.0, ISO 27001:2022, and NIST CSF 2.0 compliance frameworks.
          </p>
        </div>
      </div>

      {/* Scan Selector */}
      <div className="glass-panel p-6 rounded-3xl border border-white/5 bg-slate-950/40">
        <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3 block">Select Scan to Audit</label>
        <select
          value={selectedScan}
          onChange={e => loadCompliance(e.target.value)}
          className="w-full bg-slate-900 border border-white/10 rounded-2xl px-5 py-4 text-sm text-white focus:ring-1 focus:ring-primary/50 outline-none appearance-none"
          style={{ colorScheme: 'dark' }}
        >
          <option value="" style={{ background: '#0f172a', color: '#94a3b8' }}>-- Select a completed scan --</option>
          {scans.map(s => (
            <option key={s.id} value={s.id} style={{ background: '#0f172a', color: '#e2e8f0' }}>
              {s.name} — {s.target_raw} (Score: {s.security_score || 'N/A'})
            </option>
          ))}
        </select>
      </div>

      {loading && (
        <div className="flex items-center justify-center py-20">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <span className="ml-3 text-sm text-slate-400">Generating compliance mapping...</span>
        </div>
      )}

      {compliance && !loading && (
        <>
          {/* Summary Cards */}
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
            <div className="glass-panel p-6 rounded-3xl border border-white/5 bg-slate-950/40 text-center">
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Compliance Score</p>
              <p className={`text-4xl font-black ${summary.compliance_score >= 80 ? 'text-emerald-400' : summary.compliance_score >= 60 ? 'text-yellow-400' : 'text-red-400'}`}>
                {summary.compliance_score}%
              </p>
              <p className={`text-[10px] font-bold uppercase tracking-widest mt-1 ${summary.overall_status === 'compliant' ? 'text-emerald-400' : summary.overall_status === 'partial' ? 'text-yellow-400' : 'text-red-400'}`}>
                {summary.overall_status}
              </p>
            </div>
            {[
              { name: 'OWASP', violations: summary.owasp_violations, total: summary.owasp_total, color: 'text-orange-400' },
              { name: 'PCI-DSS', violations: summary.pci_violations, total: summary.pci_total, color: 'text-blue-400' },
              { name: 'ISO 27001', violations: summary.iso_gaps, total: summary.iso_total, color: 'text-emerald-400' },
              { name: 'NIST CSF', violations: summary.nist_gaps, total: summary.nist_total, color: 'text-purple-400' },
            ].map(fw => (
              <div key={fw.name} className="glass-panel p-6 rounded-3xl border border-white/5 bg-slate-950/40 text-center">
                <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">{fw.name}</p>
                <p className={`text-3xl font-black ${fw.violations === 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                  {fw.total - fw.violations}/{fw.total}
                </p>
                <p className="text-[10px] text-slate-500 mt-1">
                  {fw.violations === 0 ? '✓ Compliant' : `${fw.violations} violation${fw.violations > 1 ? 's' : ''}`}
                </p>
              </div>
            ))}
          </div>

          {/* Framework Details */}
          <div className="space-y-4">
            {Object.entries(FRAMEWORK_META).map(([key, meta]) => {
              const data = compliance[key] || {};
              const controls = Object.entries(data);
              const failCount = controls.filter(([, v]) => v.status === 'fail').length;
              const isExpanded = expandedFramework === key;
              const Icon = meta.icon;

              return (
                <div key={key} className={`glass-panel rounded-3xl border ${meta.border} overflow-hidden bg-slate-950/40`}>
                  <button
                    onClick={() => setExpandedFramework(isExpanded ? null : key)}
                    className="w-full flex items-center justify-between p-6 text-left hover:bg-white/5 transition-all"
                  >
                    <div className="flex items-center gap-4">
                      <div className={`p-3 rounded-xl ${meta.bg} ${meta.color}`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-white">{meta.name} <span className="text-slate-500">({meta.year})</span></h3>
                        <p className="text-[10px] text-slate-500 mt-0.5">{controls.length} controls evaluated</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {failCount === 0 ? (
                        <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-emerald-400/10 text-emerald-400 text-[10px] font-bold uppercase tracking-wider">
                          <CheckCircle2 className="w-3.5 h-3.5" /> All Pass
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-red-400/10 text-red-400 text-[10px] font-bold uppercase tracking-wider">
                          <XCircle className="w-3.5 h-3.5" /> {failCount} Failed
                        </span>
                      )}
                      <ChevronRight className={`w-4 h-4 text-slate-500 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                    </div>
                  </button>

                  <AnimatePresence>
                    {isExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <div className="border-t border-white/5 p-4">
                          <table className="w-full text-left">
                            <thead>
                              <tr className="border-b border-white/5">
                                <th className="px-4 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Control</th>
                                <th className="px-4 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Name</th>
                                <th className="px-4 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Findings</th>
                                <th className="px-4 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Severity</th>
                                <th className="px-4 py-3 text-[10px] font-bold text-slate-500 uppercase tracking-widest text-center">Status</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5">
                              {controls.map(([code, ctrl]) => (
                                <tr key={code} className="hover:bg-white/5 transition-all">
                                  <td className="px-4 py-3 text-xs font-mono text-primary font-bold">{code}</td>
                                  <td className="px-4 py-3 text-xs text-slate-300">{ctrl.name}</td>
                                  <td className="px-4 py-3 text-xs text-center text-slate-400">{ctrl.count}</td>
                                  <td className="px-4 py-3 text-center">
                                    {ctrl.max_severity !== 'pass' && (
                                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${SEV_COLORS[ctrl.max_severity] || 'text-slate-500'}`}>
                                        {ctrl.max_severity}
                                      </span>
                                    )}
                                  </td>
                                  <td className="px-4 py-3 text-center">
                                    {ctrl.status === 'pass' ? (
                                      <CheckCircle2 className="w-4 h-4 text-emerald-400 mx-auto" />
                                    ) : (
                                      <XCircle className="w-4 h-4 text-red-400 mx-auto" />
                                    )}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              );
            })}
          </div>
        </>
      )}

      {!compliance && !loading && !selectedScan && (
        <div className="flex flex-col items-center justify-center py-20 opacity-20">
          <ShieldCheck className="w-16 h-16 mb-4" />
          <p className="text-xs font-bold uppercase tracking-[0.3em]">Select a scan to view compliance mapping</p>
        </div>
      )}
    </div>
  );
};

export default CompliancePage;
