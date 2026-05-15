import React, { useState, useEffect } from 'react';
import { reportingAPI, scanAPI } from '../api/client';
import { 
  FileText, 
  Download, 
  Plus, 
  Search, 
  Filter, 
  Calendar, 
  CheckCircle2, 
  Clock, 
  AlertCircle, 
  ChevronRight, 
  Loader2,
  X,
  FileSpreadsheet,
  FileJson,
  Layout,
  Share2,
  Trash2,
  ShieldCheck,
  Database,
  Zap
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const Reporting = () => {
  const [reports, setReports] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newReport, setNewReport] = useState({
    scan_id: '',
    name: '',
    type: 'pdf',
    sections: ['vulnerabilities', 'assets', 'summary'],
    timeframe: '7d'
  });

  useEffect(() => {
    fetchReports();
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await scanAPI.listScans();
      const data = response.data;
      const scanList = Array.isArray(data) ? data : (data.items || []);
      setScans(scanList.filter(s => s.status === 'completed'));
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    }
  };

  const fetchReports = async () => {
    try {
      const response = await reportingAPI.listReports();
      const data = response.data;
      // Handle both { items: [...] } and direct array responses
      setReports(Array.isArray(data) ? data : (data.items || []));
    } catch (error) {
      console.error("Failed to fetch reports:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (e) => {
    e.preventDefault();
    if (!newReport.scan_id) {
      alert('Please select a completed scan');
      return;
    }
    setGenerating(true);
    try {
      await reportingAPI.generateReport({ scan_id: newReport.scan_id });
      setIsModalOpen(false);
      setNewReport({ scan_id: '', name: '', type: 'pdf', sections: ['vulnerabilities', 'assets', 'summary'], timeframe: '7d' });
      fetchReports();
    } catch (error) {
      console.error('Failed to generate report:', error);
      alert('Failed to generate report: ' + (error.response?.data?.detail || error.message));
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (id, name) => {
    try {
      const response = await reportingAPI.downloadReport(id);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${name}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error("Download failed:", error);
    }
  };

  if (loading && reports.length === 0) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <FileText className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Accessing Archive Vault...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6 page-entry">
      {/* Header section */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Report Archive</h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Generate and manage comprehensive security audits, compliance documentation, and executive summaries.
          </p>
        </div>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-8 py-4 bg-primary text-black rounded-2xl font-black text-xs uppercase tracking-[0.2em] shadow-[0_0_30px_rgba(189,157,255,0.3)] hover:shadow-[0_0_50px_rgba(189,157,255,0.6)] transition-all active:scale-95"
        >
          <Plus className="w-5 h-5" />
          Create Report
        </button>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Templates Panel */}
        <div className="col-span-12 lg:col-span-3 space-y-6">
          <div className="glass-panel p-8 rounded-3xl border border-white/5 bg-slate-950/40">
            <h3 className="text-[10px] font-bold tracking-[0.2em] text-slate-500 mb-8 uppercase">Standard Templates</h3>
            <div className="space-y-4">
              {[
                { label: 'Executive Summary', icon: Layout, color: 'text-primary' },
                { label: 'Technical Audit', icon: FileSpreadsheet, color: 'text-secondary' },
                { label: 'PCI Compliance', icon: ShieldCheck, color: 'text-green-400' },
                { label: 'Asset Inventory', icon: Database, color: 'text-tertiary' }
              ].map(t => (
                <button key={t.label} className="w-full flex items-center gap-4 p-4 rounded-2xl bg-white/5 border border-white/5 hover:border-primary/20 transition-all group text-left">
                  <div className={`p-2 rounded-xl bg-white/5 ${t.color}`}>
                    <t.icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-bold text-slate-300 group-hover:text-white transition-colors">{t.label}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="glass-panel p-8 rounded-3xl border border-primary/20 relative overflow-hidden group bg-primary/5">
            <div className="absolute top-0 right-0 p-6 opacity-10">
               <Zap className="w-12 h-12 text-primary" />
            </div>
            <h3 className="text-xs font-bold text-white mb-4 uppercase tracking-widest">Scheduled Reports</h3>
            <p className="text-xs text-slate-400 leading-relaxed mb-6">
              Weekly infrastructure audit is scheduled for <span className="text-primary font-bold">Monday, 00:00 UTC</span>.
            </p>
            <button className="text-[10px] font-bold text-primary uppercase tracking-widest hover:text-white transition-colors">
              Manage Schedule →
            </button>
          </div>
        </div>

        {/* Reports List */}
        <div className="col-span-12 lg:col-span-9">
          <div className="glass-panel rounded-3xl border border-white/5 bg-slate-950/40 overflow-hidden shadow-2xl">
            <div className="px-8 py-6 border-b border-white/5 bg-white/5 flex justify-between items-center">
              <div className="flex items-center gap-3">
                <Clock className="w-4 h-4 text-primary" />
                <h3 className="text-xs font-bold tracking-[0.2em] text-white uppercase font-headline">Generated Assets</h3>
              </div>
              <div className="flex items-center gap-4">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                  <input 
                    type="text" 
                    placeholder="Search archive..." 
                    className="bg-white/5 border border-white/10 rounded-lg py-1.5 pl-9 pr-4 text-[10px] text-white focus:ring-1 focus:ring-primary/50 outline-none w-48"
                  />
                </div>
              </div>
            </div>

            <div className="p-4 overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-white/5">
                    <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Designation</th>
                    <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Type</th>
                    <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Generation Date</th>
                    <th className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">Size</th>
                    <th className="px-6 py-4"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {reports.map((report) => (
                    <tr key={report.id} className="group hover:bg-white/5 transition-all">
                      <td className="px-6 py-5">
                        <div className="flex items-center gap-4">
                          <div className="p-2.5 rounded-xl bg-white/5 text-slate-400 group-hover:text-primary transition-colors">
                            <FileText className="w-5 h-5" />
                          </div>
                          <div>
                            <p className="text-sm font-bold text-white group-hover:text-primary transition-colors">{report.name}</p>
                            <p className="text-[9px] font-mono text-slate-500 uppercase tracking-widest mt-0.5">SHA-256: {report.id?.slice(0, 12)}...</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-5">
                        <span className="px-2 py-1 rounded bg-white/5 text-[9px] font-bold text-slate-400 uppercase border border-white/10">
                          {(report.type || 'pdf').toUpperCase()}
                        </span>
                      </td>
                      <td className="px-6 py-5">
                        <p className="text-xs text-slate-400">{new Date(report.created_at).toLocaleDateString()}</p>
                        <p className="text-[9px] text-slate-600 mt-0.5">{new Date(report.created_at).toLocaleTimeString()}</p>
                      </td>
                      <td className="px-6 py-5">
                        <span className="text-xs text-slate-400 font-mono">{report.size || '2.4 MB'}</span>
                      </td>
                      <td className="px-6 py-5 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button 
                            onClick={() => handleDownload(report.id, report.name)}
                            className="p-2 hover:bg-primary/10 rounded-lg text-slate-500 hover:text-primary transition-all"
                            title="Download"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                          <button className="p-2 hover:bg-white/10 rounded-lg text-slate-500 hover:text-white transition-all" title="Share">
                            <Share2 className="w-4 h-4" />
                          </button>
                          <button className="p-2 hover:bg-error/10 rounded-lg text-slate-500 hover:text-error transition-all" title="Delete">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {reports.length === 0 && (
                    <tr>
                      <td colSpan="5" className="py-20 text-center">
                        <div className="flex flex-col items-center justify-center opacity-20">
                          <FileText className="w-16 h-16 mb-4" />
                          <p className="text-xs font-bold uppercase tracking-[0.3em]">No records found in archive</p>
                        </div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Create Report Modal */}
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
                  <h3 className="text-2xl font-headline font-bold text-white uppercase tracking-tight">Assemble Security Report</h3>
                </div>
                <button onClick={() => setIsModalOpen(false)} className="p-2 hover:bg-white/10 rounded-xl transition-all">
                  <X className="w-6 h-6 text-slate-500" />
                </button>
              </div>

              <form onSubmit={handleGenerateReport} className="p-8 space-y-8">
                <div className="space-y-3">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Select Completed Scan</label>
                  <select
                    required
                    value={newReport.scan_id}
                    onChange={(e) => setNewReport({...newReport, scan_id: e.target.value})}
                    className="w-full bg-slate-900 border border-white/10 rounded-2xl px-5 py-4 text-sm text-white focus:ring-1 focus:ring-primary/50 outline-none appearance-none"
                    style={{ colorScheme: 'dark' }}
                  >
                    <option value="" style={{ background: '#0f172a', color: '#94a3b8' }}>-- Select a scan --</option>
                    {scans.map(s => (
                      <option key={s.id} value={s.id} style={{ background: '#0f172a', color: '#e2e8f0' }}>
                        {s.name} - {s.target_raw} ({s.risk_grade || 'Score: ' + s.security_score})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="grid grid-cols-2 gap-8">
                  <div className="space-y-3">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Output Format</label>
                    <div className="grid grid-cols-3 gap-2">
                      {['pdf', 'csv', 'json'].map(t => (
                        <button 
                          key={t}
                          type="button"
                          onClick={() => setNewReport({...newReport, type: t})}
                          className={`py-4 rounded-2xl text-[10px] font-bold uppercase tracking-widest border transition-all ${
                            newReport.type === t ? 'bg-primary/10 border-primary text-primary' : 'bg-white/5 border-transparent text-slate-500 hover:text-white'
                          }`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div className="space-y-3">
                    <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Temporal Scope</label>
                    <select 
                      value={newReport.timeframe}
                      onChange={(e) => setNewReport({...newReport, timeframe: e.target.value})}
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-sm text-white focus:ring-1 focus:ring-primary/50 outline-none appearance-none"
                    >
                      <option value="24h">Last 24 Hours</option>
                      <option value="7d">Last 7 Days</option>
                      <option value="30d">Last 30 Days</option>
                      <option value="all">Full History</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-3">
                  <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest ml-1">Intelligence Sections</label>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { id: 'vulnerabilities', label: 'Vulnerability Analysis' },
                      { id: 'assets', label: 'Asset Inventory' },
                      { id: 'threats', label: 'Threat Intel Graph' },
                      { id: 'ai', label: 'Neural Insights' }
                    ].map(s => (
                      <button
                        key={s.id}
                        type="button"
                        onClick={() => {
                          const sections = newReport.sections.includes(s.id)
                            ? newReport.sections.filter(id => id !== s.id)
                            : [...newReport.sections, s.id];
                          setNewReport({...newReport, sections});
                        }}
                        className={`flex items-center justify-between p-4 rounded-2xl border transition-all ${
                          newReport.sections.includes(s.id) ? 'bg-secondary/10 border-secondary/40 text-secondary' : 'bg-white/5 border-transparent text-slate-500 hover:bg-white/10'
                        }`}
                      >
                        <span className="text-xs font-bold uppercase tracking-wider">{s.label}</span>
                        {newReport.sections.includes(s.id) && <CheckCircle2 className="w-4 h-4" />}
                      </button>
                    ))}
                  </div>
                </div>

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
                    <Download className="w-5 h-5" />
                    {generating ? 'Generating...' : 'Generate PDF Report'}
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

export default Reporting;