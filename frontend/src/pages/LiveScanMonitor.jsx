import React, { useState, useEffect, useCallback } from 'react';
import {
  Activity, Globe, Shield, Search, Code, FileCode, Box, Zap, Brain,
  Play, Pause, Square, RefreshCw, Terminal, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle2, Clock, Loader2, Radio, Wifi
} from 'lucide-react';
import api from '../api/client';

const TOOL_ICONS = {
  nmap: Globe, zap: Shield, nikto: Search, semgrep: Code,
  bandit: FileCode, trivy: Box, masscan: Zap, pentagi: Brain,
};

const STATUS_CONFIG = {
  idle: { color: 'text-slate-500', bg: 'bg-slate-500/10', border: 'border-slate-500/20', label: 'IDLE', icon: Clock },
  initializing: { color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20', label: 'INIT', icon: Loader2 },
  running: { color: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/20', label: 'RUNNING', icon: Activity },
  analyzing: { color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20', label: 'ANALYZING', icon: Brain },
  completed: { color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/20', label: 'DONE', icon: CheckCircle2 },
  error: { color: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20', label: 'ERROR', icon: AlertTriangle },
};

const CATEGORY_COLORS = {
  Network: '#06b6d4', Web: '#8b5cf6', Code: '#f59e0b', Container: '#10b981', Advanced: '#ef4444',
};

function ToolCard({ tool, isExpanded, onToggle }) {
  const statusConf = STATUS_CONFIG[tool.status] || STATUS_CONFIG.idle;
  const IconComponent = TOOL_ICONS[tool.id] || Activity;
  const StatusIcon = statusConf.icon;
  const isActive = ['running', 'initializing', 'analyzing'].includes(tool.status);
  const catColor = CATEGORY_COLORS[tool.category] || '#94a3b8';

  return (
    <div className={`rounded-xl border transition-all duration-300 ${statusConf.border} ${statusConf.bg} backdrop-blur-sm overflow-hidden ${isActive ? 'shadow-lg' : ''}`}
      style={isActive ? { boxShadow: `0 0 30px ${catColor}15` } : {}}>
      <div className="p-4 cursor-pointer" onClick={onToggle}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${catColor}20` }}>
              <IconComponent className="w-5 h-5" style={{ color: catColor }} />
            </div>
            <div>
              <h3 className="text-white font-bold text-sm">{tool.name}</h3>
              <p className="text-[10px] text-slate-500 uppercase tracking-wider">{tool.category} Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`text-[9px] font-bold uppercase tracking-widest px-2 py-1 rounded-full ${statusConf.bg} ${statusConf.color} border ${statusConf.border}`}>
              <StatusIcon className={`w-3 h-3 inline mr-1 ${isActive ? 'animate-spin' : ''}`} />
              {statusConf.label}
            </span>
            {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
          </div>
        </div>

        {/* Progress bar */}
        <div className="h-1.5 bg-slate-800/50 rounded-full overflow-hidden mb-2">
          <div className="h-full rounded-full transition-all duration-1000 ease-out"
            style={{ width: `${tool.progress}%`, backgroundColor: catColor, boxShadow: `0 0 10px ${catColor}` }} />
        </div>

        <div className="flex items-center justify-between text-[10px]">
          <span className="text-slate-500">{tool.current_task || tool.description}</span>
          <div className="flex items-center gap-3">
            {tool.findings_count > 0 && (
              <span className="text-amber-400 font-bold">{tool.findings_count} findings</span>
            )}
            <span className={statusConf.color} style={{ fontVariantNumeric: 'tabular-nums' }}>{tool.progress}%</span>
            {tool.eta && <span className="text-slate-600">{tool.eta}</span>}
          </div>
        </div>
      </div>

      {/* Expanded log panel */}
      {isExpanded && (
        <div className="border-t border-white/5 p-4">
          <div className="flex items-center gap-2 mb-2">
            <Terminal className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">Live Output</span>
          </div>
          <div className="bg-black/40 rounded-lg p-3 max-h-40 overflow-y-auto font-mono text-[11px] space-y-1 custom-scrollbar">
            {tool.logs && tool.logs.length > 0 ? (
              tool.logs.map((log, i) => (
                <div key={i} className="text-slate-400 leading-relaxed">
                  <span className="text-slate-600">{log.split(']')[0]}]</span>
                  <span className={log.includes('ALERT') || log.includes('CVE') ? 'text-red-400' : log.includes('✅') ? 'text-emerald-400' : 'text-slate-300'}>
                    {log.split(']').slice(1).join(']')}
                  </span>
                </div>
              ))
            ) : (
              <span className="text-slate-600 italic">No output yet...</span>
            )}
            {isActive && <div className="text-cyan-500 animate-pulse">▌</div>}
          </div>
        </div>
      )}
    </div>
  );
}

function LiveScanMonitor() {
  const [tools, setTools] = useState([]);
  const [activeScans, setActiveScans] = useState(null);
  const [expandedTool, setExpandedTool] = useState(null);
  const [isPolling, setIsPolling] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [toolsRes, scansRes] = await Promise.all([
        api.get('/live-scan/tools'),
        api.get('/live-scan/active'),
      ]);
      setTools(toolsRes.data);
      setActiveScans(scansRes.data);
      setLastUpdate(new Date());
      setLoading(false);
    } catch (err) {
      console.error('Live scan fetch error:', err);
      // Clean empty state — no mock data injected
      setTools([]);
      setActiveScans(null);
      setLastUpdate(new Date());
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    
    // Setup WebSocket connection for real-time Kafka logs and progress
    // Use VITE_WS_URL env var; falls back to same host. Backend route: /ws/{client_id}?token=...
    const wsBase = import.meta.env.VITE_WS_URL || `ws://${window.location.hostname}:8000`;
    const clientId = `livemonitor-${Date.now()}`;
    const token = localStorage.getItem('sentinel_token') || '';
    const wsUrl = `${wsBase}/ws/${clientId}?token=${token}`;
    let ws = null;
    
    if (isPolling) {
      try {
        ws = new WebSocket(wsUrl);
        ws.onmessage = (event) => {
          const data = JSON.parse(event.data);
          if (data.type === 'tool_update') {
            setTools(prev => {
              const idx = prev.findIndex(t => t.id === data.payload.id);
              if (idx === -1) return [...prev, data.payload];
              const newTools = [...prev];
              newTools[idx] = { ...newTools[idx], ...data.payload };
              return newTools;
            });
          } else if (data.type === 'scan_update') {
            setActiveScans(data.payload);
          }
          setLastUpdate(new Date());
        };
        ws.onerror = (e) => console.error('WebSocket error:', e);
      } catch (err) {
        console.warn('WebSocket init failed, falling back to polling', err);
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
      }
    }
    
    return () => {
      if (ws) ws.close();
    };
  }, [fetchData, isPolling]);

  const runningCount = tools.filter(t => ['running', 'initializing', 'analyzing'].includes(t.status)).length;
  const completedCount = tools.filter(t => t.status === 'completed').length;
  const totalFindings = tools.reduce((sum, t) => sum + (t.findings_count || 0), 0);

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white font-headline flex items-center gap-3">
            <Radio className="w-6 h-6 text-cyan-400 animate-pulse" />
            Live Scan Execution Monitor
          </h1>
          <p className="text-slate-500 text-xs mt-1">Real-time distributed scanner orchestration — {tools.length} tools registered</p>
        </div>
        <div className="flex items-center gap-3">
          {lastUpdate && (
            <span className="text-[10px] text-slate-600 font-mono">
              Last: {lastUpdate.toLocaleTimeString()}
            </span>
          )}
          <button onClick={() => setIsPolling(!isPolling)}
            className={`px-3 py-1.5 rounded-lg text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all ${isPolling ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700'}`}>
            {isPolling ? <><Wifi className="w-3 h-3" /> Live</> : <><Pause className="w-3 h-3" /> Paused</>}
          </button>
          <button onClick={fetchData}
            className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 text-[10px] font-bold uppercase tracking-wider hover:bg-slate-700 transition-all flex items-center gap-1.5 border border-slate-700">
            <RefreshCw className="w-3 h-3" /> Refresh
          </button>
        </div>
      </div>

      {/* Overview stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Active Workers', value: runningCount, sub: `of ${tools.length}`, color: 'text-cyan-400', icon: Activity },
          { label: 'Completed', value: completedCount, sub: 'tools done', color: 'text-emerald-400', icon: CheckCircle2 },
          { label: 'Findings', value: totalFindings, sub: 'detected', color: 'text-amber-400', icon: AlertTriangle },
          { label: 'Queue Depth', value: activeScans?.queue_depth || 0, sub: 'pending', color: 'text-purple-400', icon: Clock },
        ].map((stat, i) => (
          <div key={i} className="bg-slate-900/40 backdrop-blur-sm border border-white/5 rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[9px] font-bold text-slate-500 uppercase tracking-widest">{stat.label}</span>
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
            </div>
            <div className="flex items-baseline gap-2">
              <span className={`text-2xl font-bold ${stat.color}`} style={{ fontVariantNumeric: 'tabular-nums' }}>{stat.value}</span>
              <span className="text-[10px] text-slate-600">{stat.sub}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Active scan banner */}
      {activeScans?.active_scans?.length > 0 && (
        <div className="bg-gradient-to-r from-cyan-500/5 to-purple-500/5 border border-cyan-500/20 rounded-xl p-4">
          {activeScans.active_scans.map((scan, i) => (
            <div key={i} className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_10px_#06b6d4]" />
                <div>
                  <span className="text-white font-bold text-sm">{scan.name}</span>
                  <span className="text-slate-500 text-xs ml-3">Target: {scan.target}</span>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-amber-400 text-xs font-bold">{scan.findings_so_far} findings</span>
                <div className="w-32 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-cyan-400 to-purple-400 rounded-full transition-all duration-1000" style={{ width: `${scan.progress}%` }} />
                </div>
                <span className="text-cyan-400 text-xs font-mono font-bold">{scan.progress}%</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tool grid */}
      <div className="grid grid-cols-2 gap-4">
        {tools.map((tool) => (
          <ToolCard
            key={tool.id}
            tool={tool}
            isExpanded={expandedTool === tool.id}
            onToggle={() => setExpandedTool(expandedTool === tool.id ? null : tool.id)}
          />
        ))}
      </div>
    </div>
  );
}

export default LiveScanMonitor;
