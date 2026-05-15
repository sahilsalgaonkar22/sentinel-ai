import React, { useState, useEffect } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, 
  BarChart, Bar, AreaChart, Area, PieChart, Pie, Cell, ScatterChart, Scatter, ZAxis
} from 'recharts';
import { dashboardAPI } from '../api/client';
import { 
  TrendingUp, 
  ShieldAlert, 
  Activity, 
  Globe, 
  BarChart3, 
  PieChart as PieChartIcon,
  Download,
  Calendar,
  Filter,
  Zap,
  Info,
  Layers,
  Sparkles
} from 'lucide-react';

const AnalyticsPage = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [timeRange, setTimeRange] = useState('7d');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await dashboardAPI.getAnalytics();
        setData(response.data);
      } catch (error) {
        console.error("Failed to fetch analytics:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [timeRange]);

  if (loading || !data) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <Activity className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Aggregating Global Telemetry...</span>
      </div>
    );
  }

  const COLORS = ['#bd9dff', '#36bcfd', '#ff6e84', '#ff9289'];

  return (
    <div className="space-y-8 page-entry">
      {/* Header section */}
      <div className="flex justify-between items-end mb-8">
        <div>
          <h2 className="text-4xl font-headline font-bold text-white tracking-tight">Advanced Analytics</h2>
          <p className="text-slate-400 mt-2 max-w-2xl text-sm leading-relaxed">
            Multi-dimensional visualization of global risk trends, asset exposure, and vulnerability distribution.
          </p>
        </div>
        <div className="flex gap-4">
          <div className="glass-panel p-1 rounded-xl border border-white/5 flex gap-1">
            {['24h', '7d', '30d', '90d'].map(r => (
              <button 
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-4 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest transition-all ${
                  timeRange === r ? 'bg-primary text-black' : 'text-slate-500 hover:text-white'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
          <button className="flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 rounded-xl text-[10px] font-bold text-slate-300 transition-all uppercase tracking-widest border border-white/5">
            <Download className="w-4 h-4" />
            Export Data
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Risk Trend Chart */}
        <div className="col-span-12 lg:col-span-8">
          <div className="glass-panel rounded-3xl p-8 border border-white/5 bg-slate-950/40 h-full">
            <div className="flex justify-between items-center mb-8">
              <div className="flex items-center gap-3">
                <TrendingUp className="w-5 h-5 text-primary" />
                <h3 className="text-xs font-bold text-white uppercase tracking-[0.2em] font-headline">Global Risk Trend</h3>
              </div>
              <div className="flex items-center gap-4 text-[10px] font-bold text-slate-500 uppercase">
                <span className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-primary"></div> Risk Score</span>
                <span className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full bg-secondary"></div> Scan Volume</span>
              </div>
            </div>
            <div className="h-[400px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.risk_trend}>
                  <defs>
                    <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#bd9dff" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#bd9dff" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis 
                    dataKey="name" 
                    stroke="rgba(255,255,255,0.2)" 
                    fontSize={10} 
                    tickLine={false} 
                    axisLine={false}
                    tick={{ fill: 'rgba(255,255,255,0.4)' }}
                  />
                  <YAxis 
                    stroke="rgba(255,255,255,0.2)" 
                    fontSize={10} 
                    tickLine={false} 
                    axisLine={false}
                    tick={{ fill: 'rgba(255,255,255,0.4)' }}
                  />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }}
                    itemStyle={{ color: '#fff', fontSize: '11px', fontWeight: 'bold' }}
                  />
                  <Area type="monotone" dataKey="risk" stroke="#bd9dff" strokeWidth={3} fillOpacity={1} fill="url(#colorRisk)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Distribution Pie */}
        <div className="col-span-12 lg:col-span-4">
          <div className="glass-panel rounded-3xl p-8 border border-white/5 bg-slate-950/40 h-full">
            <div className="flex items-center gap-3 mb-8">
              <PieChartIcon className="w-5 h-5 text-secondary" />
              <h3 className="text-xs font-bold text-white uppercase tracking-[0.2em] font-headline">Severity Distribution</h3>
            </div>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data.vuln_by_severity || []}
                    innerRadius={80}
                    outerRadius={100}
                    paddingAngle={8}
                    dataKey="count"
                  >
                    {(data.vuln_by_severity || []).map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'rgba(15, 23, 42, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-4 mt-8">
              {(data.vuln_by_severity || []).map((entry, index) => (
                <div key={entry.name} className="flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[index % COLORS.length] }}></div>
                    <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">{entry.name}</span>
                  </div>
                  <span className="text-sm font-black text-white">{entry.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Asset Exposure Heatmap */}
        <div className="col-span-12 lg:col-span-6">
          <div className="glass-panel rounded-3xl p-8 border border-white/5 bg-slate-950/40">
            <div className="flex justify-between items-center mb-8">
              <div className="flex items-center gap-3">
                <Globe className="w-5 h-5 text-tertiary" />
                <h3 className="text-xs font-bold text-white uppercase tracking-[0.2em] font-headline">Asset Exposure Matrix</h3>
              </div>
              <Info className="w-4 h-4 text-slate-500 cursor-help" />
            </div>
            <div className="h-[300px]">
              {(data.asset_exposure_matrix || []).length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                    <CartesianGrid stroke="rgba(255,255,255,0.05)" />
                    <XAxis type="number" dataKey="x" name="criticality" unit="" stroke="rgba(255,255,255,0.2)" fontSize={10} />
                    <YAxis type="number" dataKey="y" name="vulnerabilities" unit="" stroke="rgba(255,255,255,0.2)" fontSize={10} />
                    <ZAxis type="number" dataKey="z" range={[60, 400]} name="risk" unit="" />
                    <Tooltip cursor={{ strokeDasharray: '3 3' }} />
                    <Scatter name="Assets" data={data.asset_exposure_matrix} fill="#36bcfd" />
                  </ScatterChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-slate-500">
                  <Globe className="w-10 h-10 mb-3 opacity-30" />
                  <p className="text-xs">Add assets and run scans to populate the exposure matrix.</p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Attack Probability Scoring */}
        <div className="col-span-12 lg:col-span-6">
          <div className="glass-panel rounded-3xl p-8 border border-white/5 bg-slate-950/40 h-full">
            <div className="flex items-center gap-3 mb-8">
              <Zap className="w-5 h-5 text-primary" />
              <h3 className="text-xs font-bold text-white uppercase tracking-[0.2em] font-headline">Attack Probability Scoring</h3>
            </div>
            <div className="space-y-8">
              {(data.attack_probability || []).length > 0 ? (data.attack_probability || []).map(item => (
                <div key={item.label} className="group cursor-pointer">
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] font-bold text-white/60 group-hover:text-white transition-colors">{item.label}</span>
                    <span className="text-sm font-black text-white">{item.val}%</span>
                  </div>
                  <div className="h-2 bg-white/5 rounded-full overflow-hidden relative">
                    <div className={`${item.color} h-full transition-all duration-1000`} style={{ width: `${item.val}%` }}></div>
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  </div>
                </div>
              )) : (
                <div className="flex flex-col items-center justify-center py-8 text-slate-500">
                  <Zap className="w-10 h-10 mb-3 opacity-30" />
                  <p className="text-xs">Run scans to generate attack probability data.</p>
                </div>
              )}
            </div>
            <div className="mt-12 p-6 rounded-2xl bg-primary/5 border border-primary/20 flex items-center gap-6">
              <Sparkles className="w-8 h-8 text-primary shrink-0" />
              <div>
                <p className="text-[10px] font-bold text-primary uppercase tracking-widest mb-1">AI Prediction Insight</p>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {data.ai_prediction_insight || "Run a scan to generate AI-powered attack probability analysis."}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AnalyticsPage;