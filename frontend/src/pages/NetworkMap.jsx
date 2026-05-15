import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Globe, 
  ShieldAlert, 
  ShieldCheck, 
  Zap, 
  Activity, 
  Database, 
  Server, 
  Network, 
  Info, 
  Search, 
  Plus, 
  Minus, 
  Layers,
  ChevronRight,
  Sparkles,
  Terminal,
  Cpu,
  Target
} from 'lucide-react';
import { vulnAPI } from '../api/client';

const NetworkMap = () => {
  const [activeStep, setActiveStep] = useState(-1);
  const [isSimulating, setIsSimulating] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  
  const [paths, setPaths] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchPaths = async () => {
      try {
        const response = await vulnAPI.listAttackPaths();
        setPaths(response.data || []);
      } catch (err) {
        console.error("Failed to load attack paths:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchPaths();
  }, []);

  const activePath = paths.length > 0 ? paths[0] : null;
  const attackSteps = activePath?.chain_steps?.map((step, i) => ({
    id: i + 1,
    label: step.action || `Step ${i + 1}`,
    desc: step.description || step.action,
    status: activeStep > i ? 'completed' : (activeStep === i ? 'active' : 'pending')
  })) || [];

  useEffect(() => {
    let interval;
    if (isSimulating && attackSteps.length > 0) {
      interval = setInterval(() => {
        setActiveStep(prev => {
          if (prev >= attackSteps.length - 1) return -1;
          return prev + 1;
        });
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [isSimulating, attackSteps.length]);

  if (loading) {
    return (
      <div className="h-[calc(100vh-120px)] flex flex-col items-center justify-center text-primary">
        <Activity className="w-12 h-12 animate-pulse mb-4" />
        <span className="text-[10px] font-bold uppercase tracking-[0.5em] animate-pulse">Syncing Telemetry...</span>
      </div>
    );
  }

  // If no attack paths, display a clean state
  if (!activePath) {
    return (
      <div className="h-[calc(100vh-140px)] flex flex-col items-center justify-center border border-white/5 bg-[#05070a] rounded-3xl relative overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,#0b1220_0%,#000_100%)]"></div>
        <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'linear-gradient(rgba(189, 157, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(189, 157, 255, 0.03) 1px, transparent 1px)', backgroundSize: '50px 50px' }}></div>
        
        <ShieldCheck className="w-24 h-24 text-green-500 mb-6 relative z-10 opacity-80" />
        <h2 className="text-3xl font-headline font-bold text-white mb-2 relative z-10">No Attack Paths Detected</h2>
        <p className="text-slate-400 text-sm max-w-md text-center relative z-10 mix-blend-screen">
          Your infrastructure is currently secure. Run a scan from the dashboard to populate the network map with live attack path data.
        </p>
      </div>
    );
  }

  // Extract nodes dynamically based on the attack path steps
  const nodes = [
    { id: 'start', x: "25%", y: "20%", icon: <Globe className="w-6 h-6" />, label: activePath.entry_point || 'ENTRY_NODE', type: 'error', active: activeStep >= 0 },
    { id: 'mid1', x: "50%", y: "50%", icon: <Server className="w-8 h-8" />, label: attackSteps.length > 1 ? 'PIVOT_NODE' : 'TARGET_NODE', type: 'primary', active: activeStep >= 1 },
    ...((attackSteps.length > 2) ? [{ id: 'end', x: "75%", y: "25%", icon: <Database className="w-6 h-6" />, label: activePath.final_impact || 'CORE_SYSTEM', type: 'error', active: activeStep >= 2 }] : [])
  ];

  return (
    <div className="relative w-full h-[calc(100vh-140px)] overflow-hidden rounded-3xl border border-white/5 bg-[#05070a] page-entry">
      {/* 3D Background Atmosphere */}
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,#0b1220_0%,#000_100%)]"></div>
      <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'linear-gradient(rgba(189, 157, 255, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(189, 157, 255, 0.03) 1px, transparent 1px)', backgroundSize: '50px 50px' }}></div>

      {/* Interactive Map Surface */}
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="relative w-full h-full max-w-5xl max-h-[700px]">
          {/* Connection Lines */}
          <svg className="absolute inset-0 w-full h-full overflow-visible pointer-events-none z-0">
            {nodes.length >= 2 && (
              <motion.path 
                d="M 250 150 L 512 350" 
                fill="none" 
                stroke={activeStep >= 0 ? "#ff6e84" : "rgba(255,255,255,0.05)"} 
                strokeWidth="2"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: activeStep >= 0 ? 1 : 0 }}
                className="transition-colors duration-500"
              />
            )}
            {nodes.length >= 3 && (
              <motion.path 
                d="M 512 350 L 750 200" 
                fill="none" 
                stroke={activeStep >= 1 ? "#ff6e84" : "rgba(255,255,255,0.05)"} 
                strokeWidth="2"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: activeStep >= 1 ? 1 : 0 }}
              />
            )}
          </svg>

          {/* Nodes */}
          {nodes.map(n => (
            <Node 
              key={n.id}
              x={n.x} 
              y={n.y} 
              icon={n.icon} 
              label={n.label} 
              type={n.type}
              active={n.active}
              onClick={() => setSelectedNode(n.id)}
            />
          ))}
        </div>
      </div>

      {/* Simulation Controls */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 glass-panel px-8 py-4 rounded-3xl border border-white/10 flex items-center gap-8 shadow-2xl z-20">
        <div className="flex items-center gap-4 border-r border-white/10 pr-8">
          <button 
            onClick={() => { setIsSimulating(!isSimulating); if(activeStep === -1) setActiveStep(0); }}
            className={`p-3 rounded-2xl transition-all ${isSimulating ? 'bg-error text-white' : 'bg-primary text-black'}`}
          >
            {isSimulating ? <Activity className="w-5 h-5 animate-pulse" /> : <Zap className="w-5 h-5" />}
          </button>
          <div>
            <p className="text-[10px] font-black text-white uppercase tracking-widest">
              {isSimulating ? 'Simulation Active' : 'Ready to Simulate'}
            </p>
            <p className="text-[9px] text-slate-500 font-bold uppercase tracking-tighter truncate max-w-[150px]">{activePath.name}</p>
          </div>
        </div>
        
        <div className="flex gap-2">
          {attackSteps.map((s, i) => (
            <button 
              key={s.id}
              onClick={() => setActiveStep(i)}
              className={`w-10 h-10 rounded-xl border transition-all flex items-center justify-center text-[10px] font-black ${
                activeStep === i ? 'bg-primary border-primary text-black shadow-[0_0_15px_rgba(189,157,255,0.4)]' : 'bg-white/5 border-white/10 text-slate-500 hover:text-white'
              }`}
            >
              {s.id}
            </button>
          ))}
        </div>
      </div>

      {/* Left HUD - Attack Breakdown */}
      <div className="absolute top-8 left-8 w-80 space-y-6 z-10 max-h-[80vh] overflow-y-auto custom-scrollbar pr-2">
        <div className="glass-panel p-6 rounded-[32px] border border-white/10 bg-slate-950/40">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Terminal className="w-4 h-4 text-primary" />
              <h3 className="text-xs font-bold text-white uppercase tracking-[0.2em] font-headline">Chain Breakdown</h3>
            </div>
            <span className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded text-error bg-error/20`}>
              {activePath.severity}
            </span>
          </div>
          <div className="space-y-4">
            {attackSteps.map((s, i) => (
              <div key={s.id} className={`p-4 rounded-2xl border transition-all ${
                activeStep === i ? 'bg-primary/10 border-primary/30' : 'bg-white/5 border-transparent opacity-40'
              }`}>
                <div className="flex justify-between items-center mb-1">
                  <span className="text-[9px] font-black text-primary uppercase tracking-widest leading-relaxed line-clamp-1">{s.label}</span>
                  {activeStep === i && <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping flex-shrink-0 ml-2"></span>}
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {activePath.ai_analysis && (
          <div className="glass-panel p-6 rounded-[32px] border border-primary/20 bg-primary/5">
            <div className="flex items-center gap-3 mb-4">
              <Sparkles className="w-4 h-4 text-primary" />
              <h3 className="text-[10px] font-bold text-white uppercase tracking-widest">Sovereign Insight</h3>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed italic">
              "{activePath.ai_analysis}"
            </p>
          </div>
        )}
      </div>

      {/* Right HUD - Details */}
      <div className="absolute top-8 right-8 w-80 space-y-6 z-10">
        <div className="glass-panel p-6 rounded-[32px] border border-white/5 bg-slate-950/40">
          <div className="flex justify-between items-center mb-6">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Entry Point</h3>
          </div>
          <p className="font-mono text-[11px] text-primary">{activePath.entry_point || "Undetermined"}</p>
        </div>

        <div className="glass-panel p-6 rounded-[32px] border border-white/5 bg-slate-950/40">
          <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Final Impact</h3>
          <p className="text-[12px] font-bold text-error">{activePath.final_impact || "Compromise"}</p>
        </div>
        
        {activePath.mitigation_steps && activePath.mitigation_steps.length > 0 && (
          <div className="glass-panel p-6 rounded-[32px] border border-white/5 bg-slate-950/40">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-4">Mitigation Priority</h3>
            <ul className="space-y-2">
              {activePath.mitigation_steps.map((mit, i) => (
                <li key={i} className="text-[10px] text-slate-400 font-mono leading-relaxed list-disc list-inside">
                  {typeof mit === 'string' ? mit : (mit.action || "Patch network service")}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Floating Controls */}
      <div className="absolute left-8 bottom-8 flex flex-col gap-3 z-10">
        <button className="w-12 h-12 rounded-2xl bg-slate-950/60 border border-white/10 flex items-center justify-center text-slate-500 hover:text-white transition-all hover:border-primary/40">
          <Plus className="w-5 h-5" />
        </button>
        <button className="w-12 h-12 rounded-2xl bg-slate-950/60 border border-white/10 flex items-center justify-center text-slate-500 hover:text-white transition-all hover:border-primary/40">
          <Minus className="w-5 h-5" />
        </button>
        <button className="w-12 h-12 rounded-2xl bg-slate-950/60 border border-white/10 flex items-center justify-center text-slate-500 hover:text-white transition-all hover:border-primary/40">
          <Layers className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
};

const Node = ({ x, y, icon, label, type, active, onClick }) => {
  const colors = {
    primary: 'border-primary text-primary bg-primary/10 shadow-[0_0_20px_rgba(189,157,255,0.3)]',
    secondary: 'border-secondary text-secondary bg-secondary/10 shadow-[0_0_20px_rgba(54,188,253,0.3)]',
    error: 'border-error text-error bg-error/10 shadow-[0_0_20px_rgba(255,110,132,0.3)]'
  };

  return (
    <motion.div 
      className="absolute cursor-pointer group z-10"
      style={{ top: y, left: x, transform: 'translate(-50%, -50%)' }}
      whileHover={{ scale: 1.1 }}
      onClick={onClick}
    >
      <div className={`w-16 h-16 rounded-full border-2 flex items-center justify-center backdrop-blur-xl transition-all duration-500 ${
        active ? colors.error : colors[type]
      }`}>
        {icon}
        {active && <div className="absolute inset-0 rounded-full border-2 border-error animate-ping opacity-70"></div>}
      </div>
      <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 whitespace-nowrap bg-[#0b0e15]/80 px-2 py-1 rounded backdrop-blur">
        <span className={`text-[10px] font-black uppercase tracking-widest transition-colors duration-500 ${
          active ? 'text-error' : 'text-slate-400 group-hover:text-white'
        }`}>
          {label}
        </span>
      </div>
    </motion.div>
  );
};

export default NetworkMap;