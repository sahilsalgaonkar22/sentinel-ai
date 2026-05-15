import React, { useState, useEffect, useRef } from 'react';
import { aiAPI } from '../api/client';
import { Link, useNavigate } from 'react-router-dom';
import { Search, Loader2, Database, ShieldAlert, Activity, GitFork, Command } from 'lucide-react';

const GlobalSearch = () => {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const searchRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        searchRef.current?.querySelector('input')?.focus();
      }
      if (e.key === 'Escape') setIsOpen(false);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  useEffect(() => {
    const handleOutsideClick = (event) => {
      if (searchRef.current && !searchRef.current.contains(event.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleOutsideClick);
    return () => document.removeEventListener('mousedown', handleOutsideClick);
  }, []);

  const handleSearch = async (e) => {
    const val = e.target.value;
    setQuery(val);
    if (val.length > 2) {
      setLoading(true);
      try {
        const response = await aiAPI.search(val);
        setResults(response.data);
        setIsOpen(true);
        setSelectedIndex(-1);
      } catch (err) {
        console.error('Search error:', err);
      } finally {
        setLoading(false);
      }
    } else {
      setResults(null);
      setIsOpen(false);
    }
  };

  const allResults = results ? [
    ...(results.vulnerabilities?.map(v => ({ ...v, type: 'vulnerability', icon: <ShieldAlert className="w-4 h-4 text-error" />, path: `/vulnerabilities/${v.id}`, label: v.title })) || []),
    ...(results.assets?.map(a => ({ ...a, type: 'asset', icon: <Database className="w-4 h-4 text-primary" />, path: `/assets/${a.id}`, label: a.name })) || []),
    ...(results.scans?.map(s => ({ ...s, type: 'scan', icon: <Activity className="w-4 h-4 text-secondary" />, path: `/scans/${s.id}`, label: s.name })) || []),
    ...(results.attackPaths?.map(p => ({ ...p, type: 'attackPath', icon: <GitFork className="w-4 h-4 text-tertiary" />, path: `/threat-intel`, label: p.name })) || []),
  ] : [];

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowDown') {
      setSelectedIndex(prev => Math.min(prev + 1, allResults.length - 1));
    } else if (e.key === 'ArrowUp') {
      setSelectedIndex(prev => Math.max(prev - 1, 0));
    } else if (e.key === 'Enter' && selectedIndex >= 0) {
      navigate(allResults[selectedIndex].path);
      setIsOpen(false);
      setQuery('');
    }
  };

  return (
    <div className="relative group" ref={searchRef}>
      <div className="relative">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 group-focus-within:text-primary transition-colors" />
        <input 
          type="text"
          value={query}
          onChange={handleSearch}
          onKeyDown={handleKeyDown}
          onFocus={() => query.length > 2 && setIsOpen(true)}
          placeholder="Analyze system vectors..."
          className="bg-white/5 border border-white/5 hover:border-white/10 rounded-full pl-12 pr-12 py-2 text-xs w-80 focus:ring-1 focus:ring-primary/40 focus:bg-white/10 transition-all outline-none placeholder:text-slate-600"
        />
        <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-1 opacity-40 group-focus-within:opacity-0 transition-opacity">
          <Command className="w-3 h-3" />
          <span className="text-[10px] font-bold">K</span>
        </div>
        {loading && <Loader2 className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-primary animate-spin" />}
      </div>

      {isOpen && allResults.length > 0 && (
        <div className="absolute mt-3 w-[450px] left-0 glass-panel rounded-2xl shadow-2xl z-50 overflow-hidden border border-white/10 animate-entry">
          <div className="p-2 max-h-[400px] overflow-y-auto custom-scrollbar">
            {allResults.map((item, index) => (
              <button
                key={`${item.type}-${item.id}`}
                onClick={() => {
                  navigate(item.path);
                  setIsOpen(false);
                  setQuery('');
                }}
                className={`w-full flex items-center gap-4 px-4 py-3 rounded-xl transition-all text-left ${
                  selectedIndex === index ? 'bg-primary/20 border-l-4 border-primary' : 'hover:bg-white/5 border-l-4 border-transparent'
                }`}
              >
                <div className={`p-2 rounded-lg bg-white/5`}>
                  {item.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex justify-between items-center mb-0.5">
                    <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{item.type}</span>
                    {item.severity && (
                      <span className={`text-[8px] px-1.5 py-0.5 rounded-full font-bold ${
                        item.severity === 'critical' ? 'bg-error/20 text-error' : 'bg-primary/20 text-primary'
                      }`}>
                        {item.severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-medium text-white truncate">{item.label}</p>
                </div>
              </button>
            ))}
          </div>
          <div className="p-3 bg-slate-950/40 border-t border-white/5 flex justify-between items-center">
            <div className="flex gap-4">
              <div className="flex items-center gap-1.5">
                <span className="p-1 rounded bg-white/10 text-[8px] font-bold">↑↓</span>
                <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Navigate</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="p-1 rounded bg-white/10 text-[8px] font-bold">↵</span>
                <span className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Select</span>
              </div>
            </div>
            <span className="text-[9px] text-primary/60 font-bold uppercase tracking-[0.2em]">Sovereign AI Search</span>
          </div>
        </div>
      )}
    </div>
  );
};

export default GlobalSearch;
