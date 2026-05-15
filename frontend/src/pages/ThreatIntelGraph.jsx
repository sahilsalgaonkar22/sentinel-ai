import React, { useState, useEffect } from 'react';
import { scanAPI, vulnAPI } from '../api/client';
import { motion } from 'framer-motion';
import {
  Shield, AlertTriangle, Activity, Target, Radar,
  Search, ChevronRight, ExternalLink, Clock, TrendingUp
} from 'lucide-react';

const SEV_CONFIG = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.1)', border: 'rgba(239,68,68,0.3)', label: 'CRITICAL' },
  high:     { color: '#f97316', bg: 'rgba(249,115,22,0.1)', border: 'rgba(249,115,22,0.3)', label: 'HIGH' },
  medium:   { color: '#eab308', bg: 'rgba(234,179,8,0.1)',  border: 'rgba(234,179,8,0.3)',  label: 'MEDIUM' },
  low:      { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',  border: 'rgba(34,197,94,0.3)',  label: 'LOW' },
  info:     { color: '#60a5fa', bg: 'rgba(96,165,250,0.1)', border: 'rgba(96,165,250,0.3)', label: 'INFO' },
};

const ThreatIntelGraph = () => {
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [filterSev, setFilterSev] = useState('all');

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [vulnRes, scanRes] = await Promise.allSettled([
          vulnAPI.list({ per_page: 50 }),
          scanAPI.list(),
        ]);
        if (vulnRes.status === 'fulfilled') {
          const data = vulnRes.value.data;
          setFindings(data.items || []);
          // Compute stats from findings
          const items = data.items || [];
          setStats({
            total: data.total || items.length,
            critical: items.filter(f => f.severity === 'critical').length,
            high: items.filter(f => f.severity === 'high').length,
            medium: items.filter(f => f.severity === 'medium').length,
            low: items.filter(f => f.severity === 'low').length,
          });
        }
        if (scanRes.status === 'fulfilled') {
          const sData = scanRes.value.data;
          setScans(Array.isArray(sData) ? sData : (sData.items || []));
        }
      } catch(err) {
        console.error('Threat Intel fetch error:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const filtered = findings.filter(f => {
    const matchSearch = !searchTerm ||
      f.title?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.cve_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.tool_name?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchSev = filterSev === 'all' || f.severity === filterSev;
    return matchSearch && matchSev;
  });

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#bd9dff' }}>
        <Radar className="animate-spin" style={{ width: 32, height: 32, marginRight: 12 }} />
        <span style={{ fontSize: 14, letterSpacing: '0.2em', textTransform: 'uppercase' }}>Loading Threat Intelligence...</span>
      </div>
    );
  }

  return (
    <div style={{ padding: 24, minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
            <Shield style={{ width: 28, height: 28, color: '#bd9dff' }} />
            Threat Intelligence
          </h1>
          <p style={{ color: '#64748b', fontSize: 13, marginTop: 4 }}>
            Real-time threat landscape — findings from {scans.filter(s => s.status === 'completed').length} completed scans
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16, marginBottom: 24 }}>
        {[
          { label: 'Total Threats', value: stats.total, color: '#bd9dff', icon: Target },
          { label: 'Critical', value: stats.critical, color: '#ef4444', icon: AlertTriangle },
          { label: 'High', value: stats.high, color: '#f97316', icon: Activity },
          { label: 'Medium', value: stats.medium, color: '#eab308', icon: TrendingUp },
          { label: 'Low / Info', value: stats.low, color: '#22c55e', icon: Shield },
        ].map(({ label, value, color, icon: Icon }, i) => (
          <motion.div
            key={label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            style={{
              background: 'rgba(15,22,41,0.6)',
              border: `1px solid ${color}33`,
              borderRadius: 16,
              padding: '20px 24px',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            <div style={{ position: 'absolute', top: 12, right: 16, opacity: 0.15 }}>
              <Icon style={{ width: 40, height: 40, color }} />
            </div>
            <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', fontWeight: 700, marginBottom: 8 }}>{label}</div>
            <div style={{ fontSize: 32, fontWeight: 900, color, lineHeight: 1 }}>{value}</div>
          </motion.div>
        ))}
      </div>

      {/* Search + Filter Bar */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20, alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Search style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', width: 16, height: 16, color: '#64748b' }} />
          <input
            type="text"
            placeholder="Search threats by CVE, title, tool..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '12px 16px 12px 40px',
              background: 'rgba(15,22,41,0.6)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 12,
              color: '#e2e8f0',
              fontSize: 13,
              outline: 'none',
            }}
          />
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {['all', 'critical', 'high', 'medium', 'low'].map(sev => {
            const c = sev === 'all' ? '#bd9dff' : SEV_CONFIG[sev]?.color || '#64748b';
            return (
              <button
                key={sev}
                onClick={() => setFilterSev(sev)}
                style={{
                  padding: '8px 16px',
                  borderRadius: 10,
                  fontSize: 10,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  cursor: 'pointer',
                  border: `1px solid ${filterSev === sev ? c : 'transparent'}`,
                  background: filterSev === sev ? `${c}22` : 'rgba(15,22,41,0.4)',
                  color: filterSev === sev ? c : '#64748b',
                  transition: 'all 0.2s',
                }}
              >
                {sev}
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: selectedFinding ? '1fr 400px' : '1fr', gap: 20 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {filtered.length === 0 ? (
            <div style={{
              padding: 60, textAlign: 'center', color: '#64748b',
              background: 'rgba(15,22,41,0.4)', borderRadius: 16, border: '1px solid rgba(255,255,255,0.05)',
            }}>
              <Shield style={{ width: 48, height: 48, margin: '0 auto 16px', opacity: 0.3 }} />
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>No threats match current filters</div>
              <div style={{ fontSize: 12 }}>Try adjusting your search or run a new scan</div>
            </div>
          ) : (
            filtered.map((f, i) => {
              const sev = SEV_CONFIG[f.severity] || SEV_CONFIG.info;
              return (
                <motion.div
                  key={f.id || i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: Math.min(i * 0.02, 0.5) }}
                  onClick={() => setSelectedFinding(f)}
                  style={{
                    background: selectedFinding?.id === f.id ? 'rgba(189,157,255,0.08)' : 'rgba(15,22,41,0.5)',
                    border: `1px solid ${selectedFinding?.id === f.id ? 'rgba(189,157,255,0.3)' : 'rgba(255,255,255,0.06)'}`,
                    borderRadius: 14,
                    padding: '16px 20px',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 16,
                  }}
                >
                  {/* Severity badge */}
                  <div style={{
                    padding: '4px 10px',
                    borderRadius: 6,
                    fontSize: 9,
                    fontWeight: 800,
                    letterSpacing: '0.1em',
                    color: sev.color,
                    background: sev.bg,
                    border: `1px solid ${sev.border}`,
                    minWidth: 70,
                    textAlign: 'center',
                  }}>
                    {sev.label}
                  </div>

                  {/* Content */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0', marginBottom: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.title}
                    </div>
                    <div style={{ display: 'flex', gap: 12, fontSize: 11, color: '#64748b' }}>
                      {f.cve_id && <span style={{ color: '#f97316', fontWeight: 600 }}>{f.cve_id}</span>}
                      {f.tool_name && <span>via {f.tool_name}</span>}
                      {f.cvss_score && <span>CVSS: {f.cvss_score}</span>}
                    </div>
                  </div>

                  <ChevronRight style={{ width: 16, height: 16, color: '#334155', flexShrink: 0 }} />
                </motion.div>
              );
            })
          )}
        </div>

        {/* Detail Panel */}
        {selectedFinding && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            style={{
              background: 'rgba(15,22,41,0.7)',
              border: '1px solid rgba(189,157,255,0.2)',
              borderRadius: 20,
              padding: 28,
              position: 'sticky',
              top: 24,
              maxHeight: 'calc(100vh - 48px)',
              overflowY: 'auto',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div>
                <div style={{ fontSize: 10, color: '#bd9dff', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.2em', marginBottom: 6 }}>
                  Threat Analysis
                </div>
                <h3 style={{ fontSize: 16, fontWeight: 700, color: '#f1f5f9', margin: 0, lineHeight: 1.4 }}>
                  {selectedFinding.title}
                </h3>
              </div>
              <button onClick={() => setSelectedFinding(null)} style={{
                background: 'rgba(255,255,255,0.05)', border: 'none', color: '#64748b',
                width: 28, height: 28, borderRadius: 8, cursor: 'pointer', fontSize: 14,
              }}>×</button>
            </div>

            {/* Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 20 }}>
              <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '12px 16px' }}>
                <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 4 }}>Severity</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: SEV_CONFIG[selectedFinding.severity]?.color || '#e2e8f0' }}>
                  {selectedFinding.severity?.toUpperCase()}
                </div>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '12px 16px' }}>
                <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 4 }}>CVSS Score</div>
                <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>{selectedFinding.cvss_score || '—'}</div>
              </div>
              {selectedFinding.cve_id && (
                <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '12px 16px' }}>
                  <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 4 }}>CVE ID</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#f97316' }}>{selectedFinding.cve_id}</div>
                </div>
              )}
              {selectedFinding.cwe_id && (
                <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '12px 16px' }}>
                  <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 4 }}>CWE ID</div>
                  <div style={{ fontSize: 13, fontWeight: 600, color: '#60a5fa' }}>{selectedFinding.cwe_id}</div>
                </div>
              )}
              <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '12px 16px' }}>
                <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 4 }}>Scanner</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#22c55e' }}>{selectedFinding.tool_name || '—'}</div>
              </div>
              <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '12px 16px' }}>
                <div style={{ fontSize: 9, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.15em', marginBottom: 4 }}>Status</div>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#eab308' }}>{selectedFinding.status || 'Open'}</div>
              </div>
            </div>

            {/* Description */}
            {selectedFinding.description && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 9, color: '#bd9dff', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.2em', marginBottom: 8 }}>
                  Description
                </div>
                <div style={{ fontSize: 12, color: '#94a3b8', lineHeight: 1.7, padding: 14, background: 'rgba(189,157,255,0.04)', borderRadius: 12, border: '1px solid rgba(189,157,255,0.1)' }}>
                  {selectedFinding.description}
                </div>
              </div>
            )}

            {/* Evidence */}
            {selectedFinding.evidence && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 9, color: '#f97316', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.2em', marginBottom: 8 }}>
                  Evidence
                </div>
                <pre style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5, padding: 14, background: 'rgba(249,115,22,0.04)', borderRadius: 12, border: '1px solid rgba(249,115,22,0.1)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
                  {typeof selectedFinding.evidence === 'object' ? JSON.stringify(selectedFinding.evidence, null, 2) : selectedFinding.evidence}
                </pre>
              </div>
            )}

            {/* Remediation */}
            {selectedFinding.remediation && (
              <div>
                <div style={{ fontSize: 9, color: '#22c55e', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.2em', marginBottom: 8 }}>
                  Remediation
                </div>
                <div style={{ fontSize: 12, color: '#86efac', lineHeight: 1.7, padding: 14, background: 'rgba(34,197,94,0.04)', borderRadius: 12, border: '1px solid rgba(34,197,94,0.1)' }}>
                  {selectedFinding.remediation}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default ThreatIntelGraph;
