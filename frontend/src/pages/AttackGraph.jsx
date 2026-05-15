import React, { useEffect, useRef, useState } from 'react';
import { aiAPI, vulnAPI } from '../api/client';

const NODE_COLORS = {
  actor: '#ef4444',
  asset: '#3b82f6',
  vulnerability: '#f59e0b',
  default: '#6b7280',
};

const SEV_COLORS = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
};

export default function AttackGraph() {
  const canvasRef = useRef(null);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [attackPaths, setAttackPaths] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      try {
        const [graphRes, pathsRes] = await Promise.allSettled([
          aiAPI.getAttackGraph(),
          vulnAPI.listAttackPaths(),
        ]);

        if (graphRes.status === 'fulfilled') {
          setGraphData(graphRes.value.data);
        }
        if (pathsRes.status === 'fulfilled') {
          const data = pathsRes.value.data;
          setAttackPaths(Array.isArray(data) ? data : data?.items || []);
        }
      } catch {
        setError('Failed to load attack graph data');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  // Simple canvas-based force layout
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !graphData.nodes.length) return;

    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;

    // Assign initial positions
    const positions = {};
    graphData.nodes.forEach((node, i) => {
      const angle = (i / graphData.nodes.length) * Math.PI * 2;
      positions[node.id] = {
        x: W / 2 + Math.cos(angle) * 200,
        y: H / 2 + Math.sin(angle) * 150,
        vx: 0,
        vy: 0,
      };
    });

    let frame;
    const simulate = () => {
      // Simple repulsion + attraction (Optimized for > 100 nodes)
      graphData.nodes.forEach((a, index) => {
        for(let j = index + 1; j < graphData.nodes.length; j++) {
          const b = graphData.nodes[j];
          const dx = positions[b.id].x - positions[a.id].x;
          const dy = positions[b.id].y - positions[a.id].y;
          const distSq = (dx * dx + dy * dy) || 1;
          
          if (distSq > 62500) continue; // 250px cutoff to prevent O(N^2) choking
          
          const dist = Math.sqrt(distSq);
          const force = -3000 / distSq;
          const fX = (dx / dist) * force * 0.01;
          const fY = (dy / dist) * force * 0.01;
          
          positions[a.id].vx += fX;
          positions[a.id].vy += fY;
          positions[b.id].vx -= fX;
          positions[b.id].vy -= fY;
        }
      });

      graphData.links.forEach((link) => {
        const src = positions[link.source];
        const tgt = positions[link.target];
        if (!src || !tgt) return;
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist - 120) * 0.05;
        src.vx += (dx / dist) * force;
        src.vy += (dy / dist) * force;
        tgt.vx -= (dx / dist) * force;
        tgt.vy -= (dy / dist) * force;
      });

      graphData.nodes.forEach((node) => {
        const p = positions[node.id];
        p.vx *= 0.85;
        p.vy *= 0.85;
        p.x = Math.max(20, Math.min(W - 20, p.x + p.vx));
        p.y = Math.max(20, Math.min(H - 20, p.y + p.vy));
      });

      // Draw
      ctx.clearRect(0, 0, W, H);
      ctx.fillStyle = '#0a0f1e';
      ctx.fillRect(0, 0, W, H);

      // Draw edges
      graphData.links.forEach((link) => {
        const src = positions[link.source];
        const tgt = positions[link.target];
        if (!src || !tgt) return;
        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = 'rgba(239,68,68,0.4)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Arrow
        const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
        const ax = tgt.x - Math.cos(angle) * 20;
        const ay = tgt.y - Math.sin(angle) * 20;
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - 8 * Math.cos(angle - 0.4), ay - 8 * Math.sin(angle - 0.4));
        ctx.lineTo(ax - 8 * Math.cos(angle + 0.4), ay - 8 * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = 'rgba(239,68,68,0.7)';
        ctx.fill();
      });

      // Draw nodes
      graphData.nodes.forEach((node) => {
        const p = positions[node.id];
        const color = NODE_COLORS[node.type] || NODE_COLORS.default;
        const radius = (node.size || 12) * 0.8;

        // Glow
        const grd = ctx.createRadialGradient(p.x, p.y, 0, p.x, p.y, radius * 2);
        grd.addColorStop(0, color + '66');
        grd.addColorStop(1, 'transparent');
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius * 2, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

        // Node circle
        ctx.beginPath();
        ctx.arc(p.x, p.y, radius, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#ffffff33';
        ctx.lineWidth = 1;
        ctx.stroke();

        // Label
        ctx.font = '11px Inter, sans-serif';
        ctx.fillStyle = '#e2e8f0';
        ctx.textAlign = 'center';
        ctx.fillText(node.name, p.x, p.y + radius + 14);
      });

      frame = requestAnimationFrame(simulate);
    };

    // Run 80 frames then stop
    let count = 0;
    const run = () => {
      simulate();
      count++;
      if (count < 80) frame = requestAnimationFrame(run);
    };
    frame = requestAnimationFrame(run);

    return () => cancelAnimationFrame(frame);
  }, [graphData]);

  return (
    <div style={{ background: '#0a0f1e', minHeight: '100vh', color: '#e2e8f0', padding: '24px' }}>
      <h1 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '8px', color: '#f8fafc' }}>
        ⚡ Attack Graph
      </h1>
      <p style={{ color: '#94a3b8', marginBottom: '24px' }}>
        AI-generated attack path visualization — derived from real vulnerability findings
      </p>

      {error && (
        <div style={{ background: '#1e1b4b', border: '1px solid #ef4444', borderRadius: 8, padding: '12px 16px', marginBottom: 16, color: '#fca5a5' }}>
          {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: '20px' }}>
        {/* Graph Canvas */}
        <div style={{ background: '#0f1629', border: '1px solid #1e3a5f', borderRadius: 12, overflow: 'hidden' }}>
          {loading ? (
            <div style={{ height: 500, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#60a5fa' }}>
              Loading attack graph...
            </div>
          ) : graphData.nodes.length === 0 ? (
            <div style={{ height: 500, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: '#94a3b8' }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>🛡️</div>
              <div>No attack paths detected</div>
              <div style={{ fontSize: 12, marginTop: 8 }}>Run a scan to generate attack graph data</div>
            </div>
          ) : (
            <canvas
              ref={canvasRef}
              width={800}
              height={500}
              style={{ width: '100%', cursor: 'crosshair' }}
            />
          )}

          {/* Legend */}
          <div style={{ display: 'flex', gap: 16, padding: '12px 16px', borderTop: '1px solid #1e3a5f', flexWrap: 'wrap' }}>
            {Object.entries(NODE_COLORS).filter(([k]) => k !== 'default').map(([type, color]) => (
              <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 10, height: 10, borderRadius: '50%', background: color }} />
                <span style={{ fontSize: 12, color: '#94a3b8', textTransform: 'capitalize' }}>{type}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Paths Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ background: '#0f1629', border: '1px solid #1e3a5f', borderRadius: 12, padding: '16px' }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '12px', color: '#f1f5f9' }}>
              🔴 Critical Attack Paths
            </h2>
            {loading ? (
              <div style={{ color: '#60a5fa', fontSize: 13 }}>Loading paths...</div>
            ) : attackPaths.length === 0 ? (
              <div style={{ color: '#94a3b8', fontSize: 13 }}>No attack paths found. Run a scan first.</div>
            ) : (
              attackPaths.map((path) => (
                <div
                  key={path.id}
                  style={{
                    background: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: 8,
                    padding: '12px',
                    marginBottom: '10px',
                    cursor: 'pointer',
                  }}
                  onClick={() => setSelectedNode(path)}
                >
                  <div style={{ fontWeight: 600, fontSize: 13, color: '#f1f5f9', marginBottom: 4 }}>{path.name}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      background: SEV_COLORS[path.severity] || '#6b7280',
                      color: '#fff',
                      fontSize: 10,
                      padding: '2px 8px',
                      borderRadius: 4,
                      fontWeight: 600,
                    }}>{path.severity?.toUpperCase()}</span>
                    <span style={{ fontSize: 12, color: '#94a3b8' }}>Risk: {path.risk_score}</span>
                  </div>
                  {path.chain_steps && (
                    <div style={{ marginTop: 8 }}>
                      {path.chain_steps.map((step, i) => (
                        <div key={i} style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                          {i + 1}. {step.action}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {selectedNode && (
            <div style={{ background: '#0f1629', border: '1px solid #7c3aed', borderRadius: 12, padding: '16px' }}>
              <h2 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '10px', color: '#a78bfa' }}>
                🔍 AI Analysis
              </h2>
              <div style={{ fontSize: 13, color: '#94a3b8', lineHeight: 1.6 }}>
                {selectedNode.ai_analysis || 'No AI analysis available for this path.'}
              </div>
              {selectedNode.mitigation_steps && (
                <>
                  <div style={{ marginTop: 10, fontSize: 12, fontWeight: 600, color: '#22c55e' }}>Mitigations:</div>
                  {selectedNode.mitigation_steps.map((m, i) => (
                    <div key={i} style={{ fontSize: 12, color: '#86efac', marginTop: 4 }}>• {m}</div>
                  ))}
                </>
              )}
              <button
                onClick={() => setSelectedNode(null)}
                style={{ marginTop: 12, fontSize: 12, color: '#64748b', background: 'none', border: 'none', cursor: 'pointer' }}
              >
                ✕ Close
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
