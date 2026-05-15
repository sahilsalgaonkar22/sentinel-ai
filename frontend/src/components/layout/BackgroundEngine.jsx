import React, { useEffect } from 'react';

const BackgroundEngine = () => {
  // Use useEffect to inject particles on mount
  useEffect(() => {
    const container = document.getElementById('bg-particle-container');
    if (!container) return;

    // Clear existing
    container.innerHTML = '';
    
    // Create new particles
    for (let i = 0; i < 30; i++) {
        const p = document.createElement('div');
        p.className = 'absolute w-[2px] h-[2px] bg-[#bd9dff] rounded-full opacity-30';
        p.style.left = Math.random() * 100 + 'vw';
        p.style.animation = `floatUp ${15 + Math.random() * 20}s infinite linear`;
        p.style.animationDelay = Math.random() * 10 + 's';
        container.appendChild(p);
    }
  }, []);

  return (
    <div className="fixed inset-0 z-[-1] overflow-hidden" style={{ background: 'radial-gradient(circle at 20% 30%, #0B1220 0%, #05070D 100%)' }}>
      {/* Noise layer */}
      <div className="absolute inset-0 opacity-[0.04] pointer-events-none" style={{ backgroundImage: 'url("data:image/svg+xml,%3Csvg viewBox=\'0 0 400 400\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cfilter id=\'noiseFilter\'%3E%3CfeTurbulence type=\'fractalNoise\' baseFrequency=\'0.65\' numOctaves=\'3\' stitchTiles=\'stitch\'/%3E%3C/filter%3E%3Crect width=\'100%25\' height=\'100%25\' filter=\'url(%23noiseFilter)\'/%3E%3C/svg%3E")' }}></div>
      
      {/* Gradient Waves */}
      <div 
        className="absolute w-[150%] h-[150%] blur-[80px]" 
        style={{ top: '-20%', left: '-20%', background: 'radial-gradient(circle at center, rgba(124, 58, 237, 0.08) 0%, transparent 50%)', animation: 'waveMotion 25s infinite alternate ease-in-out' }}
      ></div>
      <div 
        className="absolute w-[150%] h-[150%] blur-[80px]" 
        style={{ bottom: '-20%', right: '-20%', background: 'radial-gradient(circle at center, rgba(124, 58, 237, 0.08) 0%, transparent 50%)', animation: 'waveMotion 25s infinite alternate ease-in-out', animationDelay: '-5s' }}
      ></div>
      
      {/* Container for JS particles */}
      <div id="bg-particle-container" className="absolute inset-0 pointer-events-none"></div>
    </div>
  );
};

export default BackgroundEngine;
