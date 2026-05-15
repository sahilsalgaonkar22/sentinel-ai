import React, { useState } from 'react';
import { Search, Bell, Activity, ShieldCheck, User } from 'lucide-react';
import GlobalSearch from '../GlobalSearch';
import NotificationCenter from '../NotificationCenter';
import useNotificationStore from '../../stores/notificationStore';
import useAuthStore from '../../stores/authStore';

const TopBar = () => {
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const { unreadCount } = useNotificationStore();
  const { user, role, logout } = useAuthStore();

  return (
    <header className="fixed top-0 right-0 left-72 z-40 px-8 py-4 backdrop-blur-xl bg-slate-950/20 border-b border-white/5 flex justify-between items-center">
      <div className="flex items-center gap-10">
        <GlobalSearch />
        
        <div className="hidden xl:flex gap-8">
          <a className="text-slate-400 hover:text-white text-[10px] font-bold uppercase tracking-[0.2em] transition-all flex items-center gap-2" href="#">
            <Activity className="w-3 h-3 text-secondary" />
            Live Stream
          </a>
          <a className="text-slate-400 hover:text-white text-[10px] font-bold uppercase tracking-[0.2em] transition-all flex items-center gap-2" href="#">
            <ShieldCheck className="w-3 h-3 text-primary" />
            Archive
          </a>
        </div>
      </div>

      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 text-[9px] font-bold text-primary px-3 py-1.5 bg-primary/10 rounded-full border border-primary/20">
          <span className="relative flex h-1.5 w-1.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-primary"></span>
          </span>
          SYNC_LOCKED
        </div>

        <div className="relative">
          <button 
            onClick={() => setIsNotificationsOpen(!isNotificationsOpen)}
            className="p-2 text-slate-400 hover:text-primary transition-all relative hover:bg-white/5 rounded-xl"
          >
            <Bell className="w-5 h-5" />
            {unreadCount > 0 && (
              <span className="absolute top-2 right-2 w-2 h-2 bg-error rounded-full ring-2 ring-slate-950"></span>
            )}
          </button>
          
          <NotificationCenter 
            isOpen={isNotificationsOpen} 
            onClose={() => setIsNotificationsOpen(false)} 
          />
        </div>

        <div className="flex items-center gap-3 border-l border-white/10 pl-6">
          <div className="text-right">
            <p className="text-[10px] font-bold text-white font-headline leading-none mb-1">
              {user?.sub?.split('@')[0].toUpperCase() || 'ADMIN_01'}
            </p>
            <p className="text-[8px] text-primary/60 font-bold uppercase tracking-tighter">
              {role?.toUpperCase() || 'ROOT AUTHORITY'}
            </p>
          </div>
          <div className="relative group cursor-pointer">
            <div className="w-9 h-9 rounded-full border-2 border-primary/20 overflow-hidden group-hover:border-primary/50 transition-all">
              <img 
                className="w-full h-full object-cover" 
                src="https://lh3.googleusercontent.com/aida-public/AB6AXuBkBnx5Yi-PC6o9HlZ8ksgYDINPV3woTvsrTYDkEjccRjc1b0FHlLrC-R7WugJ5YaiyE6SDiDf5Mwk7-YLij5rhkRbdy_vHrZi6iqryaesB6nC2sR2Yleg4PiB4YSY4y4JvVVglHfQ8ueIvqeg48MTNMS5B_KGC-mV9fXfI0vKyXQsirp9w3yzGiN8kPCOc05c3b8K8npmDWCnOdS7dPxLy6bhp4cPRNTtljDA4wfb-bkWLjPeDJZR6_I2_XAHAVgEbBywn5dGjIJ1F"
                alt="Profile"
              />
            </div>
            <div className="absolute -bottom-0.5 -right-0.5 w-3 h-3 bg-green-500 border-2 border-slate-950 rounded-full"></div>
            
            {/* User Dropdown */}
            <div className="absolute right-0 mt-2 w-48 glass-panel rounded-xl shadow-2xl border border-white/10 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-50 p-1">
              <button 
                onClick={logout}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-xs font-bold text-slate-400 hover:text-error hover:bg-error/10 rounded-lg transition-all"
              >
                <User className="w-4 h-4" />
                TERMINAL EXIT
              </button>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};

export default TopBar;
