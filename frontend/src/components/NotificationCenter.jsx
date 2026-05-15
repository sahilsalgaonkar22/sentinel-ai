import React from 'react';
import useNotificationStore from '../stores/notificationStore';
import { Bell, X, ShieldAlert, Activity, CheckCircle2, Clock, Trash2, BellOff } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const NotificationCenter = ({ isOpen, onClose }) => {
  const { notifications, unreadCount, markAsRead, markAllAsRead, clearNotifications } = useNotificationStore();

  if (!isOpen) return null;

  const getIcon = (type) => {
    switch (type) {
      case 'critical': return <ShieldAlert className="w-4 h-4 text-error" />;
      case 'scan': return <Activity className="w-4 h-4 text-secondary" />;
      case 'success': return <CheckCircle2 className="w-4 h-4 text-green-500" />;
      default: return <Bell className="w-4 h-4 text-primary" />;
    }
  };

  return (
    <div className="absolute top-20 right-8 w-[400px] glass-panel rounded-2xl shadow-2xl z-50 overflow-hidden border border-white/10 animate-entry">
      <div className="p-4 bg-slate-950/40 border-b border-white/5 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <h3 className="text-xs font-bold text-white uppercase tracking-[0.2em] font-headline">Notification Center</h3>
          {unreadCount > 0 && (
            <span className="px-2 py-0.5 rounded-full bg-primary/20 text-primary text-[10px] font-black">
              {unreadCount} NEW
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={markAllAsRead}
            className="p-1.5 hover:bg-white/5 rounded-lg text-slate-500 hover:text-primary transition-all"
            title="Mark all as read"
          >
            <CheckCircle2 className="w-4 h-4" />
          </button>
          <button 
            onClick={clearNotifications}
            className="p-1.5 hover:bg-white/5 rounded-lg text-slate-500 hover:text-error transition-all"
            title="Clear all"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          <button onClick={onClose} className="p-1.5 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white transition-all">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="max-h-[500px] overflow-y-auto custom-scrollbar">
        <AnimatePresence initial={false}>
          {notifications.length > 0 ? (
            notifications.map((n) => (
              <motion.div
                key={n.id}
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                className={`p-4 border-b border-white/5 hover:bg-white/5 transition-all cursor-pointer relative group ${!n.read ? 'bg-primary/5' : ''}`}
                onClick={() => markAsRead(n.id)}
              >
                {!n.read && <div className="absolute left-0 top-0 bottom-0 w-1 bg-primary"></div>}
                <div className="flex gap-4">
                  <div className={`mt-1 p-2 rounded-xl ${
                    n.type === 'critical' ? 'bg-error/10' : 'bg-primary/10'
                  }`}>
                    {getIcon(n.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between items-start mb-1">
                      <p className={`text-sm font-bold truncate ${!n.read ? 'text-white' : 'text-slate-400'}`}>
                        {n.title}
                      </p>
                      <span className="text-[9px] font-medium text-slate-500 flex items-center gap-1 shrink-0">
                        <Clock className="w-2.5 h-2.5" />
                        {new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 leading-relaxed line-clamp-2 group-hover:line-clamp-none transition-all">
                      {n.message}
                    </p>
                    {n.action && (
                      <button className="mt-3 text-[10px] font-bold text-primary uppercase tracking-widest hover:text-white transition-colors">
                        {n.actionLabel || 'View Details'} →
                      </button>
                    )}
                  </div>
                </div>
              </motion.div>
            ))
          ) : (
            <div className="py-20 flex flex-col items-center justify-center text-slate-600">
              <BellOff className="w-12 h-12 mb-4 opacity-20" />
              <p className="text-xs font-bold uppercase tracking-widest">Awaiting system signals...</p>
            </div>
          )}
        </AnimatePresence>
      </div>

      {notifications.length > 0 && (
        <div className="p-3 bg-slate-950/40 border-t border-white/5 text-center">
          <span className="text-[9px] text-primary/40 font-bold uppercase tracking-[0.3em]">Guardian Monitoring Active</span>
        </div>
      )}
    </div>
  );
};

export default NotificationCenter;
