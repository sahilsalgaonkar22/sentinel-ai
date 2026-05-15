import React, { useState, useEffect, useRef } from 'react';
import useUIStore from '../stores/uiStore';
import { aiAPI } from '../api/client';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  BrainCircuit, 
  Send, 
  X, 
  Zap, 
  ShieldAlert, 
  ShieldCheck, 
  Cpu, 
  Bot, 
  User,
  Loader2,
  Terminal,
  Sparkles
} from 'lucide-react';

const AIAssistant = () => {
  const { isAIAssistantOpen, toggleAIAssistant } = useUIStore();
  const [messages, setMessages] = useState([
    { 
      role: 'assistant', 
      content: "Sovereign AI initialized. Analyzing system vectors... How can I assist with your security posture today?",
      timestamp: new Date().toISOString()
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    if (input.trim() === '' || isLoading) return;

    const userMsg = { role: 'user', content: input, timestamp: new Date().toISOString() };
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await aiAPI.chat(input);
      const assistantMsg = { 
        role: 'assistant', 
        content: response.data.response,
        timestamp: new Date().toISOString()
      };
      setMessages(prev => [...prev, assistantMsg]);
    } catch (error) {
      console.error("AI Assistant error:", error);
      setMessages(prev => [...prev, { 
        role: 'assistant', 
        content: "Neural link interrupted. Please verify API connectivity.",
        type: 'error',
        timestamp: new Date().toISOString()
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AnimatePresence>
      {isAIAssistantOpen && (
        <>
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/40 backdrop-blur-sm z-[55]"
            onClick={toggleAIAssistant}
          />
          <motion.div 
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed top-4 right-4 bottom-4 w-[450px] glass-panel rounded-[32px] border border-white/10 shadow-2xl z-[60] flex flex-col overflow-hidden bg-slate-950/80 backdrop-blur-3xl"
          >
            {/* Header */}
            <div className="p-6 border-b border-white/5 bg-white/5 flex justify-between items-center">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-primary/10 text-primary">
                  <BrainCircuit className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white uppercase tracking-widest font-headline">Sovereign AI</h3>
                  <div className="flex items-center gap-1.5 mt-0.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></span>
                    <span className="text-[9px] font-bold text-slate-500 uppercase tracking-tighter">Neural Link Active</span>
                  </div>
                </div>
              </div>
              <button onClick={toggleAIAssistant} className="p-2 hover:bg-white/10 rounded-xl transition-all">
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar" ref={scrollRef}>
              {messages.map((msg, index) => (
                <motion.div 
                  key={index}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`flex gap-4 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                    msg.role === 'user' ? 'bg-secondary/10 text-secondary' : 'bg-primary/10 text-primary'
                  }`}>
                    {msg.role === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                  </div>
                  <div className={`max-w-[80%] space-y-2 ${msg.role === 'user' ? 'items-end' : ''}`}>
                    <div className={`p-4 rounded-2xl text-sm leading-relaxed ${
                      msg.role === 'user' 
                        ? 'bg-secondary/10 text-white rounded-tr-none border border-secondary/20' 
                        : 'bg-white/5 text-slate-300 rounded-tl-none border border-white/5'
                    } ${msg.type === 'error' ? 'border-error/30 text-error' : ''}`}>
                      {msg.content}
                    </div>
                    <span className="text-[8px] font-bold text-slate-600 uppercase tracking-widest px-1">
                      {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </motion.div>
              ))}
              {isLoading && (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex gap-4"
                >
                  <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center">
                    <Loader2 className="w-4 h-4 animate-spin" />
                  </div>
                  <div className="bg-white/5 border border-white/5 p-4 rounded-2xl rounded-tl-none">
                    <div className="flex gap-1">
                      <div className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '0ms' }}></div>
                      <div className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '150ms' }}></div>
                      <div className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce" style={{ animationDelay: '300ms' }}></div>
                    </div>
                  </div>
                </motion.div>
              )}
            </div>

            {/* Input */}
            <div className="p-6 bg-slate-950/60 border-t border-white/5">
              <div className="relative group">
                <div className="absolute left-4 top-1/2 -translate-y-1/2 p-1.5 rounded-lg bg-white/5 text-slate-500 group-focus-within:text-primary transition-all">
                  <Terminal className="w-4 h-4" />
                </div>
                <input 
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                  placeholder="Ask Sovereign AI anything..."
                  className="w-full bg-white/5 border border-white/5 rounded-2xl py-4 pl-14 pr-14 text-sm text-white focus:ring-1 focus:ring-primary/40 focus:bg-white/10 transition-all outline-none placeholder:text-slate-600"
                />
                <button 
                  onClick={handleSend}
                  disabled={!input.trim() || isLoading}
                  className="absolute right-3 top-1/2 -translate-y-1/2 p-2 rounded-xl bg-primary text-black disabled:opacity-50 disabled:grayscale transition-all hover:scale-105 active:scale-95 shadow-[0_0_20px_rgba(189,157,255,0.3)]"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
              <div className="mt-4 flex justify-between items-center px-1">
                <div className="flex gap-4">
                  <button className="text-[9px] font-bold text-slate-500 hover:text-primary transition-colors uppercase tracking-widest flex items-center gap-1.5">
                    <Zap className="w-3 h-3" />
                    Explain Risk
                  </button>
                  <button className="text-[9px] font-bold text-slate-500 hover:text-primary transition-colors uppercase tracking-widest flex items-center gap-1.5">
                    <ShieldAlert className="w-3 h-3" />
                    How to fix?
                  </button>
                </div>
                <span className="text-[9px] font-bold text-primary/40 uppercase tracking-[0.2em] flex items-center gap-1.5">
                  <Sparkles className="w-3 h-3" />
                  GPT-4o Enhanced
                </span>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default AIAssistant;