import { create } from 'zustand';
import { aiAPI } from '../api/client';

const useAIStore = create((set) => ({
  isOpen: false,
  history: [{ role: 'assistant', content: 'Sovereign AI initialized. How can I assist you with threat analysis today?' }],
  isTyping: false,

  setOpen: (isOpen) => set({ isOpen }),
  toggle: () => set((state) => ({ isOpen: !state.isOpen })),
  
  sendMessage: async (message) => {
    set((state) => ({
       history: [...state.history, { role: 'user', content: message }],
       isTyping: true
    }));
    try {
      const res = await aiAPI.chat(message);
      set((state) => ({
         history: [...state.history, { role: 'assistant', content: res.data.reply }],
         isTyping: false
      }));
    } catch (error) {
      console.error(error);
      set((state) => ({
         history: [...state.history, { role: 'assistant', content: 'Error communicating with intelligence node.' }],
         isTyping: false
      }));
    }
  },
  clearHistory: () => set({ history: [{ role: 'assistant', content: 'Sovereign AI memory cleared.' }] })
}));

export default useAIStore;
