import { create } from 'zustand';

const useUIStore = create((set) => ({
  isAIAssistantOpen: false,
  toggleAIAssistant: () => set((state) => ({ isAIAssistantOpen: !state.isAIAssistantOpen })),
}));

export default useUIStore;
