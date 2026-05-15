import { create } from 'zustand';
import { aiAPI } from '../api/client';

const useSearchStore = create((set) => ({
  query: '',
  results: null,
  isOpen: false,
  loading: false,
  
  setQuery: (query) => set({ query }),
  setIsOpen: (isOpen) => set({ isOpen }),
  
  performSearch: async (query) => {
    if (!query || query.length < 3) {
      set({ results: null, isOpen: false });
      return;
    }
    set({ loading: true, isOpen: true });
    try {
      const response = await aiAPI.search(query);
      set({ results: response.data, loading: false });
    } catch (_e) {
      set({ results: null, loading: false });
    }
  },
  
  clearSearch: () => set({ query: '', results: null, isOpen: false })
}));

export default useSearchStore;
