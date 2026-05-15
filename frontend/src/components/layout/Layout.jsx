import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import TopBar from './TopBar';
import BackgroundEngine from './BackgroundEngine';
import AIAssistant from '../AIAssistant';
import useUIStore from '../../stores/uiStore';

const Layout = ({ children }) => {
  const { isAIAssistantOpen } = useUIStore();

  return (
    <div className="min-h-screen selection:bg-primary/30 selection:text-white">
      <BackgroundEngine />
      <Sidebar />
      <TopBar />
      <main className="ml-72 mr-8 pt-24 pb-12 transition-all duration-500">
        <div className="page-entry">
          {children || <Outlet />}
        </div>
      </main>
      {isAIAssistantOpen && <AIAssistant />}
    </div>
  );
};

export default Layout;
