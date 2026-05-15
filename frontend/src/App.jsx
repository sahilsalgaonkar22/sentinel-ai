import React from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate, useLocation } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Layout from './components/layout/Layout';
import CommandCenter from './pages/CommandCenter';
import VulnerabilityExplorer from './pages/VulnerabilityExplorer';
import AssetInventory from './pages/AssetInventory';
import ScanManagement from './pages/ScanManagement';
import ThreatIntelGraph from './pages/ThreatIntelGraph';
import NetworkMap from './pages/NetworkMap';
import AIInsights from './pages/AIInsights';
import AnalyticsPage from './pages/AnalyticsPage';
import Reporting from './pages/Reporting';
import LiveScanMonitor from './pages/LiveScanMonitor';
import AIMonitor from './pages/AIMonitor';
import LoginPage from './pages/LoginPage';
import AttackGraph from './pages/AttackGraph';
import Settings from './pages/Settings';
import CompliancePage from './pages/CompliancePage';
import useAuthStore from './stores/authStore';

// Page transition variants — snappy fade + slight upward slide
const pageVariants = {
  initial: { opacity: 0, y: 16 },
  animate: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.22, ease: [0.25, 0.46, 0.45, 0.94] },
  },
  exit: {
    opacity: 0,
    y: -8,
    transition: { duration: 0.15, ease: 'easeIn' },
  },
};

const PageWrapper = ({ children }) => (
  <motion.div
    variants={pageVariants}
    initial="initial"
    animate="animate"
    exit="exit"
    style={{ width: '100%', height: '100%' }}
  >
    {children}
  </motion.div>
);

const PrivateRoute = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  return isAuthenticated ? children : <Navigate to="/login" />;
};

// Separate component so useLocation() has access to Router context
const AnimatedRoutes = () => {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} key={location.pathname}>
        <Route path="/" element={<PageWrapper><CommandCenter /></PageWrapper>} />
        <Route path="/vulnerabilities" element={<PageWrapper><VulnerabilityExplorer /></PageWrapper>} />
        <Route path="/assets" element={<PageWrapper><AssetInventory /></PageWrapper>} />
        <Route path="/scans" element={<PageWrapper><ScanManagement /></PageWrapper>} />
        <Route path="/threat-intel" element={<PageWrapper><ThreatIntelGraph /></PageWrapper>} />
        <Route path="/network" element={<PageWrapper><NetworkMap /></PageWrapper>} />
        <Route path="/ai-insights" element={<PageWrapper><AIInsights /></PageWrapper>} />
        <Route path="/analytics" element={<PageWrapper><AnalyticsPage /></PageWrapper>} />
        <Route path="/reporting" element={<PageWrapper><Reporting /></PageWrapper>} />
        <Route path="/live-monitor" element={<PageWrapper><LiveScanMonitor /></PageWrapper>} />
        <Route path="/ai-monitor" element={<PageWrapper><AIMonitor /></PageWrapper>} />
        <Route path="/attack-graph" element={<PageWrapper><AttackGraph /></PageWrapper>} />
        <Route path="/settings" element={<PageWrapper><Settings /></PageWrapper>} />
        <Route path="/compliance" element={<PageWrapper><CompliancePage /></PageWrapper>} />
      </Routes>
    </AnimatePresence>
  );
};

function App() {
  const { checkAuth } = useAuthStore();
  React.useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  return (
    <Router>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <PrivateRoute>
              <Layout>
                <AnimatedRoutes />
              </Layout>
            </PrivateRoute>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
