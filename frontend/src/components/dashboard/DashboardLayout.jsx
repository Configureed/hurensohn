import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import Sidebar from './Sidebar';
import DevicesPage from './DevicesPage';
import GeneratorPage from './GeneratorPage';
import InfosPage from './InfosPage';
import SecurityPage from './SecurityPage';

const DashboardLayout = () => {
  return (
    <div className="min-h-screen bg-[#0d0b14] relative overflow-hidden flex">
      {/* Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-purple-900/5 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-900/5 blur-[120px] rounded-full pointer-events-none" />
      
      <Sidebar />
      <motion.main
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex-1 ml-0 lg:ml-[280px] relative z-10"
      >
        <div className="h-full overflow-y-auto">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard/devices" />} />
            <Route path="/devices" element={<DevicesPage />} />
            <Route path="/generator" element={<GeneratorPage />} />
            <Route path="/infos" element={<InfosPage />} />
            <Route path="/security" element={<SecurityPage />} />
          </Routes>
        </div>
      </motion.main>
    </div>
  );
};

export default DashboardLayout;