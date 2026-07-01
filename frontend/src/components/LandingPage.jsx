import React from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';

const LandingPage = () => {
  return (
    <div className="min-h-screen bg-[#0d0b14] relative overflow-hidden flex flex-col items-center">
      {/* Background Glows */}
      <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-purple-900/20 blur-[120px] rounded-full" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-900/20 blur-[120px] rounded-full" />
      
      {/* Navigation */}
      <nav className="w-full max-w-5xl mt-8 px-6 py-3 glass rounded-full flex items-center justify-between z-50">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-white/10 rounded-lg flex items-center justify-center border border-white/20">
            <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A10.003 10.003 0 0012 21a10.003 10.003 0 008.454-4.686 10.003 10.003 0 00-5.101-9.758L15 6.5l-.546.546a10.003 10.003 0 00-5.101 9.758l.054.09" />
            </svg>
          </div>
          <span className="text-xl font-bold tracking-tight">OathNet</span>
        </div>
        
        <div className="hidden md:flex items-center gap-8">
          <Link to="/" className="text-sm text-white/60 hover:text-white transition-colors">Home</Link>
          <Link to="/pricing" className="text-sm text-white/60 hover:text-white transition-colors">Pricing</Link>
          <Link to="/api" className="text-sm text-white/60 hover:text-white transition-colors">API</Link>
        </div>

        <div className="flex items-center gap-4">
          <Link to="/register" className="nav-btn nav-btn-outline">Sign Up</Link>
          <Link to="/login" className="nav-btn nav-btn-primary">Login</Link>
        </div>
      </nav>

      {/* Hero Section */}
      <main className="flex-1 flex flex-col items-center justify-center px-6 text-center z-10 max-w-4xl mt-20">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="flex items-center gap-4 mb-8"
        >
          <div className="h-[1px] w-12 bg-white/20" />
          <h1 className="text-5xl md:text-7xl font-bold tracking-tight text-white/90">
            with <span className="text-white">OathNet</span>
          </h1>
          <div className="h-[1px] w-12 bg-white/20" />
        </motion.div>

        <motion.p 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3, duration: 0.8 }}
          className="text-white/40 text-sm md:text-base max-w-2xl leading-relaxed mb-12"
        >
          Search stealer logs, breach records, exposed credentials, domains, usernames, IPs, phone numbers, Discord IDs, and related OSINT sources from one defensive platform.
          <br /><br />
          <span className="text-white/20 text-xs uppercase tracking-widest">For solo researchers, online communities, creators, startups, and enterprise teams who want fast OSINT receipts without the buzzword soup.</span>
        </motion.p>

        {/* Search Area */}
        <div className="w-full max-w-2xl relative mb-8">
          <div className="absolute inset-0 bg-purple-600/10 blur-[60px] rounded-full" />
          
          {/* Logo Circle */}
          <div className="absolute top-[-80px] left-1/2 -translate-x-1/2 w-24 h-24 glass rounded-full flex items-center justify-center p-4">
            <div className="w-full h-full bg-white/5 rounded-full flex items-center justify-center border border-white/10">
              <svg className="w-10 h-10 text-white/80" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
          </div>

          <div className="relative glass rounded-full p-2 flex items-center shadow-2xl">
            <div className="pl-6 pr-4">
              <svg className="w-5 h-5 text-white/40" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
            </div>
            <input 
              type="text" 
              placeholder="e.g. discord: 123456789012345678"
              className="bg-transparent border-none outline-none text-white w-full placeholder:text-white/20 text-sm py-2"
            />
            <button className="bg-purple-600/20 hover:bg-purple-600/40 text-purple-300 px-6 py-2 rounded-full text-sm font-semibold transition-all mr-1 flex items-center gap-2">
              Search
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14 5l7 7m0 0l-7 7m7-7H3" />
              </svg>
            </button>
          </div>
        </div>

        {/* Feature Pills */}
        <div className="flex flex-wrap justify-center gap-4 z-20">
          <div className="glass px-6 py-2 rounded-full flex items-center gap-2">
            <div className="flex bg-white/5 p-1 rounded-full">
              <span className="px-3 py-1 bg-white/10 rounded-full text-[10px] font-bold">Automated</span>
              <span className="px-3 py-1 text-[10px] font-bold text-white/40">Manual</span>
            </div>
          </div>
          
          <button className="glass px-6 py-2 rounded-full text-xs font-semibold text-white/60 hover:text-white transition-all flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 10h16M4 14h16M4 18h16" />
            </svg>
            Bulk Search
          </button>

          <button className="glass px-6 py-2 rounded-full text-xs font-semibold text-white/60 hover:text-white transition-all flex items-center gap-2 border-red-500/20">
            <svg className="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            Scanner
          </button>

          <button className="glass px-6 py-2 rounded-full text-xs font-semibold text-white/60 hover:text-white transition-all flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Secure Search
          </button>

          <button className="glass px-6 py-2 rounded-full text-xs font-semibold text-white/60 hover:text-white transition-all flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
            </svg>
            15+ Sources
          </button>
        </div>
      </main>

      {/* Footer / Blur at bottom */}
      <div className="w-full h-32 bg-gradient-to-t from-purple-900/10 to-transparent mt-20" />
    </div>
  );
};

export default LandingPage;