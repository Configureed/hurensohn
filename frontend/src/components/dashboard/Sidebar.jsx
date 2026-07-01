import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../../context/AuthContext';
import { 
  Monitor, 
  Terminal, 
  ShieldCheck, 
  HelpCircle,
  LogOut,
  User,
  Crown
} from 'lucide-react';

const Sidebar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { to: '/dashboard/devices', icon: Monitor, label: 'Devices' },
    { to: '/dashboard/generator', icon: Terminal, label: 'Generator' },
    { to: '/dashboard/security', icon: ShieldCheck, label: 'Security' },
    { to: '/dashboard/infos', icon: HelpCircle, label: 'Support' },
  ];

  const isOwner = user?.role === 'owner' || user?.username?.toLowerCase() === 'voip';

  return (
    <motion.aside
      initial={{ x: -280 }}
      animate={{ x: 0 }}
      transition={{ duration: 0.3 }}
      className="fixed top-0 left-0 h-full w-[280px] bg-[#0d0b14]/80 backdrop-blur-xl border-r border-white/5 p-6 flex flex-col z-50"
    >
      <div className="mb-12 flex items-center gap-3">
        <div className="w-10 h-10 bg-purple-600 rounded-xl flex items-center justify-center shadow-lg shadow-purple-900/40">
          <svg className="w-6 h-6 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A10.003 10.003 0 0012 21a10.003 10.003 0 008.454-4.686 10.003 10.003 0 00-5.101-9.758L15 6.5l-.546.546a10.003 10.003 0 00-5.101 9.758l.054.09" />
          </svg>
        </div>
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">OathNet</h1>
          <p className="text-[10px] font-bold text-purple-400 uppercase tracking-widest">Enterprise</p>
        </div>
      </div>

      <nav className="flex-1 space-y-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `flex items-center space-x-3 px-4 py-3.5 rounded-xl transition-all ${
                isActive
                  ? 'bg-purple-600 text-white shadow-lg shadow-purple-900/20'
                  : 'text-white/40 hover:text-white hover:bg-white/5'
              }`
            }
          >
            <item.icon size={20} className={({ isActive }) => isActive ? 'text-white' : 'text-inherit'} />
            <span className="font-semibold text-sm tracking-tight">{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="mt-auto pt-6 border-t border-white/5">
        <div className="bg-white/5 rounded-2xl p-4 mb-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-purple-600/20 border border-purple-500/20 flex items-center justify-center text-purple-400 relative">
              {isOwner ? <Crown size={20} /> : <User size={20} />}
              {isOwner && (
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-purple-500 rounded-full border-2 border-[#0d0b14]" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-bold text-white truncate flex items-center gap-1.5">
                {user?.username}
                {isOwner && <span className="text-[10px] bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded uppercase">Owner</span>}
              </p>
              <p className="text-[10px] text-white/30 truncate uppercase tracking-tighter">ID: {user?.accountId}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-red-400/60 hover:text-red-400 hover:bg-red-500/10 transition-all text-xs font-bold"
          >
            <LogOut size={14} />
            Logout Session
          </button>
        </div>
        <p className="text-center text-[10px] text-white/10 font-bold uppercase tracking-[0.2em]">OathNet v1.0.0</p>
      </div>
    </motion.aside>
  );
};

export default Sidebar;