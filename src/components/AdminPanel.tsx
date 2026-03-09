import { useState, useEffect } from 'react';
import { useStore } from '../store';
import type { UserRole } from '../types';
import {
  ArrowLeft, Users, Settings, Shield, Crown, Ban, Trash2,
  ToggleLeft, ToggleRight, Save, Server, Mail, Lock, ShieldCheck,
  UserCheck, UserX, Activity, MessageSquare, Database, Search,
  RefreshCw, Download, AlertTriangle, Bell, Send, X, Eye, EyeOff,
  Zap, Globe, Key, FileText, HardDrive, Upload, Clock, LogOut,
  CheckCircle, XCircle, Info, ChevronDown, ChevronUp, Copy, Wifi, Bot
} from 'lucide-react';

interface LogEntry {
  id: string;
  timestamp: number;
  type: 'info' | 'warning' | 'error' | 'success';
  action: string;
  user?: string;
  details?: string;
}

interface PendingBot {
  id: string;
  username: string;
  displayName?: string | null;
  ownerId?: string | null;
  ownerUsername?: string | null;
  code: string;
  createdAt: number;
}

export function AdminPanel() {
  const {
    currentUser, users, chats, messages, serverConfig, serverUrl,
    setScreen, updateUserRole, banUser, unbanUser, deleteUser, updateServerConfig,
    fetchUsers, addNotification, authToken,
  } = useStore();

  const [tab, setTab] = useState<'overview' | 'users' | 'config' | 'moderation' | 'logs' | 'announcements' | 'storage' | 'sessions' | 'browsers' | 'botApprovals' | 'system' | 'messages' | 'server' | 'files'>('overview');
  const [browserData, setBrowserData] = useState<Record<string, { firstSeen: string; lastSeen: string; userId?: string; username?: string; visits: Array<{ timestamp?: string; action?: string; screenWidth?: number; screenHeight?: number; platform?: string; hardwareConcurrency?: number; deviceMemory?: number; userAgent?: string; timezone?: string; language?: string }> }>>({});
  const [editConfig, setEditConfig] = useState({ ...serverConfig });
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [userSearch, setUserSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedUsers, setSelectedUsers] = useState<string[]>([]);
  const [showBulkActions, setShowBulkActions] = useState(false);
  const [announcement, setAnnouncement] = useState('');
  const [serverStats, setServerStats] = useState<Record<string, number> | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logsExpanded, setLogsExpanded] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [showPasswordField, setShowPasswordField] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [maintenanceMode, setMaintenanceMode] = useState(false);
  const [maintenanceMessage, setMaintenanceMessage] = useState('Server is under maintenance. Please try again later.');
  const [loadingMaintenance, setLoadingMaintenance] = useState(false);
  const [pendingBots, setPendingBots] = useState<PendingBot[]>([]);
  const [loadingPendingBots, setLoadingPendingBots] = useState(false);
  const [selectedPendingBot, setSelectedPendingBot] = useState<PendingBot | null>(null);
  const [approvingBotId, setApprovingBotId] = useState<string | null>(null);
  const [systemHealth, setSystemHealth] = useState<any>(null);
  const [messageStats, setMessageStats] = useState<any>(null);
  const [uploadedFiles, setUploadedFiles] = useState<any[]>([]);
  const [loadingSystem, setLoadingSystem] = useState(false);
  const [performingAction, setPerformingAction] = useState<string | null>(null);
  const [allMessages, setAllMessages] = useState<any[]>([]);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [selectedMessages, setSelectedMessages] = useState<string[]>([]);
  const [messageSearch, setMessageSearch] = useState('');
  const [showSecurityLogs, setShowSecurityLogs] = useState(false);

  // Fetch server stats
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/stats`, {
          headers: { 'Authorization': `Bearer ${authToken}` },
        });
        if (response.ok) {
          const data = await response.json();
          setServerStats(data);
        }
      } catch (error) {
        console.error('Failed to fetch stats:', error);
      }
    };
    fetchStats();
  }, [serverUrl, authToken]);

  const fetchPendingBots = async () => {
    if (currentUser?.role !== 'admin') return;
    setLoadingPendingBots(true);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/bots/pending`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setPendingBots((data || []) as PendingBot[]);
      } else {
        setPendingBots([]);
      }
    } catch (e) {
      console.error('Failed to fetch pending bots:', e);
      setPendingBots([]);
    } finally {
      setLoadingPendingBots(false);
    }
  };

  const fetchAllMessages = async () => {
    if (currentUser?.role !== 'admin') return;
    setLoadingMessages(true);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/messages`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setAllMessages(data || []);
      } else {
        setAllMessages([]);
      }
    } catch (e) {
      console.error('Failed to fetch messages:', e);
      setAllMessages([]);
    } finally {
      setLoadingMessages(false);
    }
  };

  const fetchSecurityLogs = async () => {
    if (!isAdmin) return;
    setLoadingSecurityLogs(true);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/security/logs`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setSecurityLogs(data || []);
      } else {
        setSecurityLogs([]);
      }
    } catch (error) {
      console.error('Failed to fetch security logs:', error);
      setSecurityLogs([]);
    } finally {
      setLoadingSecurityLogs(false);
    }
  };

  const fetchSystemHealth = async () => {
    if (currentUser?.role !== 'admin') return;
    setLoadingSystem(true);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/health`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setSystemHealth(data);
      }
    } catch (error) {
      console.error('Failed to fetch system health:', error);
    } finally {
      setLoadingSystem(false);
    }
  };

  const fetchMessageStats = async () => {
    if (currentUser?.role !== 'admin') return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/messages/stats`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setMessageStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch message stats:', error);
    }
  };

  const fetchUploadedFiles = async () => {
    if (currentUser?.role !== 'admin') return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/files`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setUploadedFiles(data || []);
      }
    } catch (error) {
      console.error('Failed to fetch uploaded files:', error);
    }
  };

  const fetchSystemHealth = async () => {
    if (currentUser?.role !== 'admin') return;
    setLoadingSystem(true);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/health`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setSystemHealth(data);
      }
    } catch (error) {
      console.error('Failed to fetch system health:', error);
    } finally {
      setLoadingSystem(false);
    }
  };

  const fetchMessageStats = async () => {
    if (currentUser?.role !== 'admin') return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/messages/stats`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setMessageStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch message stats:', error);
    }
  };

  const fetchUploadedFiles = async () => {
    if (currentUser?.role !== 'admin') return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/files`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setUploadedFiles(data || []);
      }
    } catch (error) {
      console.error('Failed to fetch uploaded files:', error);
    }
  };

  const isAdmin = currentUser?.role === 'admin';
  const isModerator = currentUser?.role === 'moderator';

  if (!currentUser || (!isAdmin && !isModerator)) {
    return (
      <div className="flex h-full items-center justify-center bg-gray-950">
        <p className="text-red-400">Access denied. Admin or Moderator only.</p>
      </div>
    );
  }

  // Check if user can change role (admin only, can't change admin/mod roles as mod)
  const canChangeRole = (targetUser: { id: string; role: string }) => {
    if (targetUser.id === currentUser.id) return false;
    if (isAdmin) return true;
    // Moderator restrictions: can't change admin/mod roles
    if (isModerator && (targetUser.role === 'admin' || targetUser.role === 'moderator')) return false;
    return isModerator;
  };

  // Get available role options for a user
  const getRoleOptions = (targetUser: { id: string; role: string }) => {
    if (isAdmin) {
      return ['user', 'moderator', 'admin', 'banned', 'bot'];
    }
    // Moderators can only set user or banned
    if (isModerator && targetUser.role !== 'admin' && targetUser.role !== 'moderator') {
      return ['user', 'banned'];
    }
    return [];
  };

  const totalUsers = serverStats?.totalUsers ?? users.length;
  const onlineUsers = serverStats?.onlineUsers ?? users.filter(u => u.online).length;
  const bannedUsers = serverStats?.bannedUsers ?? users.filter(u => u.role === 'banned').length;
  const totalMessages = serverStats?.totalMessages ?? messages.length;
  const totalGroups = serverStats?.totalGroups ?? chats.filter(c => c.type === 'group').length;
  const totalDirect = serverStats?.totalDirect ?? chats.filter(c => c.type === 'direct').length;

  const handleSaveConfig = () => {
    updateServerConfig(editConfig);
  };

  const roleColor = (role: UserRole) => {
    switch (role) {
      case 'admin': return 'text-amber-400 bg-amber-400/10';
      case 'moderator': return 'text-blue-400 bg-blue-400/10';
      case 'banned': return 'text-red-400 bg-red-400/10';
      case 'bot': return 'text-purple-400 bg-purple-400/10';
      default: return 'text-gray-400 bg-gray-400/10';
    }
  };

  // Filter users
  const filteredUsers = users.filter(u => {
    const matchSearch = u.username.toLowerCase().includes(userSearch.toLowerCase()) ||
                       u.email.toLowerCase().includes(userSearch.toLowerCase());
    const matchRole = roleFilter === 'all' || u.role === roleFilter;
    const matchStatus = statusFilter === 'all' || 
                       (statusFilter === 'online' && u.online) ||
                       (statusFilter === 'offline' && !u.online) ||
                       (statusFilter === 'verified' && u.emailVerified) ||
                       (statusFilter === 'unverified' && !u.emailVerified);
    return matchSearch && matchRole && matchStatus;
  });

  const handleSelectUser = (userId: string) => {
    setSelectedUsers(prev => 
      prev.includes(userId) ? prev.filter(id => id !== userId) : [...prev, userId]
    );
  };

  const handleSelectAll = () => {
    const selectableUsers = filteredUsers.filter(u => {
      if (u.id === currentUser.id) return false;
      // Moderators can't select admins or other moderators
      if (isModerator && !isAdmin && (u.role === 'admin' || u.role === 'moderator')) return false;
      return true;
    });
    if (selectedUsers.length === selectableUsers.length && selectableUsers.length > 0) {
      setSelectedUsers([]);
    } else {
      setSelectedUsers(selectableUsers.map(u => u.id));
    }
  };

  const handleBulkAction = (action: 'ban' | 'unban' | 'delete' | 'makemod' | 'makeuser') => {
    selectedUsers.forEach(userId => {
      switch (action) {
        case 'ban': banUser(userId); break;
        case 'unban': unbanUser(userId); break;
        case 'delete': deleteUser(userId); break;
        case 'makemod': updateUserRole(userId, 'moderator'); break;
        case 'makeuser': updateUserRole(userId, 'user'); break;
      }
    });
    setSelectedUsers([]);
    setShowBulkActions(false);
    addNotification(`Bulk action applied to ${selectedUsers.length} users`, 'success');
  };

  const handleSendAnnouncement = async () => {
    if (!announcement.trim()) return;
    try {
      await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/announcement`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ message: announcement }),
      });
      addNotification('Announcement sent to all users', 'success');
      setAnnouncement('');
    } catch {
      addNotification('Failed to send announcement', 'error');
    }
  };

  // System functions
  const fetchSystemHealth = async () => {
    if (!isAdmin) return;
    setLoadingSystem(true);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/health`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setSystemHealth(data);
      }
    } catch (error) {
      console.error('Failed to fetch system health:', error);
    } finally {
      setLoadingSystem(false);
    }
  };

  const fetchMessageStats = async () => {
    if (!isAdmin) return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/messages/stats`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setMessageStats(data);
      }
    } catch (error) {
      console.error('Failed to fetch message stats:', error);
    }
  };

  const fetchUploadedFiles = async () => {
    if (!isAdmin) return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/files`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setUploadedFiles(data.files || []);
      }
    } catch (error) {
      console.error('Failed to fetch uploaded files:', error);
    }
  };

  const performSystemAction = async (action: string, endpoint: string, method: string = 'POST', body?: any) => {
    setPerformingAction(action);
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}${endpoint}`, {
        method,
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      
      if (response.ok) {
        const data = await response.json();
        addNotification(`${action} completed successfully`, 'success');
        
        // Refresh relevant data
        if (action.includes('backup') || action.includes('export')) {
          // Could trigger download if needed
        } else if (action.includes('delete') || action.includes('clear')) {
          if (action.includes('file')) fetchUploadedFiles();
          if (action.includes('message')) fetchMessageStats();
          if (action.includes('log')) setLogs([]);
        } else if (action.includes('restart')) {
          // Server will disconnect users
        }
        
        return data;
      } else {
        addNotification(`${action} failed`, 'error');
      }
    } catch (error) {
      console.error(`Failed to ${action}:`, error);
      addNotification(`${action} failed`, 'error');
    } finally {
      setPerformingAction(null);
    }
  };

  const exportUsers = () => {
    const data = users.map(u => ({
      username: u.username,
      email: u.email,
      role: u.role,
      online: u.online,
      emailVerified: u.emailVerified,
      createdAt: u.createdAt ? new Date(u.createdAt).toISOString() : 'N/A',
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `4messenger-users-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addNotification('Users exported successfully', 'success');
  };

  const formatTime = (ts: number) => {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDate = (ts: number) => {
    return new Date(ts).toLocaleDateString();
  };

  const logIcon = (type: string) => {
    switch (type) {
      case 'success': return <CheckCircle className="h-4 w-4 text-green-400" />;
      case 'warning': return <AlertTriangle className="h-4 w-4 text-amber-400" />;
      case 'error': return <XCircle className="h-4 w-4 text-red-400" />;
      default: return <Info className="h-4 w-4 text-blue-400" />;
    }
  };

  const [showMobileMenu, setShowMobileMenu] = useState(false);

  return (
    <div className="flex h-screen bg-gray-900">
      {/* Mobile Menu Button */}
      <button
        onClick={() => setShowMobileMenu(!showMobileMenu)}
        className="fixed top-4 left-4 z-50 md:hidden rounded-lg bg-gray-800 p-2 text-white shadow-lg"
      >
        {showMobileMenu ? <X className="h-5 w-5" /> : <Activity className="h-5 w-5" />}
      </button>

      {/* Mobile Overlay */}
      {showMobileMenu && (
        <div
          className="fixed inset-0 z-30 bg-black/50 md:hidden"
          onClick={() => setShowMobileMenu(false)}
        />
      )}

      {/* Sidebar */}
      <div className={`fixed md:relative z-40 w-64 shrink-0 border-r border-white/10 bg-gray-900/95 md:bg-gray-900/80 flex flex-col overflow-y-auto h-full transform transition-transform duration-200 ${showMobileMenu ? 'translate-x-0' : '-translate-x-full md:translate-x-0'}`}>
        <div className="p-4 border-b border-white/10">
          <button onClick={() => setScreen('chat')} className="flex items-center gap-2 text-sm text-gray-400 transition hover:text-white mb-4">
            <ArrowLeft className="h-4 w-4" /> Back to Chat
          </button>
                      <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br ${isAdmin ? 'from-amber-500 to-orange-600' : 'from-blue-500 to-indigo-600'}`}>
              {isAdmin ? <Crown className="h-5 w-5 text-white" /> : <Shield className="h-5 w-5 text-white" />}
            </div>
            <div>
              <h2 className="font-bold text-white">{isAdmin ? 'Admin Panel' : 'Mod Panel'}</h2>
              <p className="text-xs text-gray-400">{serverConfig.serverName}</p>
            </div>
          </div>
        </div>

        <nav className="p-2 space-y-1 flex-1">
          {[
            { id: 'overview' as const, icon: Activity, label: 'Overview', adminOnly: false },
            { id: 'users' as const, icon: Users, label: 'Users', adminOnly: false },
            { id: 'moderation' as const, icon: Shield, label: 'Moderation', adminOnly: false },
            { id: 'sessions' as const, icon: Wifi, label: 'Sessions', adminOnly: false },
            { id: 'botApprovals' as const, icon: Bot, label: 'Bot Approvals', adminOnly: true },
            { id: 'storage' as const, icon: HardDrive, label: 'Storage', adminOnly: true },
            { id: 'logs' as const, icon: FileText, label: 'System Logs', adminOnly: false },
            { id: 'announcements' as const, icon: Bell, label: 'Announcements', adminOnly: false },
            { id: 'browsers' as const, icon: Globe, label: 'Browser Data', adminOnly: true },
            { id: 'system' as const, icon: Zap, label: 'System', adminOnly: true },
            { id: 'messages' as const, icon: MessageSquare, label: 'Messages', adminOnly: true },
            { id: 'server' as const, icon: Server, label: 'Server Actions', adminOnly: true },
            { id: 'files' as const, icon: Upload, label: 'Files', adminOnly: true },
            { id: 'config' as const, icon: Settings, label: 'Server Config', adminOnly: true },
          ].filter(item => isAdmin || !item.adminOnly).map(item => (
            <button
              key={item.id}
              onClick={() => { setTab(item.id); setShowMobileMenu(false); }}
              className={`flex w-full items-center gap-3 rounded-xl px-4 py-2.5 text-sm transition ${
                tab === item.id ? 'bg-indigo-500/10 text-indigo-400' : 'text-gray-400 hover:bg-white/5 hover:text-white'
              }`}
            >
              <item.icon className="h-5 w-5" />
              {item.label}
              {item.id === 'botApprovals' && isAdmin && pendingBots.length > 0 && (
                <span className="ml-auto rounded-full bg-amber-500/20 px-2 py-0.5 text-[10px] font-bold text-amber-400">
                  {pendingBots.length}
                </span>
              )}
            </button>
          ))}
        </nav>

        {/* Quick Stats */}
        <div className="p-4 border-t border-white/10">
          <div className="grid grid-cols-2 gap-2 text-center">
            <div className="rounded-lg bg-white/5 p-2">
              <p className="text-lg font-bold text-white">{onlineUsers}</p>
              <p className="text-[10px] text-gray-500">Online</p>
            </div>
            <div className="rounded-lg bg-white/5 p-2">
              <p className="text-lg font-bold text-white">{totalUsers}</p>
              <p className="text-[10px] text-gray-500">Users</p>
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 md:p-6 pt-16 md:pt-6">
        {/* Header with refresh button */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between mb-6 gap-4">
          <div>
            <h3 className="text-xl md:text-2xl font-bold text-white capitalize">{tab === 'config' ? 'Server Configuration' : tab}</h3>
            <p className="text-sm text-gray-500">Last updated: {formatTime(Date.now())}</p>
          </div>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 rounded-xl bg-white/5 px-4 py-2 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {tab === 'overview' && (
          <div>
            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
              {[
                { label: 'Total Users', value: totalUsers, icon: Users, color: 'from-indigo-500 to-purple-600', change: '+12%' },
                { label: 'Online Now', value: onlineUsers, icon: Activity, color: 'from-green-500 to-emerald-600', change: `${Math.round((onlineUsers / Math.max(totalUsers, 1)) * 100)}%` },
                { label: 'Banned', value: bannedUsers, icon: Ban, color: 'from-red-500 to-rose-600' },
                { label: 'Total Messages', value: totalMessages, icon: MessageSquare, color: 'from-blue-500 to-cyan-600' },
              ].map(stat => (
                <div key={stat.label} className="rounded-2xl border border-white/10 bg-white/5 p-5 hover:bg-white/[0.07] transition">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm text-gray-400">{stat.label}</span>
                    <div className={`flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br ${stat.color}`}>
                      <stat.icon className="h-5 w-5 text-white" />
                    </div>
                  </div>
                  <div className="flex items-end justify-between">
                    <p className="text-3xl font-bold text-white">{stat.value.toLocaleString()}</p>
                    {stat.change && (
                      <span className="text-xs text-green-400">{stat.change}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>

            {/* Additional Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <Users className="h-5 w-5 text-indigo-400" />
                  <span className="text-sm text-gray-400">Chat Statistics</span>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Groups</span>
                    <span className="text-sm text-white font-medium">{totalGroups}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Direct Chats</span>
                    <span className="text-sm text-white font-medium">{totalDirect}</span>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <Shield className="h-5 w-5 text-blue-400" />
                  <span className="text-sm text-gray-400">Roles Distribution</span>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Admins</span>
                    <span className="text-sm text-amber-400 font-medium">{users.filter(u => u.role === 'admin').length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Moderators</span>
                    <span className="text-sm text-blue-400 font-medium">{users.filter(u => u.role === 'moderator').length}</span>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center gap-3 mb-3">
                  <Zap className="h-5 w-5 text-amber-400" />
                  <span className="text-sm text-gray-400">Server Status</span>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500">Status</span>
                    {maintenanceMode ? (
                      <span className="flex items-center gap-1.5 text-sm text-amber-400 font-medium">
                        <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
                        Maintenance
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-sm text-green-400 font-medium">
                        <span className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                        Online
                      </span>
                    )}
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-gray-500">Encryption</span>
                    <span className={`text-sm font-medium ${serverConfig.encryptionEnabled ? 'text-green-400' : 'text-gray-500'}`}>
                      {serverConfig.encryptionEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Server Info & Recent Activity */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Database className="h-5 w-5 text-indigo-400" /> Server Configuration
                </h4>
                <div className="space-y-3">
                  {[
                    { label: 'Server Name', value: serverConfig.serverName, icon: Globe },
                    { label: 'Encryption', value: serverConfig.encryptionEnabled ? 'Enabled' : 'Disabled', icon: Lock, color: serverConfig.encryptionEnabled ? 'text-green-400' : 'text-red-400' },
                    { label: 'CAPTCHA', value: serverConfig.captchaEnabled ? 'Enabled' : 'Disabled', icon: ShieldCheck, color: serverConfig.captchaEnabled ? 'text-green-400' : 'text-gray-500' },
                    { label: 'Email Verification', value: serverConfig.emailVerification ? 'Required' : 'Disabled', icon: Mail, color: serverConfig.emailVerification ? 'text-green-400' : 'text-gray-500' },
                    { label: 'Registration', value: serverConfig.allowRegistration ? 'Open' : 'Closed', icon: UserCheck, color: serverConfig.allowRegistration ? 'text-green-400' : 'text-red-400' },
                    { label: 'Server Password', value: serverConfig.serverPassword ? 'Set' : 'None', icon: Key, color: serverConfig.serverPassword ? 'text-amber-400' : 'text-gray-500' },
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-sm text-gray-400">
                        <item.icon className="h-4 w-4" />
                        {item.label}
                      </span>
                      <span className={`text-sm font-medium ${item.color || 'text-white'}`}>{item.value}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Users className="h-5 w-5 text-indigo-400" /> Recent Users
                </h4>
                <div className="space-y-2">
                  {users.length === 0 ? (
                    <p className="text-sm text-gray-500 text-center py-4">No users yet</p>
                  ) : (
                    users.slice(0, 5).map(u => (
                      <div key={u.id} className="flex items-center gap-3 rounded-lg p-2 hover:bg-white/5 transition">
                        <div className="relative">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-sm font-bold text-white">
                            {u.username[0].toUpperCase()}
                          </div>
                          {u.online && (
                            <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-gray-900 bg-green-500" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <span className="text-sm text-white truncate block">{u.username}</span>
                          <span className="text-xs text-gray-500">{u.email}</span>
                        </div>
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${roleColor(u.role)}`}>
                          {u.role}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'users' && (
          <div>
            {/* Toolbar */}
            <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3 mb-4">
              <div className="relative flex-1 min-w-0 sm:min-w-[200px]">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <input
                  type="text"
                  value={userSearch}
                  onChange={e => setUserSearch(e.target.value)}
                  placeholder="Search users..."
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-2 pl-10 pr-4 text-sm text-white placeholder-gray-500 outline-none focus:border-indigo-500"
                />
              </div>
              
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={roleFilter}
                  onChange={e => setRoleFilter(e.target.value)}
                  className="flex-1 sm:flex-none rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white outline-none min-w-0"
                >
                  <option value="all">All Roles</option>
                  <option value="admin">Admin</option>
                  <option value="moderator">Moderator</option>
                  <option value="user">User</option>
                  <option value="banned">Banned</option>
                  <option value="bot">Bot</option>
                </select>
                
                <select
                  value={statusFilter}
                  onChange={e => setStatusFilter(e.target.value)}
                  className="flex-1 sm:flex-none rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-white outline-none min-w-0"
                >
                  <option value="all">All Status</option>
                  <option value="online">Online</option>
                  <option value="offline">Offline</option>
                  <option value="verified">Verified</option>
                  <option value="unverified">Unverified</option>
                </select>

                {isAdmin && (
                  <button
                    onClick={exportUsers}
                    className="flex items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white"
                  >
                    <Download className="h-4 w-4" />
                    <span className="hidden sm:inline">Export</span>
                  </button>
                )}
              </div>
            </div>

            {/* Bulk Actions */}
            {selectedUsers.length > 0 && (
              <div className="mb-4 flex items-center gap-3 rounded-xl border border-indigo-500/20 bg-indigo-500/10 p-3">
                <span className="text-sm text-indigo-400">{selectedUsers.length} selected</span>
                <div className="flex-1" />
                <div className="relative">
                  <button
                    onClick={() => setShowBulkActions(!showBulkActions)}
                    className="flex items-center gap-2 rounded-lg bg-indigo-500/20 px-3 py-1.5 text-sm text-indigo-400 transition hover:bg-indigo-500/30"
                  >
                    Bulk Actions
                    {showBulkActions ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </button>
                  {showBulkActions && (
                    <div className="absolute right-0 top-full mt-1 z-10 rounded-xl border border-white/10 bg-gray-800 py-1 shadow-xl min-w-[150px]">
                      <button onClick={() => handleBulkAction('ban')} className="flex w-full items-center gap-2 px-4 py-2 text-sm text-amber-400 hover:bg-white/5">
                        <Ban className="h-4 w-4" /> Ban All
                      </button>
                      <button onClick={() => handleBulkAction('unban')} className="flex w-full items-center gap-2 px-4 py-2 text-sm text-green-400 hover:bg-white/5">
                        <UserCheck className="h-4 w-4" /> Unban All
                      </button>
                      {isAdmin && (
                        <>
                          <button onClick={() => handleBulkAction('makemod')} className="flex w-full items-center gap-2 px-4 py-2 text-sm text-blue-400 hover:bg-white/5">
                            <Shield className="h-4 w-4" /> Make Moderators
                          </button>
                          <button onClick={() => handleBulkAction('makeuser')} className="flex w-full items-center gap-2 px-4 py-2 text-sm text-gray-400 hover:bg-white/5">
                            <Users className="h-4 w-4" /> Make Users
                          </button>
                          <hr className="my-1 border-white/10" />
                          <button onClick={() => handleBulkAction('delete')} className="flex w-full items-center gap-2 px-4 py-2 text-sm text-red-400 hover:bg-white/5">
                            <Trash2 className="h-4 w-4" /> Delete All
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
                <button onClick={() => setSelectedUsers([])} className="text-gray-400 hover:text-white">
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}

            {/* Users Table */}
            <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className="px-4 py-3 text-left">
                        <input
                          type="checkbox"
                          checked={selectedUsers.length === filteredUsers.filter(u => u.id !== currentUser.id).length && filteredUsers.length > 1}
                          onChange={handleSelectAll}
                          className="rounded border-white/20 bg-white/5 text-indigo-500"
                        />
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">User</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Email</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Role</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Joined</th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5">
                    {filteredUsers.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                          {userSearch || roleFilter !== 'all' || statusFilter !== 'all' 
                            ? 'No users match your filters'
                            : 'No users in the database'}
                        </td>
                      </tr>
                    ) : null}
                    {filteredUsers.map(u => (
                      <tr key={u.id} className={`hover:bg-white/5 transition ${selectedUsers.includes(u.id) ? 'bg-indigo-500/5' : ''}`}>
                        <td className="px-4 py-3">
                          {u.id !== currentUser.id && canChangeRole(u) && (
                            <input
                              type="checkbox"
                              checked={selectedUsers.includes(u.id)}
                              onChange={() => handleSelectUser(u.id)}
                              className="rounded border-white/20 bg-white/5 text-indigo-500"
                            />
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-3">
                            <div className="relative">
                              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-sm font-bold text-white">
                                {u.username[0].toUpperCase()}
                              </div>
                              {u.online && (
                                <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-gray-900 bg-green-500" />
                              )}
                            </div>
                            <div>
                              <span className="text-sm font-medium text-white">{u.username}</span>
                              {u.id === currentUser.id && (
                                <span className="ml-2 text-xs text-indigo-400">(you)</span>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className="text-sm text-gray-400">{u.email}</span>
                            {u.emailVerified ? (
                              <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                            ) : (
                              <XCircle className="h-3.5 w-3.5 text-gray-500" />
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {canChangeRole(u) ? (
                            <select
                              value={u.role}
                              onChange={e => updateUserRole(u.id, e.target.value as UserRole)}
                              className={`rounded-lg border border-white/10 bg-transparent px-2 py-1 text-sm outline-none ${roleColor(u.role)}`}
                            >
                              {getRoleOptions(u).map(role => (
                                <option key={role} value={role} className="bg-gray-800">{role.charAt(0).toUpperCase() + role.slice(1)}</option>
                              ))}
                            </select>
                          ) : (
                            <span className={`rounded-lg px-2 py-1 text-sm ${roleColor(u.role)}`}>
                              {u.role.charAt(0).toUpperCase() + u.role.slice(1)}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`flex items-center gap-1.5 text-xs ${u.online ? 'text-green-400' : 'text-gray-500'}`}>
                            <span className={`h-2 w-2 rounded-full ${u.online ? 'bg-green-400' : 'bg-gray-600'}`} />
                            {u.online ? 'Online' : 'Offline'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500">
                          {u.createdAt ? formatDate(u.createdAt) : 'N/A'}
                        </td>
                        <td className="px-4 py-3">
                          {u.id !== currentUser.id && canChangeRole(u) && (
                            <div className="flex items-center gap-1">
                              {u.role === 'banned' ? (
                                <button onClick={() => unbanUser(u.id)} className="rounded-lg p-1.5 text-green-400 transition hover:bg-green-400/10" title="Unban">
                                  <UserCheck className="h-4 w-4" />
                                </button>
                              ) : (
                                <button onClick={() => banUser(u.id)} className="rounded-lg p-1.5 text-amber-400 transition hover:bg-amber-400/10" title="Ban">
                                  <Ban className="h-4 w-4" />
                                </button>
                              )}
                              {isAdmin && (
                                confirmDelete === u.id ? (
                                  <button onClick={() => { deleteUser(u.id); setConfirmDelete(null); }} className="rounded-lg bg-red-500/20 px-2 py-1 text-xs text-red-400 transition hover:bg-red-500/30">
                                    Confirm?
                                  </button>
                                ) : (
                                  <button onClick={() => setConfirmDelete(u.id)} className="rounded-lg p-1.5 text-red-400 transition hover:bg-red-400/10" title="Delete">
                                    <Trash2 className="h-4 w-4" />
                                  </button>
                                )
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
              <span>Showing {filteredUsers.length} of {users.length} users</span>
            </div>
          </div>
        )}

        {tab === 'moderation' && (
          <div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Ban className="h-5 w-5 text-red-400" /> Banned Users ({users.filter(u => u.role === 'banned').length})
                </h4>
                {users.filter(u => u.role === 'banned').length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-8">No banned users</p>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {users.filter(u => u.role === 'banned').map(u => (
                      <div key={u.id} className="flex items-center justify-between rounded-lg bg-red-500/5 border border-red-500/10 p-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-red-500/20 text-sm font-bold text-red-400">
                            {u.username[0].toUpperCase()}
                          </div>
                          <div>
                            <span className="text-sm font-medium text-white">{u.username}</span>
                            <p className="text-xs text-gray-500">{u.email}</p>
                          </div>
                        </div>
                        <button onClick={() => unbanUser(u.id)} className="rounded-lg bg-green-500/10 px-3 py-1.5 text-xs text-green-400 transition hover:bg-green-500/20">
                          Unban
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Shield className="h-5 w-5 text-blue-400" /> Moderators ({users.filter(u => u.role === 'moderator').length})
                </h4>
                {users.filter(u => u.role === 'moderator').length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-8">No moderators assigned</p>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {users.filter(u => u.role === 'moderator').map(u => (
                      <div key={u.id} className="flex items-center justify-between rounded-lg bg-blue-500/5 border border-blue-500/10 p-3">
                        <div className="flex items-center gap-3">
                          <div className="relative">
                            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/20 text-sm font-bold text-blue-400">
                              {u.username[0].toUpperCase()}
                            </div>
                            {u.online && (
                              <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border border-gray-900 bg-green-500" />
                            )}
                          </div>
                          <div>
                            <span className="text-sm font-medium text-white">{u.username}</span>
                            {u.id === currentUser.id && <span className="ml-2 text-xs text-indigo-400">(you)</span>}
                            <span className={`ml-2 text-xs ${u.online ? 'text-green-400' : 'text-gray-500'}`}>
                              {u.online ? 'Online' : 'Offline'}
                            </span>
                          </div>
                        </div>
                        {isAdmin && u.id !== currentUser.id && (
                          <button onClick={() => updateUserRole(u.id, 'user')} className="rounded-lg bg-gray-500/10 px-3 py-1.5 text-xs text-gray-400 transition hover:bg-gray-500/20">
                            Demote
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Users className="h-5 w-5 text-purple-400" /> Group Management
                </h4>
                {chats.filter(c => c.type === 'group').length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-8">No groups found</p>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {chats.filter(c => c.type === 'group').map(group => (
                      <div key={group.id} className="flex items-center justify-between rounded-lg bg-purple-500/5 border border-purple-500/10 p-3">
                        <div className="flex items-center gap-3">
                          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-purple-500/20 text-sm font-bold text-purple-400">
                            {group.name[0].toUpperCase()}
                          </div>
                          <div>
                            <span className="text-sm font-medium text-white">{group.name}</span>
                            <p className="text-xs text-gray-500">
                              {group.participants?.length || 0} members • Created {group.createdAt ? new Date(group.createdAt).toLocaleDateString() : 'Unknown'}
                            </p>
                          </div>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => {
                              // View group details (could open a modal or navigate)
                              addNotification(`Viewing group: ${group.name}`, 'info');
                            }}
                            className="rounded-lg bg-blue-500/10 px-3 py-1.5 text-xs text-blue-400 transition hover:bg-blue-500/20"
                            title="View group details"
                          >
                            <Eye className="h-3 w-3" />
                          </button>
                          {isAdmin && (
                            <button
                              onClick={() => {
                                // Delete group (would need server endpoint)
                                addNotification(`Group deletion not implemented yet: ${group.name}`, 'warning');
                              }}
                              className="rounded-lg bg-red-500/10 px-3 py-1.5 text-xs text-red-400 transition hover:bg-red-500/20"
                              title="Delete group"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-amber-400" /> Quick Actions
                </h4>
                <div className="space-y-2">
                  {isAdmin && (
                    <>
                      <button
                        onClick={() => performSystemAction('Kick All Users', '/api/admin/kick-all')}
                        disabled={performingAction === 'Kick All Users'}
                        className="flex w-full items-center gap-3 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-left transition hover:bg-red-500/20 disabled:opacity-50"
                      >
                        {performingAction === 'Kick All Users' ? (
                          <RefreshCw className="h-5 w-5 animate-spin text-red-400" />
                        ) : (
                          <LogOut className="h-5 w-5 text-red-400" />
                        )}
                        <div>
                          <p className="text-sm font-medium text-white">Kick All Users</p>
                          <p className="text-xs text-gray-500">Disconnect all online users</p>
                        </div>
                      </button>
                      
                      <button
                        onClick={() => performSystemAction('Delete All Messages', '/api/admin/messages', 'DELETE')}
                        disabled={performingAction === 'Delete All Messages'}
                        className="flex w-full items-center gap-3 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-left transition hover:bg-red-500/20 disabled:opacity-50"
                      >
                        {performingAction === 'Delete All Messages' ? (
                          <RefreshCw className="h-5 w-5 animate-spin text-red-400" />
                        ) : (
                          <Trash2 className="h-5 w-5 text-red-400" />
                        )}
                        <div>
                          <p className="text-sm font-medium text-white">Delete All Messages</p>
                          <p className="text-xs text-gray-500">Permanently delete all messages</p>
                        </div>
                      </button>
                      
                      <button
                        onClick={() => {
                          users.filter(u => !u.emailVerified && u.id !== currentUser.id && u.role !== 'admin' && u.role !== 'moderator').forEach(u => banUser(u.id));
                          addNotification('Banned all unverified users', 'success');
                        }}
                        className="flex w-full items-center gap-3 rounded-xl bg-amber-500/10 border border-amber-500/20 p-3 text-left transition hover:bg-amber-500/20"
                      >
                        <UserX className="h-5 w-5 text-amber-400" />
                        <div>
                          <p className="text-sm font-medium text-white">Ban Unverified Users</p>
                          <p className="text-xs text-gray-500">Ban all users without verified email</p>
                        </div>
                      </button>
                    </>
                  )}
                  <button
                    onClick={() => {
                      users.filter(u => u.role === 'banned').forEach(u => unbanUser(u.id));
                      addNotification('Unbanned all users', 'success');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-green-500/10 border border-green-500/20 p-3 text-left transition hover:bg-green-500/20"
                  >
                    <UserCheck className="h-5 w-5 text-green-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Unban All Users</p>
                      <p className="text-xs text-gray-500">Remove ban from all banned users</p>
                    </div>
                  </button>
                  {isModerator && !isAdmin && (
                    <div className="rounded-xl bg-blue-500/5 border border-blue-500/10 p-3 mt-4">
                      <p className="text-xs text-blue-400">
                        <Shield className="h-3 w-3 inline mr-1" />
                        As a moderator, you can ban/unban regular users but cannot modify admin or moderator roles.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'logs' && (
          <div>
            <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
              <div className="flex items-center justify-between mb-4">
                <h4 className="font-semibold text-white flex items-center gap-2">
                  <FileText className="h-5 w-5 text-indigo-400" /> System Logs
                </h4>
                <button
                  onClick={() => setLogsExpanded(!logsExpanded)}
                  className="text-gray-400 hover:text-white"
                >
                  {logsExpanded ? <ChevronUp className="h-5 w-5" /> : <ChevronDown className="h-5 w-5" />}
                </button>
              </div>
              
              {logsExpanded && (
                <div className="space-y-2 max-h-[600px] overflow-y-auto">
                  {logs.length === 0 ? (
                    <p className="text-sm text-gray-500 text-center py-8">No logs available</p>
                  ) : (
                    logs.map(log => (
                      <div key={log.id} className="flex items-start gap-3 rounded-lg bg-white/5 p-3">
                        {logIcon(log.type)}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium text-white">{log.action}</span>
                            {log.user && (
                              <span className="text-xs text-indigo-400">@{log.user}</span>
                            )}
                          </div>
                          {log.details && (
                            <p className="text-xs text-gray-500 mt-0.5">{log.details}</p>
                          )}
                        </div>
                        <span className="text-xs text-gray-600 shrink-0">
                          {formatTime(log.timestamp)}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            <div className="mt-4 text-sm text-gray-500 text-center">
              <p>System logs are stored on the server. This is a preview of recent activity.</p>
            </div>
          </div>
        )}

        {tab === 'announcements' && (
          <div>
            <div className="max-w-2xl">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Bell className="h-5 w-5 text-indigo-400" /> Send Announcement
                </h4>
                <p className="text-sm text-gray-400 mb-4">
                  Send a message to all connected users. This will appear as a notification.
                </p>
                <textarea
                  value={announcement}
                  onChange={e => setAnnouncement(e.target.value)}
                  placeholder="Type your announcement..."
                  rows={4}
                  className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-gray-500 outline-none focus:border-indigo-500 resize-none mb-4"
                />
                <button
                  onClick={handleSendAnnouncement}
                  disabled={!announcement.trim()}
                  className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 px-6 py-3 font-semibold text-white shadow-lg transition disabled:opacity-50 active:scale-[0.98]"
                >
                  <Send className="h-5 w-5" /> Send to All Users
                </button>
              </div>

              <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-6">
                <h4 className="font-semibold text-white mb-4">Announcement Tips</h4>
                <ul className="space-y-2 text-sm text-gray-400">
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                    Keep announcements short and clear
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                    Use for important updates only to avoid notification fatigue
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                    Announcements are shown to currently online users
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {tab === 'sessions' && (
          <div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Active Sessions */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Wifi className="h-5 w-5 text-green-400" /> Active Sessions ({users.filter(u => u.online).length})
                </h4>
                {users.filter(u => u.online).length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-8">No active sessions</p>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {users.filter(u => u.online).map(u => {
                      // Check if current user can kick this user
                      const canKick = u.id !== currentUser.id && (
                        isAdmin || 
                        (isModerator && u.role !== 'admin' && u.role !== 'moderator')
                      );
                      
                      return (
                        <div key={u.id} className="flex items-center justify-between rounded-lg bg-green-500/5 border border-green-500/10 p-3">
                          <div className="flex items-center gap-3">
                            <div className="relative">
                              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-green-500/20 text-sm font-bold text-green-400">
                                {u.username[0].toUpperCase()}
                              </div>
                              <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-gray-900 bg-green-500" />
                            </div>
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-medium text-white">{u.username}</span>
                                {u.role === 'admin' && <Crown className="h-3 w-3 text-amber-400" />}
                                {u.role === 'moderator' && <Shield className="h-3 w-3 text-blue-400" />}
                                {u.id === currentUser.id && <span className="text-xs text-indigo-400">(you)</span>}
                              </div>
                              <p className="text-xs text-gray-500 flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                Connected now
                              </p>
                            </div>
                          </div>
                          {canKick && (
                            <button
                              onClick={async () => {
                                try {
                                  const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/${u.id}/kick`, {
                                    method: 'POST',
                                    headers: { 
                                      'Content-Type': 'application/json',
                                      'Authorization': `Bearer ${authToken}` 
                                    },
                                    body: JSON.stringify({ reason: 'Kicked by admin/moderator' }),
                                  });
                                  if (response.ok) {
                                    addNotification(`Kicked ${u.username}`, 'success');
                                    fetchUsers();
                                  } else {
                                    const data = await response.json();
                                    addNotification(data.error || 'Failed to kick user', 'error');
                                  }
                                } catch {
                                  addNotification('Failed to kick user', 'error');
                                }
                              }}
                              className="flex items-center gap-1 rounded-lg bg-red-500/10 px-3 py-1.5 text-xs text-red-400 transition hover:bg-red-500/20"
                            >
                              <LogOut className="h-3 w-3" /> Kick
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Session Stats */}
              <div className="space-y-4">
                <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                  <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                    <Activity className="h-5 w-5 text-indigo-400" /> Connection Stats
                  </h4>
                  <div className="space-y-3">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-400">Active Connections</span>
                      <span className="text-lg font-bold text-green-400">{users.filter(u => u.online).length}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-400">Idle Users</span>
                      <span className="text-lg font-bold text-amber-400">{users.filter(u => !u.online && u.lastSeen && Date.now() - u.lastSeen < 86400000).length}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-gray-400">Inactive (24h+)</span>
                      <span className="text-lg font-bold text-gray-500">{users.filter(u => !u.online && (!u.lastSeen || Date.now() - u.lastSeen >= 86400000)).length}</span>
                    </div>
                  </div>
                </div>

                {isAdmin && (
                  <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-5">
                    <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                      <AlertTriangle className="h-5 w-5 text-amber-400" /> Disconnect All Users
                    </h4>
                    <p className="text-sm text-gray-400 mb-4">
                      Force disconnect all users from the server. They will need to reconnect.
                    </p>
                    <button
                      onClick={async () => {
                        try {
                          const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/kick-all`, {
                            method: 'POST',
                            headers: { 
                              'Content-Type': 'application/json',
                              'Authorization': `Bearer ${authToken}` 
                            },
                          });
                          if (response.ok) {
                            addNotification('All users disconnected', 'success');
                            fetchUsers();
                          } else {
                            addNotification('Failed to disconnect users', 'error');
                          }
                        } catch {
                          addNotification('Failed to disconnect users', 'error');
                        }
                      }}
                      className="flex items-center gap-2 rounded-xl bg-amber-500/20 px-4 py-2 text-sm text-amber-400 transition hover:bg-amber-500/30"
                    >
                      <LogOut className="h-4 w-4" /> Disconnect All
                    </button>
                  </div>
                )}
                {isModerator && !isAdmin && (
                  <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-5">
                    <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                      <Shield className="h-5 w-5 text-blue-400" /> Moderator Restrictions
                    </h4>
                    <p className="text-sm text-gray-400">
                      As a moderator, you can kick regular users but cannot kick other moderators or administrators.
                      The "Disconnect All" feature is only available to administrators.
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {tab === 'botApprovals' && isAdmin && (
          <div className="max-w-5xl">
            <div className="rounded-2xl border border-white/10 bg-white/5 p-5 mb-6">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h4 className="font-semibold text-white mb-1 flex items-center gap-2">
                    <Bot className="h-5 w-5 text-amber-400" />
                    Bot approvals
                  </h4>
                  <p className="text-sm text-gray-400">
                    New user-created bots require admin approval before other users can access them. Review the code carefully before approving.
                  </p>
                </div>
                <button
                  onClick={fetchPendingBots}
                  disabled={loadingPendingBots}
                  className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white disabled:opacity-50"
                >
                  <RefreshCw className={`h-4 w-4 ${loadingPendingBots ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
              <div className="p-4 border-b border-white/10 flex items-center justify-between">
                <span className="text-sm text-gray-400">
                  Pending bots: <span className="text-white font-semibold">{pendingBots.length}</span>
                </span>
              </div>

              {loadingPendingBots ? (
                <div className="p-10 text-center text-gray-500">
                  <div className="mx-auto mb-3 h-10 w-10 animate-spin rounded-full border-4 border-indigo-500 border-t-transparent" />
                  Loading pending bots...
                </div>
              ) : pendingBots.length === 0 ? (
                <div className="p-12 text-center text-gray-500">
                  <Bot className="h-12 w-12 mx-auto mb-3 text-gray-600" />
                  No bots pending approval
                </div>
              ) : (
                <div className="divide-y divide-white/5">
                  {pendingBots.map(b => (
                    <div key={b.id} className="p-4 flex flex-col md:flex-row md:items-center gap-4 hover:bg-white/5 transition">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-white truncate">{b.displayName || b.username}</span>
                          <span className="text-xs text-gray-500 truncate">@{b.username}</span>
                        </div>
                        <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
                          <span>Created: {b.createdAt ? new Date(b.createdAt).toLocaleString() : 'N/A'}</span>
                          <span>Owner: {b.ownerUsername ? `@${b.ownerUsername}` : (b.ownerId || 'Unknown')}</span>
                          <span>Code: {typeof b.code === 'string' ? `${b.code.length.toLocaleString()} chars` : 'N/A'}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => setSelectedPendingBot(b)}
                          className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-300 transition hover:bg-white/10"
                        >
                          <Eye className="h-4 w-4" />
                          View code
                        </button>
                        <button
                          onClick={async () => {
                            setApprovingBotId(b.id);
                            try {
                              const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/bots/${b.id}/approve`, {
                                method: 'PUT',
                                headers: { 'Authorization': `Bearer ${authToken}` },
                              });
                              if (response.ok) {
                                addNotification('Bot approved', 'success');
                                setPendingBots(prev => prev.filter(x => x.id !== b.id));
                                if (selectedPendingBot?.id === b.id) setSelectedPendingBot(null);
                              } else {
                                const data = await response.json().catch(() => ({}));
                                addNotification(data.error || 'Failed to approve bot', 'error');
                              }
                            } catch {
                              addNotification('Failed to approve bot', 'error');
                            } finally {
                              setApprovingBotId(null);
                            }
                          }}
                          disabled={approvingBotId === b.id}
                          className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-green-600 px-4 py-2 text-sm font-semibold text-white shadow-lg transition disabled:opacity-50 active:scale-[0.98]"
                        >
                          <CheckCircle className="h-4 w-4" />
                          {approvingBotId === b.id ? 'Approving...' : 'Approve'}
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Code viewer modal */}
            {selectedPendingBot && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4" onClick={() => setSelectedPendingBot(null)}>
                <div className="w-full max-w-4xl rounded-2xl border border-white/10 bg-gray-900 p-6 shadow-2xl" onClick={e => e.stopPropagation()}>
                  <div className="flex items-start justify-between gap-4 mb-4">
                    <div className="min-w-0">
                      <h3 className="text-lg font-bold text-white truncate flex items-center gap-2">
                        <Bot className="h-5 w-5 text-amber-400" />
                        {selectedPendingBot.displayName || selectedPendingBot.username}
                        <span className="text-sm font-normal text-gray-500 truncate">@{selectedPendingBot.username}</span>
                      </h3>
                      <p className="text-xs text-gray-500 mt-1">
                        Owner: {selectedPendingBot.ownerUsername ? `@${selectedPendingBot.ownerUsername}` : (selectedPendingBot.ownerId || 'Unknown')} • Created: {selectedPendingBot.createdAt ? new Date(selectedPendingBot.createdAt).toLocaleString() : 'N/A'}
                      </p>
                    </div>
                    <button onClick={() => setSelectedPendingBot(null)} className="text-gray-400 hover:text-white transition">
                      <X className="h-5 w-5" />
                    </button>
                  </div>

                  <div className="rounded-xl border border-white/10 bg-black/40 p-4 max-h-[60vh] overflow-auto">
                    <pre className="text-xs text-gray-200 whitespace-pre-wrap break-words">
                      {selectedPendingBot.code || ''}
                    </pre>
                  </div>

                  <div className="mt-4 flex items-center justify-end gap-2">
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(selectedPendingBot.code || '');
                        addNotification('Code copied to clipboard', 'success');
                      }}
                      className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm text-gray-300 transition hover:bg-white/10"
                    >
                      <Copy className="h-4 w-4" />
                      Copy
                    </button>
                    <button
                      onClick={async () => {
                        setApprovingBotId(selectedPendingBot.id);
                        try {
                          const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/bots/${selectedPendingBot.id}/approve`, {
                            method: 'PUT',
                            headers: { 'Authorization': `Bearer ${authToken}` },
                          });
                          if (response.ok) {
                            addNotification('Bot approved', 'success');
                            setPendingBots(prev => prev.filter(x => x.id !== selectedPendingBot.id));
                            setSelectedPendingBot(null);
                          } else {
                            const data = await response.json().catch(() => ({}));
                            addNotification(data.error || 'Failed to approve bot', 'error');
                          }
                        } catch {
                          addNotification('Failed to approve bot', 'error');
                        } finally {
                          setApprovingBotId(null);
                        }
                      }}
                      disabled={approvingBotId === selectedPendingBot.id}
                      className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-green-600 px-5 py-2 text-sm font-semibold text-white shadow-lg transition disabled:opacity-50 active:scale-[0.98]"
                    >
                      <CheckCircle className="h-4 w-4" />
                      {approvingBotId === selectedPendingBot.id ? 'Approving...' : 'Approve'}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {tab === 'storage' && (
          <div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-gray-400">Messages</span>
                  <MessageSquare className="h-5 w-5 text-blue-400" />
                </div>
                <p className="text-2xl font-bold text-white">{messages.length.toLocaleString()}</p>
                <p className="text-xs text-gray-500 mt-1">Total stored messages</p>
              </div>
              
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-gray-400">Chats</span>
                  <Users className="h-5 w-5 text-purple-400" />
                </div>
                <p className="text-2xl font-bold text-white">{chats.length.toLocaleString()}</p>
                <p className="text-xs text-gray-500 mt-1">{chats.filter(c => c.type === 'group').length} groups, {chats.filter(c => c.type === 'direct').length} direct</p>
              </div>
              
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-gray-400">Max File Size</span>
                  <Upload className="h-5 w-5 text-green-400" />
                </div>
                <p className="text-2xl font-bold text-white">{(serverConfig.maxFileSize / 1024 / 1024).toFixed(0)} MB</p>
                <p className="text-xs text-gray-500 mt-1">Per upload limit</p>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Backup & Restore */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Database className="h-5 w-5 text-indigo-400" /> Backup & Export
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={exportUsers}
                    className="flex w-full items-center gap-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 p-3 text-left transition hover:bg-indigo-500/20"
                  >
                    <Download className="h-5 w-5 text-indigo-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Export Users</p>
                      <p className="text-xs text-gray-500">Download all users as JSON</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => {
                      const allData = {
                        exportedAt: new Date().toISOString(),
                        users: users.map(u => ({ username: u.username, email: u.email, role: u.role })),
                        chats: chats.map(c => ({ id: c.id, type: c.type, name: c.name, participants: c.participants.length })),
                        stats: { totalMessages: messages.length, totalUsers: users.length, totalChats: chats.length }
                      };
                      const blob = new Blob([JSON.stringify(allData, null, 2)], { type: 'application/json' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `4messenger-backup-${new Date().toISOString().split('T')[0]}.json`;
                      a.click();
                      URL.revokeObjectURL(url);
                      addNotification('Full backup exported', 'success');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-green-500/10 border border-green-500/20 p-3 text-left transition hover:bg-green-500/20"
                  >
                    <HardDrive className="h-5 w-5 text-green-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Full Backup</p>
                      <p className="text-xs text-gray-500">Export all data (users, chats, stats)</p>
                    </div>
                  </button>
                </div>
              </div>

              {/* Storage Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Trash2 className="h-5 w-5 text-red-400" /> Data Management
                </h4>
                <div className="space-y-3">
                  <div className="rounded-xl bg-red-500/5 border border-red-500/10 p-4">
                    <p className="text-sm text-gray-400 mb-3">
                      These actions are destructive and cannot be undone. Use with caution.
                    </p>
                    <div className="space-y-2">
                      <button
                        onClick={() => {
                          if (confirm('Delete all messages? This cannot be undone.')) {
                            // In a real app, this would call an API endpoint
                            addNotification('This feature requires server implementation', 'info');
                          }
                        }}
                        className="flex w-full items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400 transition hover:bg-red-500/20"
                      >
                        <Trash2 className="h-4 w-4" /> Clear All Messages
                      </button>
                      <button
                        onClick={() => {
                          if (confirm('Delete all chats? This will also delete all messages.')) {
                            addNotification('This feature requires server implementation', 'info');
                          }
                        }}
                        className="flex w-full items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400 transition hover:bg-red-500/20"
                      >
                        <Trash2 className="h-4 w-4" /> Clear All Chats
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Server Info */}
              <div className="lg:col-span-2 rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Server className="h-5 w-5 text-indigo-400" /> Server Information
                </h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="rounded-xl bg-white/5 p-3">
                    <p className="text-xs text-gray-500 mb-1">Server URL</p>
                    <p className="text-sm text-white truncate flex items-center gap-1">
                      {serverUrl}
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(serverUrl);
                          addNotification('URL copied to clipboard', 'success');
                        }}
                        className="text-gray-500 hover:text-white"
                      >
                        <Copy className="h-3 w-3" />
                      </button>
                    </p>
                  </div>
                  <div className="rounded-xl bg-white/5 p-3">
                    <p className="text-xs text-gray-500 mb-1">Database</p>
                    <p className="text-sm text-white">SQLite (sql.js)</p>
                  </div>
                  <div className="rounded-xl bg-white/5 p-3">
                    <p className="text-xs text-gray-500 mb-1">Encryption</p>
                    <p className={`text-sm ${serverConfig.encryptionEnabled ? 'text-green-400' : 'text-gray-400'}`}>
                      {serverConfig.encryptionEnabled ? 'AES-256-GCM' : 'Disabled'}
                    </p>
                  </div>
                  <div className="rounded-xl bg-white/5 p-3">
                    <p className="text-xs text-gray-500 mb-1">Server Status</p>
                    <p className="text-sm text-green-400 flex items-center gap-1">
                      <span className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                      Online
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'browsers' && (
          <div>
            <div className="rounded-2xl border border-white/10 bg-white/5 p-5 mb-6">
              <h4 className="font-semibold text-white mb-2 flex items-center gap-2">
                <Globe className="h-5 w-5 text-indigo-400" /> Browser Data Collection
              </h4>
              <p className="text-sm text-gray-400">
                Browser fingerprints and visit data collected from all visitors, identified by IP address.
                This data is collected before authentication for security monitoring purposes.
              </p>
            </div>

            {Object.keys(browserData).length === 0 ? (
              <div className="rounded-2xl border border-white/10 bg-white/5 p-12 text-center">
                <Globe className="h-12 w-12 text-gray-600 mx-auto mb-4" />
                <p className="text-gray-400">No browser data collected yet</p>
                <p className="text-sm text-gray-500 mt-1">Data will appear here when users connect to the server</p>
              </div>
            ) : (
              <div className="space-y-4">
                {Object.entries(browserData).map(([ip, data]) => (
                  <div key={ip} className="rounded-2xl border border-white/10 bg-white/5 p-5">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/20">
                          <Globe className="h-5 w-5 text-indigo-400" />
                        </div>
                        <div>
                          <h5 className="font-semibold text-white">{ip}</h5>
                          <p className="text-xs text-gray-500">
                            First seen: {new Date(data.firstSeen).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      {data.username && (
                        <div className="text-right">
                          <span className="text-sm text-indigo-400">@{data.username}</span>
                          <p className="text-xs text-gray-500">Logged in user</p>
                        </div>
                      )}
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                      <div className="rounded-lg bg-white/5 p-2">
                        <p className="text-xs text-gray-500">Last Seen</p>
                        <p className="text-sm text-white truncate">{new Date(data.lastSeen).toLocaleString()}</p>
                      </div>
                      <div className="rounded-lg bg-white/5 p-2">
                        <p className="text-xs text-gray-500">Total Visits</p>
                        <p className="text-sm text-white">{data.visits?.length || 0}</p>
                      </div>
                      {data.visits?.[0]?.timezone && (
                        <div className="rounded-lg bg-white/5 p-2">
                          <p className="text-xs text-gray-500">Timezone</p>
                          <p className="text-sm text-white truncate">{data.visits[0].timezone}</p>
                        </div>
                      )}
                      {data.visits?.[0]?.language && (
                        <div className="rounded-lg bg-white/5 p-2">
                          <p className="text-xs text-gray-500">Language</p>
                          <p className="text-sm text-white truncate">{data.visits[0].language}</p>
                        </div>
                      )}
                    </div>

                    {data.visits && data.visits.length > 0 && (
                      <details className="group">
                        <summary className="cursor-pointer text-sm text-indigo-400 hover:text-indigo-300">
                          View visit details ({data.visits.length} visits)
                        </summary>
                        <div className="mt-3 space-y-2 max-h-60 overflow-y-auto">
                          {data.visits.slice(-10).reverse().map((visit, idx) => (
                            <div key={idx} className="rounded-lg bg-white/5 p-3 text-xs">
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-gray-400">{visit.timestamp || 'Unknown time'}</span>
                                {visit.action && <span className="text-indigo-400">{visit.action}</span>}
                              </div>
                              <div className="grid grid-cols-2 gap-2 text-gray-500">
                                {visit.screenWidth && (
                                  <div>Screen: {visit.screenWidth}x{visit.screenHeight}</div>
                                )}
                                {visit.platform && (
                                  <div>Platform: {visit.platform}</div>
                                )}
                                {visit.hardwareConcurrency && (
                                  <div>CPU Cores: {visit.hardwareConcurrency}</div>
                                )}
                                {visit.deviceMemory && (
                                  <div>Memory: {visit.deviceMemory} GB</div>
                                )}
                              </div>
                              {visit.userAgent && (
                                <div className="mt-2 text-gray-600 truncate" title={visit.userAgent}>
                                  UA: {visit.userAgent}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div className="mt-6 rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-medium text-amber-400">Privacy Notice</p>
                  <p className="text-xs text-gray-400 mt-1">
                    This data is collected for security monitoring. Ensure your privacy policy covers browser fingerprinting.
                    Data is stored in browsersdata.json on the server.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'system' && isAdmin && (
          <div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              {/* System Health */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-semibold text-white flex items-center gap-2">
                    <Zap className="h-5 w-5 text-green-400" /> System Health
                  </h4>
                  <button
                    onClick={fetchSystemHealth}
                    disabled={loadingSystem}
                    className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white disabled:opacity-50"
                  >
                    <RefreshCw className={`h-4 w-4 ${loadingSystem ? 'animate-spin' : ''}`} />
                    Refresh
                  </button>
                </div>
                
                {loadingSystem ? (
                  <div className="text-center py-8">
                    <RefreshCw className="h-8 w-8 animate-spin text-indigo-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-500">Loading system health...</p>
                  </div>
                ) : systemHealth ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="rounded-xl bg-white/5 p-3">
                        <p className="text-xs text-gray-500 mb-1">Uptime</p>
                        <p className="text-sm text-white font-medium">
                          {Math.floor(systemHealth.uptime / 3600)}h {Math.floor((systemHealth.uptime % 3600) / 60)}m
                        </p>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3">
                        <p className="text-xs text-gray-500 mb-1">Platform</p>
                        <p className="text-sm text-white font-medium">{systemHealth.system.platform}</p>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3">
                        <p className="text-xs text-gray-500 mb-1">Memory Used</p>
                        <p className="text-sm text-white font-medium">
                          {(systemHealth.memory.used / 1024 / 1024).toFixed(1)} MB
                        </p>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3">
                        <p className="text-xs text-gray-500 mb-1">Database Size</p>
                        <p className="text-sm text-white font-medium">
                          {(systemHealth.database.size / 1024 / 1024).toFixed(1)} MB
                        </p>
                      </div>
                    </div>
                    
                    <div className="rounded-xl bg-white/5 p-4">
                      <h5 className="text-sm font-medium text-white mb-2">System Resources</h5>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between">
                          <span className="text-gray-500">CPU Cores:</span>
                          <span className="text-white">{systemHealth.system.cpus}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Total Memory:</span>
                          <span className="text-white">{(systemHealth.system.totalMemory / 1024 / 1024 / 1024).toFixed(1)} GB</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Free Memory:</span>
                          <span className="text-white">{(systemHealth.system.freeMemory / 1024 / 1024 / 1024).toFixed(1)} GB</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Load Average:</span>
                          <span className="text-white">{systemHealth.system.loadAverage.map((l: number) => l.toFixed(2)).join(', ')}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <AlertTriangle className="h-8 w-8 mx-auto mb-2 text-amber-400" />
                    <p>Unable to load system health data</p>
                  </div>
                )}
              </div>

              {/* Message Statistics */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-semibold text-white flex items-center gap-2">
                    <MessageSquare className="h-5 w-5 text-blue-400" /> Message Statistics
                  </h4>
                  <button
                    onClick={fetchMessageStats}
                    className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white"
                  >
                    <RefreshCw className="h-4 w-4" />
                    Refresh
                  </button>
                </div>
                
                {messageStats ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="rounded-xl bg-white/5 p-3">
                        <p className="text-xs text-gray-500 mb-1">Total Messages</p>
                        <p className="text-lg text-white font-bold">{messageStats.totalMessages.toLocaleString()}</p>
                      </div>
                      <div className="rounded-xl bg-white/5 p-3">
                        <p className="text-xs text-gray-500 mb-1">Active Users</p>
                        <p className="text-lg text-white font-bold">{messageStats.topUsers?.length || 0}</p>
                      </div>
                    </div>
                    
                    {messageStats.messagesByType && messageStats.messagesByType.length > 0 && (
                      <div className="rounded-xl bg-white/5 p-4">
                        <h5 className="text-sm font-medium text-white mb-2">Messages by Type</h5>
                        <div className="space-y-2">
                          {messageStats.messagesByType.map((type: any) => (
                            <div key={type.type} className="flex justify-between text-sm">
                              <span className="text-gray-400 capitalize">{type.type || 'text'}</span>
                              <span className="text-white font-medium">{type.count.toLocaleString()}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {messageStats.topUsers && messageStats.topUsers.length > 0 && (
                      <div className="rounded-xl bg-white/5 p-4">
                        <h5 className="text-sm font-medium text-white mb-2">Top Contributors</h5>
                        <div className="space-y-2">
                          {messageStats.topUsers.slice(0, 5).map((user: any, index: number) => (
                            <div key={user.username} className="flex justify-between items-center text-sm">
                              <div className="flex items-center gap-2">
                                <span className="text-gray-500 w-4">#{index + 1}</span>
                                <span className="text-white">{user.username}</span>
                              </div>
                              <span className="text-indigo-400 font-medium">{user.messageCount}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <MessageSquare className="h-8 w-8 mx-auto mb-2 text-blue-400" />
                    <p>Loading message statistics...</p>
                  </div>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              {/* Database Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Database className="h-5 w-5 text-indigo-400" /> Database Management
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => performSystemAction('Database Backup', '/api/admin/database/backup')}
                    disabled={performingAction === 'Database Backup'}
                    className="flex w-full items-center gap-3 rounded-xl bg-green-500/10 border border-green-500/20 p-3 text-left transition hover:bg-green-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Database Backup' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-green-400" />
                    ) : (
                      <Database className="h-5 w-5 text-green-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Create Database Backup</p>
                      <p className="text-xs text-gray-500">Download a full database backup file</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => {
                      window.open(`${serverUrl.replace(/\/$/, '')}/api/admin/database/export`, '_blank');
                      addNotification('Database export started', 'success');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-blue-500/10 border border-blue-500/20 p-3 text-left transition hover:bg-blue-500/20"
                  >
                    <Download className="h-5 w-5 text-blue-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Export Data (JSON)</p>
                      <p className="text-xs text-gray-500">Export users, chats, and recent messages</p>
                    </div>
                  </button>
                </div>
              </div>

              {/* File Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-semibold text-white flex items-center gap-2">
                    <HardDrive className="h-5 w-5 text-purple-400" /> File Management
                  </h4>
                  <button
                    onClick={fetchUploadedFiles}
                    className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-1.5 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white"
                  >
                    <RefreshCw className="h-4 w-4" />
                    Refresh
                  </button>
                </div>
                
                <div className="space-y-3">
                  {uploadedFiles.length > 0 ? (
                    <div className="max-h-48 overflow-y-auto space-y-2">
                      {uploadedFiles.slice(0, 10).map((file: any) => (
                        <div key={file.name} className="flex items-center justify-between rounded-lg bg-white/5 p-2">
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-white truncate">{file.name}</p>
                            <p className="text-xs text-gray-500">
                              {(file.size / 1024).toFixed(1)} KB • {new Date(file.modified).toLocaleDateString()}
                            </p>
                          </div>
                          <button
                            onClick={() => performSystemAction(`Delete ${file.name}`, `/api/admin/files/${encodeURIComponent(file.name)}`, 'DELETE')}
                            disabled={performingAction === `Delete ${file.name}`}
                            className="text-red-400 hover:text-red-300 p-1"
                            title="Delete file"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </div>
                      ))}
                      {uploadedFiles.length > 10 && (
                        <p className="text-xs text-gray-500 text-center py-2">
                          And {uploadedFiles.length - 10} more files...
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-gray-500">
                      <HardDrive className="h-8 w-8 mx-auto mb-2 text-purple-400" />
                      <p>No uploaded files</p>
                    </div>
                  )}
                  
                  <div className="pt-2 border-t border-white/10">
                    <p className="text-xs text-gray-500 mb-2">
                      Total storage used: {(uploadedFiles.reduce((sum: number, f: any) => sum + f.size, 0) / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Server Actions */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Server className="h-5 w-5 text-amber-400" /> Server Actions
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => performSystemAction('Server Restart', '/api/admin/server/restart')}
                    disabled={performingAction === 'Server Restart'}
                    className="flex w-full items-center gap-3 rounded-xl bg-amber-500/10 border border-amber-500/20 p-3 text-left transition hover:bg-amber-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Server Restart' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-amber-400" />
                    ) : (
                      <Server className="h-5 w-5 text-amber-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Restart Server</p>
                      <p className="text-xs text-gray-500">Disconnect all users and restart</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => performSystemAction('Clear Cache', '/api/admin/cache/clear')}
                    disabled={performingAction === 'Clear Cache'}
                    className="flex w-full items-center gap-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 p-3 text-left transition hover:bg-indigo-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Clear Cache' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-indigo-400" />
                    ) : (
                      <Zap className="h-5 w-5 text-indigo-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Clear Cache</p>
                      <p className="text-xs text-gray-500">Clear any cached data</p>
                    </div>
                  </button>
                </div>
              </div>

              {/* Security Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-green-400" /> Security Management
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => setShowPasswordField(!showPasswordField)}
                    className="flex w-full items-center gap-3 rounded-xl bg-green-500/10 border border-green-500/20 p-3 text-left transition hover:bg-green-500/20"
                  >
                    <Key className="h-5 w-5 text-green-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Change Admin Password</p>
                      <p className="text-xs text-gray-500">Update your admin password</p>
                    </div>
                  </button>
                  
                  {showPasswordField && (
                    <div className="space-y-2 p-3 bg-white/5 rounded-lg">
                      <input
                        type="password"
                        placeholder="New password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 text-sm text-white placeholder-gray-400 focus:border-indigo-500 focus:outline-none"
                      />
                      <input
                        type="password"
                        placeholder="Confirm password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full rounded-lg bg-white/10 border border-white/20 px-3 py-2 text-sm text-white placeholder-gray-400 focus:border-indigo-500 focus:outline-none"
                      />
                      <div className="flex gap-2">
                        <button
                          onClick={async () => {
                            if (!newPassword.trim()) {
                              addNotification('Password cannot be empty', 'error');
                              return;
                            }
                            if (newPassword !== confirmPassword) {
                              addNotification('Passwords do not match', 'error');
                              return;
                            }
                            if (newPassword.length < 8) {
                              addNotification('Password must be at least 8 characters', 'error');
                              return;
                            }
                            try {
                              const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/password`, {
                                method: 'POST',
                                headers: { 
                                  'Content-Type': 'application/json',
                                  'Authorization': `Bearer ${authToken}` 
                                },
                                body: JSON.stringify({ newPassword }),
                              });
                              if (response.ok) {
                                addNotification('Password changed successfully', 'success');
                                setNewPassword('');
                                setConfirmPassword('');
                                setShowPasswordField(false);
                              } else {
                                const data = await response.json();
                                addNotification(data.error || 'Failed to change password', 'error');
                              }
                            } catch {
                              addNotification('Failed to change password', 'error');
                            }
                          }}
                          className="flex-1 rounded-lg bg-indigo-500/20 px-3 py-1.5 text-xs text-indigo-400 transition hover:bg-indigo-500/30"
                        >
                          Change
                        </button>
                        <button
                          onClick={() => {
                            setShowPasswordField(false);
                            setNewPassword('');
                            setConfirmPassword('');
                          }}
                          className="rounded-lg bg-gray-500/20 px-3 py-1.5 text-xs text-gray-400 transition hover:bg-gray-500/30"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                  
                  <button
                    onClick={async () => {
                      if (confirm('This will invalidate all current user sessions. Are you sure?')) {
                        try {
                          const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/jwt/regenerate`, {
                            method: 'POST',
                            headers: { 
                              'Content-Type': 'application/json',
                              'Authorization': `Bearer ${authToken}` 
                            },
                          });
                          if (response.ok) {
                            addNotification('JWT secret regenerated. All users will need to log in again.', 'success');
                          } else {
                            const data = await response.json();
                            addNotification(data.error || 'Failed to regenerate JWT secret', 'error');
                          }
                        } catch {
                          addNotification('Failed to regenerate JWT secret', 'error');
                        }
                      }
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-blue-500/10 border border-blue-500/20 p-3 text-left transition hover:bg-blue-500/20"
                  >
                    <Lock className="h-5 w-5 text-blue-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Regenerate JWT Secret</p>
                      <p className="text-xs text-gray-500">Invalidate all current sessions</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => {
                      // View security logs
                      addNotification('Security logs not implemented yet', 'warning');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-purple-500/10 border border-purple-500/20 p-3 text-left transition hover:bg-purple-500/20"
                  >
                    <Eye className="h-5 w-5 text-purple-400" />
                    <div>
                      <p className="text-sm font-medium text-white">View Security Logs</p>
                      <p className="text-xs text-gray-500">Check login attempts and security events</p>
                    </div>
                  </button>
                </div>
              </div>

              {/* Log Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <FileText className="h-5 w-5 text-red-400" /> Log Management
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => performSystemAction('Clear Logs', '/api/admin/logs/clear')}
                    disabled={performingAction === 'Clear Logs'}
                    className="flex w-full items-center gap-3 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-left transition hover:bg-red-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Clear Logs' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-red-400" />
                    ) : (
                      <Trash2 className="h-5 w-5 text-red-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Clear System Logs</p>
                      <p className="text-xs text-gray-500">Delete all log entries</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => {
                      const logData = logs.map(log => 
                        `[${new Date(log.timestamp).toISOString()}] ${log.type.toUpperCase()}: ${log.action} ${log.user ? `(@${log.user})` : ''} ${log.details || ''}`
                      ).join('\n');
                      const blob = new Blob([logData], { type: 'text/plain' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `4messenger-logs-${new Date().toISOString().split('T')[0]}.txt`;
                      a.click();
                      URL.revokeObjectURL(url);
                      addNotification('Logs exported', 'success');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-gray-500/10 border border-gray-500/20 p-3 text-left transition hover:bg-gray-500/20"
                  >
                    <Download className="h-5 w-5 text-gray-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Export Logs</p>
                      <p className="text-xs text-gray-500">Download current logs</p>
                    </div>
                  </button>
                </div>
              </div>

              {/* Message Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <MessageSquare className="h-5 w-5 text-orange-400" /> Message Management
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => {
                      const days = prompt('Delete messages older than how many days? (leave empty to cancel)');
                      if (days && parseInt(days) > 0) {
                        const beforeDate = new Date(Date.now() - parseInt(days) * 24 * 60 * 60 * 1000).toISOString();
                        performSystemAction('Delete Old Messages', '/api/admin/messages', 'DELETE', { beforeDate });
                      }
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-orange-500/10 border border-orange-500/20 p-3 text-left transition hover:bg-orange-500/20"
                  >
                    <Clock className="h-5 w-5 text-orange-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Delete Old Messages</p>
                      <p className="text-xs text-gray-500">Remove messages older than X days</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => {
                      const userId = prompt('Enter user ID to delete all their messages (leave empty to cancel):');
                      if (userId?.trim()) {
                        performSystemAction('Delete User Messages', '/api/admin/messages', 'DELETE', { userId: userId.trim() });
                      }
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-red-500/10 border border-red-500/20 p-3 text-left transition hover:bg-red-500/20"
                  >
                    <UserX className="h-5 w-5 text-red-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Delete User Messages</p>
                      <p className="text-xs text-gray-500">Remove all messages from a user</p>
                    </div>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'messages' && isAdmin && (
          <div>
            <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3 mb-4">
              <div className="relative flex-1 min-w-0 sm:min-w-[200px]">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <input
                  type="text"
                  value={messageSearch}
                  onChange={e => setMessageSearch(e.target.value)}
                  placeholder="Search messages..."
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-2 pl-10 pr-4 text-sm text-white placeholder-gray-500 outline-none focus:border-indigo-500"
                />
              </div>
              
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={fetchAllMessages}
                  disabled={loadingMessages}
                  className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white disabled:opacity-50"
                >
                  <RefreshCw className={`h-4 w-4 ${loadingMessages ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
              </div>
            </div>

            {/* Bulk Actions for Messages */}
            {selectedMessages.length > 0 && (
              <div className="mb-4 flex items-center gap-3 rounded-xl border border-red-500/20 bg-red-500/10 p-3">
                <span className="text-sm text-red-400">{selectedMessages.length} selected</span>
                <div className="flex-1" />
                <button
                  onClick={() => {
                    if (confirm('Are you sure you want to delete the selected messages?')) {
                      performSystemAction('Delete Selected Messages', '/api/admin/messages', 'DELETE', { messageIds: selectedMessages });
                      setSelectedMessages([]);
                    }
                  }}
                  disabled={performingAction === 'Delete Selected Messages'}
                  className="flex items-center gap-2 rounded-lg bg-red-500/20 px-3 py-1.5 text-sm text-red-400 transition hover:bg-red-500/30 disabled:opacity-50"
                >
                  {performingAction === 'Delete Selected Messages' ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                  Delete Selected
                </button>
              </div>
            )}

            <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
              {loadingMessages ? (
                <div className="text-center py-12">
                  <RefreshCw className="h-8 w-8 animate-spin text-indigo-400 mx-auto mb-2" />
                  <p className="text-sm text-gray-500">Loading messages...</p>
                </div>
              ) : allMessages.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <MessageSquare className="h-8 w-8 mx-auto mb-2 text-blue-400" />
                  <p>No messages found</p>
                </div>
              ) : (
                <div className="max-h-96 overflow-y-auto">
                  {allMessages
                    .filter(msg => 
                      messageSearch === '' || 
                      msg.content?.toLowerCase().includes(messageSearch.toLowerCase()) ||
                      msg.username?.toLowerCase().includes(messageSearch.toLowerCase()) ||
                      msg.chatName?.toLowerCase().includes(messageSearch.toLowerCase())
                    )
                    .map((msg: any) => (
                      <div key={msg.id} className="flex items-start gap-3 p-4 border-b border-white/5 hover:bg-white/5 transition">
                        <input
                          type="checkbox"
                          checked={selectedMessages.includes(msg.id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedMessages(prev => [...prev, msg.id]);
                            } else {
                              setSelectedMessages(prev => prev.filter(id => id !== msg.id));
                            }
                          }}
                          className="mt-1"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm font-medium text-white">{msg.username || 'Unknown'}</span>
                            <span className="text-xs text-gray-500">in {msg.chatName || 'Unknown Chat'}</span>
                            <span className="text-xs text-gray-500">{new Date(msg.timestamp).toLocaleString()}</span>
                          </div>
                          <p className="text-sm text-gray-300 break-words">{msg.content || '[Media/File]'}</p>
                        </div>
                        <button
                          onClick={() => {
                            if (confirm('Are you sure you want to delete this message?')) {
                              performSystemAction(`Delete Message ${msg.id}`, `/api/admin/messages`, 'DELETE', { messageIds: [msg.id] });
                            }
                          }}
                          disabled={performingAction === `Delete Message ${msg.id}`}
                          className="text-red-400 hover:text-red-300 p-1"
                          title="Delete message"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'server' && isAdmin && (
          <div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Server Control */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Server className="h-5 w-5 text-amber-400" /> Server Control
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => performSystemAction('Server Restart', '/api/admin/server/restart')}
                    disabled={performingAction === 'Server Restart'}
                    className="flex w-full items-center gap-3 rounded-xl bg-amber-500/10 border border-amber-500/20 p-3 text-left transition hover:bg-amber-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Server Restart' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-amber-400" />
                    ) : (
                      <Server className="h-5 w-5 text-amber-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Restart Server</p>
                      <p className="text-xs text-gray-500">Disconnect all users and restart the server</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => performSystemAction('Clear Cache', '/api/admin/cache/clear')}
                    disabled={performingAction === 'Clear Cache'}
                    className="flex w-full items-center gap-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 p-3 text-left transition hover:bg-indigo-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Clear Cache' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-indigo-400" />
                    ) : (
                      <Zap className="h-5 w-5 text-indigo-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Clear Cache</p>
                      <p className="text-xs text-gray-500">Clear any cached data and restart cache</p>
                    </div>
                  </button>
                </div>
              </div>

              {/* Database Management */}
              <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Database className="h-5 w-5 text-indigo-400" /> Database Management
                </h4>
                <div className="space-y-3">
                  <button
                    onClick={() => performSystemAction('Database Backup', '/api/admin/database/backup')}
                    disabled={performingAction === 'Database Backup'}
                    className="flex w-full items-center gap-3 rounded-xl bg-green-500/10 border border-green-500/20 p-3 text-left transition hover:bg-green-500/20 disabled:opacity-50"
                  >
                    {performingAction === 'Database Backup' ? (
                      <RefreshCw className="h-5 w-5 animate-spin text-green-400" />
                    ) : (
                      <Database className="h-5 w-5 text-green-400" />
                    )}
                    <div>
                      <p className="text-sm font-medium text-white">Create Database Backup</p>
                      <p className="text-xs text-gray-500">Download a full database backup file</p>
                    </div>
                  </button>
                  
                  <button
                    onClick={() => {
                      window.open(`${serverUrl.replace(/\/$/, '')}/api/admin/database/export`, '_blank');
                      addNotification('Database export started', 'success');
                    }}
                    className="flex w-full items-center gap-3 rounded-xl bg-blue-500/10 border border-blue-500/20 p-3 text-left transition hover:bg-blue-500/20"
                  >
                    <Download className="h-5 w-5 text-blue-400" />
                    <div>
                      <p className="text-sm font-medium text-white">Export Data (JSON)</p>
                      <p className="text-xs text-gray-500">Export users, chats, and recent messages</p>
                    </div>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {tab === 'files' && isAdmin && (
          <div>
            <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3 mb-4">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={fetchUploadedFiles}
                  className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white"
                >
                  <RefreshCw className="h-4 w-4" />
                  Refresh Files
                </button>
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/5 p-5">
              <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                <Upload className="h-5 w-5 text-purple-400" /> Uploaded Files
              </h4>
              
              {uploadedFiles.length > 0 ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {uploadedFiles.map((file: any) => (
                      <div key={file.name} className="rounded-xl border border-white/10 bg-white/5 p-4">
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-white truncate" title={file.name}>{file.name}</p>
                            <p className="text-xs text-gray-500">
                              {(file.size / 1024).toFixed(1)} KB • {new Date(file.modified).toLocaleDateString()}
                            </p>
                          </div>
                          <button
                            onClick={() => performSystemAction(`Delete ${file.name}`, `/api/admin/files/${encodeURIComponent(file.name)}`, 'DELETE')}
                            disabled={performingAction === `Delete ${file.name}`}
                            className="text-red-400 hover:text-red-300 p-1 ml-2"
                            title="Delete file"
                          >
                            {performingAction === `Delete ${file.name}` ? (
                              <RefreshCw className="h-4 w-4 animate-spin" />
                            ) : (
                              <Trash2 className="h-4 w-4" />
                            )}
                          </button>
                        </div>
                        <div className="flex gap-2">
                          <button
                            onClick={() => window.open(`${serverUrl.replace(/\/$/, '')}/uploads/${encodeURIComponent(file.name)}`, '_blank')}
                            className="flex-1 text-xs bg-blue-500/20 text-blue-400 px-2 py-1 rounded hover:bg-blue-500/30 transition"
                          >
                            View
                          </button>
                          <button
                            onClick={() => {
                              const link = document.createElement('a');
                              link.href = `${serverUrl.replace(/\/$/, '')}/uploads/${encodeURIComponent(file.name)}`;
                              link.download = file.name;
                              link.click();
                            }}
                            className="flex-1 text-xs bg-green-500/20 text-green-400 px-2 py-1 rounded hover:bg-green-500/30 transition"
                          >
                            Download
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  <div className="pt-4 border-t border-white/10">
                    <p className="text-sm text-gray-400">
                      Total storage used: {(uploadedFiles.reduce((sum: number, f: any) => sum + f.size, 0) / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <Upload className="h-8 w-8 mx-auto mb-2 text-purple-400" />
                  <p>No uploaded files found</p>
                </div>
              )}
            </div>
          </div>
        )}

        {tab === 'config' && (
          <div>
            <div className="max-w-2xl space-y-6">
              {/* Maintenance Mode */}
              <div className={`rounded-2xl border p-6 ${maintenanceMode ? 'border-amber-500/30 bg-amber-500/10' : 'border-white/10 bg-white/5'}`}>
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <AlertTriangle className={`h-5 w-5 ${maintenanceMode ? 'text-amber-400' : 'text-gray-400'}`} /> 
                  Maintenance Mode
                  {maintenanceMode && (
                    <span className="ml-2 px-2 py-0.5 rounded-full text-xs bg-amber-500/20 text-amber-400 animate-pulse">
                      ACTIVE
                    </span>
                  )}
                </h4>
                <p className="text-sm text-gray-400 mb-4">
                  When enabled, only administrators can access the server. All other users will be disconnected.
                </p>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Maintenance Message</label>
                    <input
                      type="text"
                      value={maintenanceMessage}
                      onChange={e => setMaintenanceMessage(e.target.value)}
                      className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white outline-none focus:border-indigo-500"
                      placeholder="Message shown to users during maintenance"
                    />
                  </div>
                  <button
                    onClick={handleToggleMaintenance}
                    disabled={loadingMaintenance}
                    className={`flex items-center gap-2 rounded-xl px-6 py-3 font-semibold shadow-lg transition disabled:opacity-50 ${
                      maintenanceMode 
                        ? 'bg-gradient-to-r from-green-500 to-emerald-600 text-white'
                        : 'bg-gradient-to-r from-amber-500 to-orange-600 text-white'
                    }`}
                  >
                    {loadingMaintenance ? (
                      <RefreshCw className="h-5 w-5 animate-spin" />
                    ) : maintenanceMode ? (
                      <>
                        <CheckCircle className="h-5 w-5" /> Disable Maintenance Mode
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-5 w-5" /> Enable Maintenance Mode
                      </>
                    )}
                  </button>
                </div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Server className="h-5 w-5 text-indigo-400" /> General Settings
                </h4>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Server Name</label>
                    <input
                      type="text"
                      value={editConfig.serverName}
                      onChange={e => setEditConfig(prev => ({ ...prev, serverName: e.target.value }))}
                      className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white outline-none focus:border-indigo-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Max File Size (bytes)</label>
                    <input
                      type="number"
                      value={editConfig.maxFileSize}
                      onChange={e => setEditConfig(prev => ({ ...prev, maxFileSize: parseInt(e.target.value) || 0 }))}
                      className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white outline-none focus:border-indigo-500"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Current: {(editConfig.maxFileSize / 1024 / 1024).toFixed(1)} MB
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Max Bot Memory (MB)</label>
                    <input
                      type="number"
                      value={editConfig.maxBotMemoryMB || 50}
                      onChange={e => setEditConfig(prev => ({ ...prev, maxBotMemoryMB: parseInt(e.target.value) || 50 }))}
                      className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white outline-none focus:border-indigo-500"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Limits the amount of RAM a custom python bot can use before being killed
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-white/10 bg-white/5 p-6">
                <h4 className="font-semibold text-white mb-4 flex items-center gap-2">
                  <Lock className="h-5 w-5 text-amber-400" /> Security Settings
                </h4>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1 flex items-center justify-between">
                      <span>Server Password</span>
                      <button
                        onClick={() => setShowPasswordField(!showPasswordField)}
                        className="text-xs text-indigo-400 hover:text-indigo-300"
                      >
                        {showPasswordField ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </label>
                    <input
                      type={showPasswordField ? 'text' : 'password'}
                      value={editConfig.serverPassword}
                      onChange={e => setEditConfig(prev => ({ ...prev, serverPassword: e.target.value }))}
                      className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white outline-none focus:border-indigo-500"
                      placeholder="Leave empty to disable"
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Users will need this password to access the server
                    </p>
                  </div>

                  {[
                    { key: 'captchaEnabled' as const, label: 'CAPTCHA Verification', icon: ShieldCheck, desc: 'Require CAPTCHA before login/register' },
                    { key: 'encryptionEnabled' as const, label: 'Message Encryption', icon: Lock, desc: 'Encrypt all messages in the database' },
                    { key: 'emailVerification' as const, label: 'Email Verification', icon: Mail, desc: 'Require email verification for new accounts' },
                    { key: 'allowRegistration' as const, label: 'Allow Registration', icon: Users, desc: 'Allow new users to create accounts' },
                  ].map(toggle => (
                    <div key={toggle.key} className="flex items-center justify-between rounded-xl bg-white/5 p-4">
                      <div className="flex items-center gap-3">
                        <toggle.icon className="h-5 w-5 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium text-white">{toggle.label}</p>
                          <p className="text-xs text-gray-500">{toggle.desc}</p>
                        </div>
                      </div>
                      <button
                        onClick={() => setEditConfig(prev => ({ ...prev, [toggle.key]: !prev[toggle.key] }))}
                        className="transition hover:scale-110"
                      >
                        {editConfig[toggle.key] ? (
                          <ToggleRight className="h-8 w-8 text-indigo-400" />
                        ) : (
                          <ToggleLeft className="h-8 w-8 text-gray-600" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-4">
                <button
                  onClick={handleSaveConfig}
                  className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 px-6 py-3 font-semibold text-white shadow-lg transition active:scale-[0.98]"
                >
                  <Save className="h-5 w-5" /> Save Configuration
                </button>
                <button
                  onClick={() => setEditConfig({ ...serverConfig })}
                  className="rounded-xl border border-white/10 bg-white/5 px-6 py-3 text-sm text-gray-400 transition hover:bg-white/10 hover:text-white"
                >
                  Reset Changes
                </button>
              </div>

              <div className="rounded-2xl border border-amber-500/20 bg-amber-500/5 p-4">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-sm font-medium text-amber-400">Configuration changes</p>
                    <p className="text-xs text-gray-400 mt-1">
                      Some changes may require users to re-authenticate. Changes are saved to the server's config.json file.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
