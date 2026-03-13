import { useState, useRef, useEffect, useCallback } from 'react';
import { useStore } from '../store';
import {
  Search, Plus, Settings, LogOut, Users, MessageSquare, Hash,
  Send, Paperclip, Smile, Phone, Video, MoreVertical, Image,
  Edit2, Trash2, ChevronLeft, Shield, Crown, UserPlus, X,
  Lock, Menu, Info, FileText, Download, Play, Music, Film,
  Mic, Square, BarChart2, Check, Bot
} from 'lucide-react';
import { MediaViewer } from './MediaViewer';
import { UserSettings } from './UserSettings';
import { CallOverlay } from './CallOverlay';
import { YouTubePreview, YouTubePlayer, isYouTubeUrl, extractYouTubeId } from './YouTubePlayer';
import { StickerPicker, StickerMessage } from './StickerPicker';
import type { Chat, Message } from '../types';

// Cache for blob URLs
const blobUrlCache = new Map<string, string>();

// Component for authenticated image preview
function AuthenticatedImage({ 
  src, 
  alt, 
  className, 
  style,
  onClick,
  serverUrl,
  authToken 
}: { 
  src: string; 
  alt: string; 
  className?: string;
  style?: React.CSSProperties;
  onClick?: () => void;
  serverUrl: string;
  authToken: string | null;
}) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    
    // Check cache first
    const cacheKey = src;
    if (blobUrlCache.has(cacheKey)) {
      setBlobUrl(blobUrlCache.get(cacheKey)!);
      setLoading(false);
      return;
    }

    const fetchImage = async () => {
      try {
        let fetchUrl = src;
        if (src.startsWith('/api/') || src.startsWith('/uploads/')) {
          fetchUrl = `${serverUrl.replace(/\/$/, '')}${src}`;
        }

        const response = await fetch(fetchUrl, {
          headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {},
        });

        if (!response.ok) throw new Error('Failed to load');

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        
        if (mounted) {
          blobUrlCache.set(cacheKey, url);
          setBlobUrl(url);
          setLoading(false);
        }
      } catch {
        if (mounted) {
          setError(true);
          setLoading(false);
        }
      }
    };

    fetchImage();

    return () => {
      mounted = false;
    };
  }, [src, serverUrl, authToken]);

  if (loading) {
    return (
      <div className={className} style={{ ...style, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(255,255,255,0.1)' }}>
        <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (error || !blobUrl) {
    return (
      <div className={className} style={{ ...style, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(255,255,255,0.1)' }}>
        <Image className="h-8 w-8 text-gray-500" />
      </div>
    );
  }

  return (
    <img
      src={blobUrl}
      alt={alt}
      className={className}
      style={style}
      onClick={onClick}
      onError={() => setError(true)}
    />
  );
}

function formatTime(ts: number) {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDate(ts: number) {
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString();
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

const emojis = ['😀', '😂', '😍', '🤔', '👍', '👎', '❤️', '🔥', '🎉', '😢', '😮', '🙏', '💯', '✅', '🚀', '💡', '⭐', '🎵', '📎', '🔒'];

export function ChatScreen() {
  const {
    currentUser, users, chats, messages, activeChat, searchQuery,
    showSidebar, showChatInfo, showNewChat, showNewGroup, serverConfig,
    setActiveChat, sendMessage, editMessage, deleteMessage, createDirectChat,
    createGroup, leaveGroup, addToGroup, removeFromGroup,
    startCall, toggleSidebar, setShowChatInfo, setShowNewChat, setShowNewGroup,
    setSearchQuery, setScreen, logout, decryptMessage, markAsRead,
    searchUsers, fetchUsers, appearance, chatKeys, e2eeKeyPair,
  } = useStore();
  
  const makeChannelAdmin = useStore(s => s.makeChannelAdmin);
  const removeChannelAdmin = useStore(s => s.removeChannelAdmin);
  const updateChatSettings = useStore(s => s.updateChatSettings);

  const [msgInput, setMsgInput] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editText, setEditText] = useState('');
  const [showEmoji, setShowEmoji] = useState(false);
  const [contextMenu, setContextMenu] = useState<{ msgId: string; x: number; y: number } | null>(null);
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [selectedMembers, setSelectedMembers] = useState<string[]>([]);
  const [isCreatingChannel, setIsCreatingChannel] = useState(false);
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [searchedUsers, setSearchedUsers] = useState<typeof users>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [showMobileChat, setShowMobileChat] = useState(false);
  const [mediaViewer, setMediaViewer] = useState<{
    type: 'image' | 'video' | 'audio';
    src: string;
    fileName: string;
  } | null>(null);
  const [uploadingFile, setUploadingFile] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [youtubePlayer, setYoutubePlayer] = useState<string | null>(null);
  const [showStickerPicker, setShowStickerPicker] = useState(false);
  const [savedStickers, setSavedStickers] = useState<string[]>([]);
  
  // Voice recording states
  const [isRecording, setIsRecording] = useState(false);
  const [recordingTime, setRecordingTime] = useState(0);
  const [mediaRecorder, setMediaRecorder] = useState<MediaRecorder | null>(null);
  
  // Poll states
  const [showPollModal, setShowPollModal] = useState(false);
  const [pollQuestion, setPollQuestion] = useState('');
  const [pollOptions, setPollOptions] = useState(['', '']);
  const [pollMultipleChoice, setPollMultipleChoice] = useState(false);
  const [pollAnonymous, setPollAnonymous] = useState(false);
  
  // Chat edit states
  const [editingChatSettings, setEditingChatSettings] = useState(false);
  const [editChatName, setEditChatName] = useState('');
  const [editChatDescription, setEditChatDescription] = useState('');
  const [editChatAvatar, setEditChatAvatar] = useState<string | null>(null);
  const [savingChatSettings, setSavingChatSettings] = useState(false);
  const chatAvatarInputRef = useRef<HTMLInputElement>(null);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const recordingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  
  const { serverUrl, authToken } = useStore();

  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, activeChat, scrollToBottom]);

  useEffect(() => {
    const handleClick = () => { setContextMenu(null); setShowEmoji(false); };
    window.addEventListener('click', handleClick);
    return () => window.removeEventListener('click', handleClick);
  }, []);

  if (!currentUser) return null;

  const myChats = chats.filter(c => c.participants.includes(currentUser.id));
  const filteredChats = myChats.filter(c => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    if (c.type === 'group') return c.name?.toLowerCase().includes(q);
    const other = users.find(u => c.participants.find(p => p !== currentUser.id) === u.id);
    return other?.username.toLowerCase().includes(q);
  });

  const chat = activeChat ? chats.find(c => c.id === activeChat) : null;
  const chatMessages = activeChat ? messages.filter(m => m.chatId === activeChat) : [];

  const hasBotInChat = (c: Chat) => {
    return c.participants.some(uid => {
      const u = users.find(user => user.id === uid);
      return !!u?.isBot;
    });
  };

  const isE2EEActive = (c: Chat | null) => {
    if (!c) return false;
    if (!serverConfig.encryptionEnabled) return false;
    if (hasBotInChat(c)) return false;
    return !!chatKeys[c.id];
  };

  const isE2EELocked = () => {
    // When session is restored without password, device keys cannot be unlocked,
    // so encrypted messages will show as placeholders until a full login.
    return serverConfig.encryptionEnabled && !e2eeKeyPair;
  };

  // getChatDisplayName is used instead of this

  const getChatAvatar = (c: Chat): { type: 'image' | 'letter'; value: string } => {
    if (c.type === 'group' || c.isChannel) {
      return { type: 'letter', value: c.name?.[0]?.toUpperCase() || 'G' };
    }
    const otherId = c.participants.find(p => p !== currentUser.id);
    const otherUser = users.find(u => u.id === otherId);
    const avatar = otherUser?.avatar;
    // Check if avatar is a valid URL or data URI
    if (avatar && (avatar.startsWith('http') || avatar.startsWith('data:') || avatar.startsWith('/'))) {
      return { type: 'image', value: avatar };
    }
    const displayName = otherUser?.displayName || otherUser?.username || 'U';
    return { type: 'letter', value: displayName?.[0]?.toUpperCase() || 'U' };
  };

  const getChatDisplayName = (c: Chat) => {
    // Groups and channels should display their name
    if (c.type === 'group' || c.type === 'channel' || c.isChannel) {
      return c.name || (c.isChannel ? 'Channel' : 'Group');
    }
    // Direct chats show the other user's name
    const otherId = c.participants.find(p => p !== currentUser.id);
    const otherUser = users.find(u => u.id === otherId);
    const displayName = otherUser?.displayName || otherUser?.username || 'Unknown Chat';
    return displayName + (otherUser?.isBot ? ' 🤖' : '');
  };

  const getUserAvatar = (userId: string) => {
    const user = users.find(u => u.id === userId);
    return user?.avatar;
  };

  const getUserDisplayName = (userId: string) => {
    const user = users.find(u => u.id === userId);
    return user?.displayName || user?.username || `User ${userId.slice(0,8)}`;
  };

  const getChatOnline = (c: Chat) => {
    if (c.type === 'group' || c.type === 'channel' || c.isChannel) return false;
    const otherId = c.participants.find(p => p !== currentUser.id);
    return users.find(u => u.id === otherId)?.online || false;
  };

  const handleSend = () => {
    if (!msgInput.trim() || !activeChat) return;
    sendMessage(activeChat, msgInput.trim());
    setMsgInput('');
  };

  const handleEditSave = () => {
    if (editingId && editText.trim()) {
      editMessage(editingId, editText.trim());
      setEditingId(null);
      setEditText('');
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !activeChat || !authToken) return;
    
    setUploadingFile(true);
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
        },
        body: formData,
      });
      
      if (!response.ok) {
        throw new Error('Upload failed');
      }
      
      const data = await response.json();
      
      // Determine file type
      const mimeType = data.mimeType || file.type;
      let messageType: 'image' | 'file' = 'file';
      if (mimeType.startsWith('image/')) messageType = 'image';
      
      // Send message with file info
      sendMessage(activeChat, data.fileName, messageType, data.fileName, data.fileSize, data.fileUrl);
    } catch (error) {
      console.error('File upload failed:', error);
    } finally {
      setUploadingFile(false);
      e.target.value = '';
    }
  };
  
  // Helper functions for media type detection
  const isImageFile = (fileName: string, mimeType?: string) => {
    if (mimeType?.startsWith('image/')) return true;
    const ext = fileName.toLowerCase().split('.').pop();
    return ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'].includes(ext || '');
  };
  
  const isVideoFile = (fileName: string, mimeType?: string) => {
    if (mimeType?.startsWith('video/')) return true;
    const ext = fileName.toLowerCase().split('.').pop();
    return ['mp4', 'webm', 'ogg', 'mov', 'avi', 'mkv'].includes(ext || '');
  };
  
  const isAudioFile = (fileName: string, mimeType?: string) => {
    if (mimeType?.startsWith('audio/')) return true;
    const ext = fileName.toLowerCase().split('.').pop();
    return ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma'].includes(ext || '');
  };
  
  const getFileIcon = (fileName: string) => {
    if (isImageFile(fileName)) return <Image className="h-5 w-5 shrink-0" />;
    if (isVideoFile(fileName)) return <Film className="h-5 w-5 shrink-0" />;
    if (isAudioFile(fileName)) return <Music className="h-5 w-5 shrink-0" />;
    return <FileText className="h-5 w-5 shrink-0" />;
  };
  
  const handleMediaClick = (message: Message) => {
    const fileName = message.fileName || 'file';
    const fileUrl = message.fileUrl || message.content;
    
    if (isImageFile(fileName)) {
      setMediaViewer({ type: 'image', src: fileUrl, fileName });
    } else if (isVideoFile(fileName)) {
      setMediaViewer({ type: 'video', src: fileUrl, fileName });
    } else if (isAudioFile(fileName)) {
      setMediaViewer({ type: 'audio', src: fileUrl, fileName });
    }
  };
  
  const handleDownload = async (fileUrl: string, fileName: string) => {
    try {
      const downloadUrl = fileUrl.includes('/api/files/') 
        ? `${serverUrl.replace(/\/$/, '')}${fileUrl}/download`
        : `${serverUrl.replace(/\/$/, '')}${fileUrl}`;
      
      const response = await fetch(downloadUrl, {
        headers: authToken ? { 'Authorization': `Bearer ${authToken}` } : {},
      });
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed:', err);
    }
  };

  const handleCreateGroup = () => {
    if (groupName.trim() && selectedMembers.length > 0) {
      createGroup(groupName.trim(), selectedMembers, groupDesc.trim() || undefined, isCreatingChannel);
      setGroupName('');
      setGroupDesc('');
      setSelectedMembers([]);
      setIsCreatingChannel(false);
    }
  };

  const handleStartBot = async () => {
    if (!activeChat) return;
    sendMessage(activeChat, '/start');
  };

  const handleUserSearch = async () => {
    if (!userSearchQuery.trim()) {
      setSearchedUsers([]);
      return;
    }
    setIsSearching(true);
    const results = await searchUsers(userSearchQuery.trim());
    // For admins, the server returns partial matches
    // For others, the server returns exact matches only
    if (currentUser.role === 'admin') {
      // Admin gets partial matches from server
      setSearchedUsers(results.filter(u => u.id !== currentUser?.id));
    } else {
      // Moderators and users get exact match only (server already filters)
      setSearchedUsers(results.filter(u => 
        u.id !== currentUser?.id && u.role !== 'banned'
      ));
    }
    setIsSearching(false);
  };

  const clearUserSearch = () => {
    setUserSearchQuery('');
    setSearchedUsers([]);
    fetchUsers();
  };

  // Voice recording functions
  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const recorder = new MediaRecorder(stream, { mimeType: 'audio/webm' });
      const chunks: Blob[] = [];
      
      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) chunks.push(e.data);
      };
      
      recorder.onstop = async () => {
        stream.getTracks().forEach(t => t.stop());
        const blob = new Blob(chunks, { type: 'audio/webm' });
        await sendVoiceMessage(blob);
      };
      
      setMediaRecorder(recorder);
      recorder.start();
      setIsRecording(true);
      setRecordingTime(0);
      
      recordingIntervalRef.current = setInterval(() => {
        setRecordingTime(t => t + 1);
      }, 1000);
    } catch (err) {
      console.error('Failed to start recording:', err);
    }
  };
  
  const stopRecording = () => {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
      mediaRecorder.stop();
    }
    setIsRecording(false);
    if (recordingIntervalRef.current) {
      clearInterval(recordingIntervalRef.current);
      recordingIntervalRef.current = null;
    }
  };
  
  const cancelRecording = () => {
    if (mediaRecorder && mediaRecorder.state !== 'inactive') {
      mediaRecorder.stream.getTracks().forEach(t => t.stop());
      mediaRecorder.stop();
    }
    setIsRecording(false);
    if (recordingIntervalRef.current) {
      clearInterval(recordingIntervalRef.current);
      recordingIntervalRef.current = null;
    }
  };
  
  const sendVoiceMessage = async (blob: Blob) => {
    if (!activeChat || !authToken) return;
    
    setUploadingFile(true);
    try {
      const formData = new FormData();
      const fileName = `voice_${Date.now()}.webm`;
      formData.append('file', blob, fileName);
      
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/upload`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` },
        body: formData,
      });
      
      if (!response.ok) throw new Error('Upload failed');
      
      const data = await response.json();
      sendMessage(activeChat, data.fileName, 'voice', data.fileName, data.fileSize, data.fileUrl);
    } catch (err) {
      console.error('Failed to send voice message:', err);
    } finally {
      setUploadingFile(false);
    }
  };
  
  const formatRecordingTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };
  
  // Poll functions
  const handleSendSticker = (sticker: { id: string; name: string; imageData: string }) => {
    if (!activeChat) return;
    // Send sticker as a message with type 'sticker'
    sendMessage(activeChat, sticker.id, 'sticker' as any, sticker.name);
  };
  
  const handleSaveSticker = (stickerId: string) => {
    setSavedStickers(prev => [...prev, stickerId]);
  };

  const handleCreatePoll = async () => {
    if (!activeChat || !authToken || !pollQuestion.trim()) return;
    
    const validOptions = pollOptions.filter(o => o.trim());
    if (validOptions.length < 2) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${activeChat}/polls`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question: pollQuestion.trim(),
          options: validOptions,
          multipleChoice: pollMultipleChoice,
          anonymous: pollAnonymous,
        }),
      });
      
      if (!response.ok) throw new Error('Failed to create poll');
      
      setShowPollModal(false);
      setPollQuestion('');
      setPollOptions(['', '']);
      setPollMultipleChoice(false);
      setPollAnonymous(false);
    } catch (err) {
      console.error('Failed to create poll:', err);
    }
  };
  
  const handleVotePoll = async (pollId: string, optionIndex: number) => {
    if (!authToken) return;
    
    try {
      await fetch(`${serverUrl.replace(/\/$/, '')}/api/polls/${pollId}/vote`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${authToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ optionIndex }),
      });
    } catch (err) {
      console.error('Failed to vote:', err);
    }
  };
  
  const addPollOption = () => {
    if (pollOptions.length < 10) {
      setPollOptions([...pollOptions, '']);
    }
  };
  
  const removePollOption = (index: number) => {
    if (pollOptions.length > 2) {
      setPollOptions(pollOptions.filter((_, i) => i !== index));
    }
  };
  
  const updatePollOption = (index: number, value: string) => {
    const newOptions = [...pollOptions];
    newOptions[index] = value;
    setPollOptions(newOptions);
  };

  // Chat settings edit functions
  const startEditingChatSettings = () => {
    if (!chat) return;
    setEditChatName(chat.name || '');
    setEditChatDescription(chat.description || '');
    setEditChatAvatar(chat.avatar || null);
    setEditingChatSettings(true);
  };
  
  const cancelEditingChatSettings = () => {
    setEditingChatSettings(false);
    setEditChatName('');
    setEditChatDescription('');
    setEditChatAvatar(null);
  };
  
  const handleSaveChatSettings = async () => {
    if (!chat) return;
    setSavingChatSettings(true);
    try {
      await updateChatSettings(chat.id, {
        name: editChatName || undefined,
        description: editChatDescription || undefined,
        avatar: editChatAvatar || undefined,
      });
      setEditingChatSettings(false);
    } finally {
      setSavingChatSettings(false);
    }
  };
  
  const handleChatAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    // Convert to base64
    const reader = new FileReader();
    reader.onload = () => {
      const base64 = reader.result as string;
      setEditChatAvatar(base64);
    };
    reader.readAsDataURL(file);
    e.target.value = '';
  };
  
  // Check if user can edit chat settings
  const canEditChatSettings = (c: Chat) => {
    if (!c || c.type === 'direct') return false;
    if (currentUser.role === 'admin') return true;
    if (c.isChannel && c.isChannelAdmin) return true;
    if (c.type === 'group' && c.admins?.includes(currentUser.id)) return true;
    return false;
  };

  const getMessageContent = (m: Message) => {
    if (m.encrypted) {
      return decryptMessage(m.content);
    }
    return m.content;
  };

  const roleIcon = (role: string) => {
    if (role === 'admin') return <Crown className="h-3 w-3 text-amber-400" />;
    if (role === 'moderator') return <Shield className="h-3 w-3 text-blue-400" />;
    if (role === 'bot') return <span className="ml-1 rounded bg-purple-500/20 px-1.5 py-0.5 text-[10px] font-bold uppercase text-purple-400 border border-purple-500/30 tracking-wider">Bot</span>;
    return null;
  };

  const totalUnread = myChats.reduce((sum, c) => sum + c.unreadCount, 0);

  // Get chat background class based on appearance
  const getChatBgClass = () => {
    switch (appearance.chatBackground) {
      case 'gradient1': return 'chat-bg-gradient1';
      case 'gradient2': return 'chat-bg-gradient2';
      case 'gradient3': return 'chat-bg-gradient3';
      case 'solid': return 'chat-bg-solid';
      default: return 'chat-bg-default';
    }
  };

  // Get message style class
  const getMessageStyleClass = () => {
    switch (appearance.messageStyle) {
      case 'classic': return 'message-classic';
      case 'minimal': return 'message-minimal';
      case 'bubbles': return 'message-bubbles';
      default: return 'message-modern';
    }
  };

  // Get border radius for messages
  const getMessageRadius = () => {
    switch (appearance.roundedCorners) {
      case 'none': return 'rounded-none';
      case 'small': return 'rounded-md';
      case 'large': return 'rounded-3xl';
      default: return 'rounded-2xl';
    }
  };

  // Get message spacing
  const getMessageSpacing = () => {
    switch (appearance.density) {
      case 'compact': return 'mb-1';
      case 'spacious': return 'mb-6';
      default: return 'mb-3';
    }
  };

  // Format time based on 24-hour preference
  const formatTimeWithPreference = (ts: number) => {
    const d = new Date(ts);
    if (appearance.use24HourTime) {
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
    }
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Group messages by date
  const messagesByDate: { date: string; msgs: Message[] }[] = [];
  chatMessages.forEach(m => {
    const date = formatDate(m.timestamp);
    const last = messagesByDate[messagesByDate.length - 1];
    if (last && last.date === date) {
      last.msgs.push(m);
    } else {
      messagesByDate.push({ date, msgs: [m] });
    }
  });

  return (
    <div className="flex h-screen bg-gray-900">
      {/* Sidebar */}
      <div className={`${showSidebar ? 'flex' : 'hidden'} ${activeChat && showMobileChat ? 'hidden md:flex' : 'flex'} w-full flex-col border-r border-white/10 bg-gray-900/80 md:w-80 lg:w-96 shrink-0`}>
        {/* User header */}
        <div className="flex items-center gap-3 border-b border-white/10 p-4">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 font-bold text-white">
            {currentUser.username[0].toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="font-semibold text-white truncate">{currentUser.username}</span>
              {roleIcon(currentUser.role)}
            </div>
            <span className="text-xs text-green-400">Online</span>
          </div>
          <div className="flex items-center gap-1">
            <button onClick={() => setShowSettings(true)} className="rounded-lg p-2 text-gray-400 transition hover:bg-white/10 hover:text-white" title="Settings">
              <Settings className="h-5 w-5" />
            </button>
            {(currentUser.role === 'admin' || currentUser.role === 'moderator') && (
              <button onClick={() => setScreen('admin')} className="rounded-lg p-2 text-gray-400 transition hover:bg-white/10 hover:text-amber-400" title={currentUser.role === 'admin' ? 'Admin Panel' : 'Moderation Panel'}>
                <Crown className="h-5 w-5" />
              </button>
            )}
            <button onClick={logout} className="rounded-lg p-2 text-gray-400 transition hover:bg-white/10 hover:text-red-400" title="Logout">
              <LogOut className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Search + New */}
        <div className="flex items-center gap-2 p-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search chats..."
              className="w-full rounded-lg border border-white/10 bg-white/5 py-2 pl-9 pr-3 text-sm text-white placeholder-gray-500 outline-none focus:border-indigo-500"
            />
          </div>
          <button onClick={() => setShowNewChat(true)} className="rounded-lg bg-indigo-500/20 p-2 text-indigo-400 transition hover:bg-indigo-500/30" title="New Chat">
            <Plus className="h-5 w-5" />
          </button>
        </div>

        {/* Chat list */}
        <div className="flex-1 overflow-y-auto">
          {filteredChats.length === 0 && (
            <div className="p-8 text-center text-gray-500">
              <MessageSquare className="mx-auto mb-2 h-8 w-8" />
              <p className="text-sm">No chats yet</p>
            </div>
          )}
          {filteredChats.sort((a, b) => (b.lastMessage?.timestamp || b.createdAt) - (a.lastMessage?.timestamp || a.createdAt)).map(c => (
            <button
              key={c.id}
              onClick={() => { setActiveChat(c.id); setShowMobileChat(true); markAsRead(c.id); }}
              className={`flex w-full items-center gap-3 px-4 py-3 transition hover:bg-white/5 ${activeChat === c.id ? 'bg-indigo-500/10 border-l-2 border-indigo-500' : 'border-l-2 border-transparent'}`}
            >
              <div className="relative">
                <div className={`flex h-12 w-12 items-center justify-center rounded-full font-bold text-white ${c.isChannel ? 'bg-gradient-to-br from-amber-500 to-orange-600' : c.type === 'group' ? 'bg-gradient-to-br from-emerald-500 to-teal-600' : 'bg-gradient-to-br from-indigo-500 to-purple-600'}`}>
                  {c.isChannel ? '📢' : c.type === 'group' ? <Users className="h-5 w-5" /> : (() => {
                    const av = getChatAvatar(c);
                    return av.type === 'image' ? <img src={av.value} alt="" className="w-full h-full rounded-full object-cover" /> : av.value;
                  })()}
                </div>
                {getChatOnline(c) && (
                  <div className="absolute bottom-0 right-0 h-3.5 w-3.5 rounded-full border-2 border-gray-900 bg-green-500" />
                )}
              </div>
              <div className="flex-1 min-w-0 text-left">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-white truncate">{getChatDisplayName(c)}</span>
                  {c.lastMessage && (
                    <span className="text-xs text-gray-500 shrink-0 ml-2">{formatTime(c.lastMessage.timestamp)}</span>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-400 truncate">
                    {c.lastMessage ? (
                      c.lastMessage.type === 'system' ? c.lastMessage.content :
                      `${c.lastMessage.senderId === currentUser.id ? 'You: ' : ''}${c.lastMessage.content}`
                    ) : 'No messages yet'}
                  </span>
                  {c.unreadCount > 0 && (
                    <span className="ml-2 flex h-5 min-w-5 items-center justify-center rounded-full bg-indigo-500 px-1.5 text-xs font-bold text-white shrink-0">
                      {c.unreadCount}
                    </span>
                  )}
                </div>
              </div>
            </button>
          ))}
        </div>

        {/* Bottom bar */}
        <div className="border-t border-white/10 p-3">
          <div className="flex items-center justify-between text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Lock className="h-3 w-3" />
              {serverConfig.encryptionEnabled ? 'End-to-end encryption available' : 'Encryption disabled by server'}
            </span>
            <span>{totalUnread > 0 ? `${totalUnread} unread` : 'All read'}</span>
          </div>
        </div>
      </div>

      {/* Chat area */}
      <div className={`${!activeChat && !showMobileChat ? 'hidden md:flex' : 'flex'} flex-1 flex-col ${getChatBgClass()}`}>
        {!activeChat ? (
          <div className="flex flex-1 items-center justify-center">
            <div className="text-center">
              <div className="mx-auto mb-4 flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20">
                <MessageSquare className="h-10 w-10 text-indigo-400" />
              </div>
              <h3 className="text-xl font-semibold text-white">Select a chat</h3>
              <p className="mt-1 text-gray-400">Choose a conversation or start a new one</p>
            </div>
          </div>
        ) : chat ? (
          <>
            {/* Chat header */}
            <div className="flex items-center gap-3 border-b border-white/10 bg-gray-900/50 px-4 py-3 backdrop-blur">
              <button onClick={() => { setActiveChat(null); setShowMobileChat(false); }} className="rounded-lg p-1 text-gray-400 md:hidden hover:text-white">
                <ChevronLeft className="h-6 w-6" />
              </button>
              <button onClick={() => toggleSidebar()} className="hidden rounded-lg p-1 text-gray-400 md:block hover:text-white">
                <Menu className="h-5 w-5" />
              </button>
              <div className="relative">
                <div className={`flex h-10 w-10 items-center justify-center rounded-full font-bold text-white ${chat.isChannel ? 'bg-gradient-to-br from-amber-500 to-orange-600' : chat.type === 'group' ? 'bg-gradient-to-br from-emerald-500 to-teal-600' : 'bg-gradient-to-br from-indigo-500 to-purple-600'}`}>
                  {chat.isChannel ? '📢' : chat.type === 'group' ? <Hash className="h-5 w-5" /> : (() => {
                    const av = getChatAvatar(chat);
                    return av.type === 'image' ? <img src={av.value} alt="" className="w-full h-full rounded-full object-cover" /> : av.value;
                  })()}
                </div>
                {getChatOnline(chat) && (
                  <div className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-gray-900 bg-green-500" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="font-semibold text-white truncate">{getChatDisplayName(chat)}</h3>
                <p className="text-xs text-gray-400">
                  {chat.isChannel
                    ? `Channel • ${chat.participants.length} subscribers`
                    : chat.type === 'group'
                    ? `${chat.participants.length} members`
                    : (() => {
                        const otherId = chat.participants.find(p => p !== currentUser.id);
                        const otherUser = users.find(u => u.id === otherId);
                        if (otherUser?.role === 'bot') return 'Bot';
                        return getChatOnline(chat) ? 'Online' : 'Offline';
                      })()
                  }
                </p>
              </div>
              <div className="flex items-center gap-1">
                {serverConfig.encryptionEnabled && (
                  <div
                    className={`mr-1 flex items-center gap-1 rounded-full px-2 py-1 text-xs border ${
                      isE2EEActive(chat)
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : hasBotInChat(chat)
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        : isE2EELocked()
                        ? 'bg-red-500/10 text-red-400 border-red-500/20'
                        : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                    }`}
                    title={
                      isE2EEActive(chat)
                        ? 'Messages are end-to-end encrypted'
                        : hasBotInChat(chat)
                        ? 'Bots cannot read E2EE messages; encryption is disabled for this chat'
                        : isE2EELocked()
                        ? 'E2EE keys are locked (session restored). Sign out and sign in to unlock.'
                        : 'E2EE not set up for this chat yet'
                    }
                  >
                    <Lock className="h-3 w-3" />
                    {isE2EEActive(chat)
                      ? 'E2EE on'
                      : hasBotInChat(chat)
                      ? 'E2EE off (bot)'
                      : isE2EELocked()
                      ? 'E2EE locked'
                      : 'E2EE off'}
                  </div>
                )}
                <button onClick={() => startCall(chat.id, 'voice')} className="rounded-lg p-2 text-gray-400 transition hover:bg-white/10 hover:text-white" title="Voice call">
                  <Phone className="h-5 w-5" />
                </button>
                <button onClick={() => startCall(chat.id, 'video')} className="rounded-lg p-2 text-gray-400 transition hover:bg-white/10 hover:text-white" title="Video call">
                  <Video className="h-5 w-5" />
                </button>
                <button onClick={() => setShowChatInfo(!showChatInfo)} className="rounded-lg p-2 text-gray-400 transition hover:bg-white/10 hover:text-white" title="Chat info">
                  <Info className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto px-4 py-4" onClick={() => setContextMenu(null)}>
              {serverConfig.encryptionEnabled && (
                <div className={`mx-auto mb-4 flex max-w-md items-center justify-center gap-2 rounded-full px-4 py-2 text-xs border ${
                  isE2EEActive(chat)
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : hasBotInChat(chat)
                    ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                    : isE2EELocked()
                    ? 'bg-red-500/10 text-red-400 border-red-500/20'
                    : 'bg-gray-500/10 text-gray-400 border-gray-500/20'
                }`}>
                  <Lock className="h-3 w-3" />
                  {isE2EEActive(chat)
                    ? 'Messages are end-to-end encrypted'
                    : hasBotInChat(chat)
                    ? 'Encryption disabled for this chat (bot participants)'
                    : isE2EELocked()
                    ? 'Encrypted messages are locked (refresh the page or log in again to unlock)'
                    : 'Encryption not set up for this chat yet'}
                </div>
              )}

              {messagesByDate.map(group => (
                <div key={group.date}>
                  <div className="my-4 flex items-center justify-center">
                    <span className="rounded-full bg-white/5 px-3 py-1 text-xs text-gray-500">{group.date}</span>
                  </div>
                  {group.msgs.map(m => {
                    const sender = users.find(u => u.id === m.senderId);
                    const isMe = m.senderId === currentUser.id;
                    const isSystem = m.type === 'system';

                    if (isSystem) {
                      return (
                        <div key={m.id} className="my-2 text-center">
                          <span className="rounded-full bg-white/5 px-3 py-1 text-xs text-gray-500">{m.content}</span>
                        </div>
                      );
                    }

                    return (
                      <div key={m.id} className={`${getMessageSpacing()} flex ${isMe ? 'justify-end' : 'justify-start'}`}>
                        <div className={`group relative max-w-[75%] ${isMe ? 'order-2' : ''}`}>
                          {!isMe && (chat.type === 'group' || chat.isChannel) && appearance.showAvatars && (() => {
                            const avatar = getUserAvatar(m.senderId);
                            const isAvatarUrl = avatar && (avatar.startsWith('http') || avatar.startsWith('data:') || avatar.startsWith('/'));
                            return (
                            <div className="mb-0.5 flex items-center gap-1 text-xs">
                              {isAvatarUrl ? (
                                <img src={avatar} alt="" className="w-4 h-4 rounded-full object-cover" />
                              ) : null}
                              <span className="font-medium" style={{ color: appearance.accentColor }}>{getUserDisplayName(m.senderId)}</span>
                              {sender && roleIcon(sender.role)}
                            </div>
                            );
                          })()}
                          <div
                            className={`${getMessageRadius()} ${getMessageStyleClass()} px-4 py-2.5 ${
                              isMe
                                ? 'text-white'
                                : 'bg-white/10 text-gray-100'
                            }`}
                            style={isMe ? { background: `linear-gradient(to right, ${appearance.accentColor}, ${appearance.accentColor}dd)` } : undefined}
                            onContextMenu={e => {
                              e.preventDefault();
                              if (isMe || currentUser.role === 'admin' || currentUser.role === 'moderator') {
                                setContextMenu({ msgId: m.id, x: e.clientX, y: e.clientY });
                              }
                            }}
                          >
                            {/* File/media content - show if fileUrl exists OR type is file/image */}
                            {(() => {
                              const hasFile = !!(m.fileUrl || m.type === 'file' || m.type === 'image');
                              if (!hasFile) return null;
                              
                              const fileName = m.fileName || m.fileUrl?.split('/').pop() || 'file';
                              const fileUrl = m.fileUrl || '';
                              const isImage = isImageFile(fileName);
                              const isVideo = isVideoFile(fileName);
                              const isAudio = isAudioFile(fileName);
                              
                              return (
                              <div className="mb-2">
                                {/* Preview for images */}
                                {fileUrl && isImage && (
                                  <div 
                                    className="mb-2 cursor-pointer rounded-lg overflow-hidden max-w-xs"
                                    onClick={() => handleMediaClick(m)}
                                  >
                                    <AuthenticatedImage 
                                      src={fileUrl}
                                      alt={fileName}
                                      className="max-w-full h-auto rounded-lg hover:opacity-90 transition-opacity"
                                      style={{ maxHeight: '200px', minHeight: '80px', minWidth: '80px' }}
                                      serverUrl={serverUrl}
                                      authToken={authToken}
                                    />
                                  </div>
                                )}
                                
                                {/* Video preview */}
                                {fileUrl && isVideo && (
                                  <div 
                                    className="mb-2 cursor-pointer rounded-lg overflow-hidden max-w-xs bg-black/20 p-4 flex items-center justify-center"
                                    onClick={() => handleMediaClick(m)}
                                  >
                                    <div className="flex flex-col items-center gap-2">
                                      <div className="w-12 h-12 rounded-full bg-white/10 flex items-center justify-center">
                                        <Play className="h-6 w-6 ml-1" />
                                      </div>
                                      <span className="text-xs opacity-70">Click to play video</span>
                                    </div>
                                  </div>
                                )}
                                
                                {/* Audio preview */}
                                {fileUrl && isAudio && (
                                  <div 
                                    className="mb-2 cursor-pointer rounded-lg overflow-hidden bg-gradient-to-r from-purple-500/20 to-indigo-500/20 p-3 flex items-center gap-3"
                                    onClick={() => handleMediaClick(m)}
                                  >
                                    <div className="w-10 h-10 rounded-full bg-white/10 flex items-center justify-center shrink-0">
                                      <Play className="h-5 w-5 ml-0.5" />
                                    </div>
                                    <div className="min-w-0 flex-1">
                                      <p className="text-sm font-medium truncate">{m.type === 'voice' ? '🎤 Voice message' : fileName}</p>
                                      <p className="text-xs opacity-70">Click to play</p>
                                    </div>
                                  </div>
                                )}
                                
                                {/* Non-media file preview - downloadable files */}
                                {!isImage && !isVideo && !isAudio && (
                                  <div 
                                    className="mb-2 cursor-pointer rounded-lg overflow-hidden bg-gradient-to-r from-gray-500/20 to-gray-600/20 p-3 flex items-center gap-3 hover:from-gray-500/30 hover:to-gray-600/30 transition-colors"
                                    onClick={() => handleDownload(fileUrl || m.content, fileName)}
                                  >
                                    <div className="w-10 h-10 rounded-full bg-white/10 flex items-center justify-center shrink-0">
                                      <FileText className="h-5 w-5" />
                                    </div>
                                    <div className="min-w-0 flex-1">
                                      <p className="text-sm font-medium truncate">{fileName}</p>
                                      <p className="text-xs opacity-70">
                                        {m.fileSize ? formatFileSize(m.fileSize) : 'Click to download'}
                                      </p>
                                    </div>
                                    <div className="w-8 h-8 rounded-full bg-indigo-500/20 flex items-center justify-center shrink-0">
                                      <Download className="h-4 w-4 text-indigo-400" />
                                    </div>
                                  </div>
                                )}
                                
                                {/* File info bar for media files */}
                                {(isImage || isVideo || isAudio) && (
                                <div className="flex items-center gap-2">
                                  {getFileIcon(fileName)}
                                  <div className="min-w-0 flex-1">
                                    <p className="text-sm font-medium truncate">{fileName}</p>
                                    {m.fileSize && <p className="text-xs opacity-70">{formatFileSize(m.fileSize)}</p>}
                                  </div>
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      handleDownload(fileUrl || m.content, fileName);
                                    }}
                                    className={`p-1.5 rounded-lg transition ${isMe ? 'hover:bg-white/20' : 'hover:bg-white/10'}`}
                                    title="Download"
                                  >
                                    <Download className="h-4 w-4" />
                                  </button>
                                </div>
                                )}
                              </div>
                              );
                            })()}
                            {/* Only show text content for text messages without files */}
                            {m.type === 'text' && !m.fileUrl && (() => {
                              const content = getMessageContent(m);
                              const youtubeMatch = content.match(/(https?:\/\/)?(www\.)?(youtube\.com|youtu\.be)\S+/);
                              const youtubeUrl = youtubeMatch?.[0];
                              const hasYoutube = youtubeUrl && isYouTubeUrl(youtubeUrl) && extractYouTubeId(youtubeUrl);
                              
                              return (
                                <>
                                  <p className="text-sm whitespace-pre-wrap break-words">{content}</p>
                                  {hasYoutube && (
                                    <div className="mt-2">
                                      <YouTubePreview 
                                        url={youtubeUrl} 
                                        onClick={() => setYoutubePlayer(youtubeUrl)} 
                                      />
                                    </div>
                                  )}
                                </>
                              );
                            })()}
                            {/* Sticker message */}
                            {m.type === 'sticker' && (
                              <div className="min-w-[100px]">
                                <StickerMessage 
                                  stickerId={m.content}
                                  onSave={handleSaveSticker}
                                  isSaved={savedStickers.includes(m.content)}
                                />
                              </div>
                            )}
                            {/* Poll message */}
                            {m.type === 'poll' && m.poll && (
                              <div className="min-w-[250px]">
                                <div className="flex items-center gap-2 mb-2">
                                  <BarChart2 className="h-4 w-4 text-indigo-400" />
                                  <span className="text-xs text-indigo-400 font-medium">Poll</span>
                                  {m.poll.anonymous && <span className="text-xs text-gray-500">• Anonymous</span>}
                                </div>
                                <p className="font-medium mb-3">{m.poll.question}</p>
                                <div className="space-y-2">
                                  {m.poll.options.map((option, idx) => {
                                    const totalVotes = m.poll!.options.reduce((sum, o) => sum + o.votes.length, 0);
                                    const percentage = totalVotes > 0 ? Math.round((option.votes.length / totalVotes) * 100) : 0;
                                    const hasVoted = option.votes.includes(currentUser.id);
                                    const userHasVotedAny = m.poll!.options.some(o => o.votes.includes(currentUser.id));
                                    
                                    return (
                                      <button
                                        key={idx}
                                        onClick={() => !userHasVotedAny && !m.poll!.closed && handleVotePoll(m.poll!.id, idx)}
                                        disabled={userHasVotedAny || m.poll!.closed}
                                        className={`w-full text-left rounded-lg p-2 transition relative overflow-hidden ${
                                          hasVoted ? 'bg-indigo-500/30 border border-indigo-500/50' : 
                                          userHasVotedAny || m.poll!.closed ? 'bg-white/5' : 'bg-white/5 hover:bg-white/10'
                                        }`}
                                      >
                                        {/* Progress bar background */}
                                        {userHasVotedAny && (
                                          <div 
                                            className="absolute inset-y-0 left-0 bg-indigo-500/20 transition-all"
                                            style={{ width: `${percentage}%` }}
                                          />
                                        )}
                                        <div className="relative flex items-center justify-between">
                                          <div className="flex items-center gap-2">
                                            {hasVoted && <Check className="h-4 w-4 text-indigo-400" />}
                                            <span className="text-sm">{option.text}</span>
                                          </div>
                                          {userHasVotedAny && (
                                            <span className="text-xs text-gray-400">
                                              {percentage}% ({option.votes.length})
                                            </span>
                                          )}
                                        </div>
                                      </button>
                                    );
                                  })}
                                </div>
                                <div className="mt-2 text-xs text-gray-500">
                                  {m.poll.options.reduce((sum, o) => sum + o.votes.length, 0)} votes
                                  {m.poll.multipleChoice && ' • Multiple choice'}
                                  {m.poll.closed && ' • Closed'}
                                </div>
                              </div>
                            )}
                            {appearance.showTimestamps && (
                            <div className={`mt-1 flex items-center gap-1.5 text-[10px] ${isMe ? 'text-white/70' : 'text-gray-500'}`}>
                              <span>{formatTimeWithPreference(m.timestamp)}</span>
                              {m.edited && <span>• edited</span>}
                              {m.encrypted && <Lock className="h-2.5 w-2.5" />}
                            </div>
                            )}
                          </div>

                          {/* Quick actions on hover */}
                          {(isMe || currentUser.role === 'admin' || currentUser.role === 'moderator') && (
                            <button
                              onClick={e => { e.stopPropagation(); setContextMenu({ msgId: m.id, x: e.clientX, y: e.clientY }); }}
                              className={`absolute top-1 ${isMe ? '-left-8' : '-right-8'} hidden rounded p-1 text-gray-500 hover:bg-white/10 hover:text-white group-hover:block`}
                            >
                              <MoreVertical className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>

            {/* Context menu */}
            {contextMenu && (
              <div
                className="fixed z-50 rounded-xl border border-white/10 bg-gray-800 py-1 shadow-xl"
                style={{ left: Math.min(contextMenu.x, window.innerWidth - 160), top: Math.min(contextMenu.y, window.innerHeight - 100) }}
                onClick={e => e.stopPropagation()}
              >
                {messages.find(m => m.id === contextMenu.msgId)?.senderId === currentUser.id && (
                  <button
                    onClick={() => {
                      const msg = messages.find(m => m.id === contextMenu.msgId);
                      if (msg) {
                        setEditingId(msg.id);
                        setEditText(getMessageContent(msg));
                      }
                      setContextMenu(null);
                    }}
                    className="flex w-full items-center gap-2 px-4 py-2 text-sm text-gray-300 hover:bg-white/10"
                  >
                    <Edit2 className="h-4 w-4" /> Edit
                  </button>
                )}
                <button
                  onClick={() => { deleteMessage(contextMenu.msgId); setContextMenu(null); }}
                  className="flex w-full items-center gap-2 px-4 py-2 text-sm text-red-400 hover:bg-white/10"
                >
                  <Trash2 className="h-4 w-4" /> Delete
                </button>
              </div>
            )}

            {/* Edit bar */}
            {editingId && (
              <div className="flex items-center gap-2 border-t border-amber-500/20 bg-amber-500/5 px-4 py-2">
                <Edit2 className="h-4 w-4 text-amber-400" />
                <span className="text-sm text-amber-400">Editing message</span>
                <div className="flex-1" />
                <button onClick={() => { setEditingId(null); setEditText(''); }} className="text-gray-400 hover:text-white">
                  <X className="h-4 w-4" />
                </button>
              </div>
            )}

            {/* Input */}
            <div className="border-t border-white/10 bg-gray-900/50 p-4 backdrop-blur">
              {/* Channel restriction message */}
              {chat.isChannel && !chat.isChannelAdmin && currentUser.role !== 'admin' ? (
                <div className="flex items-center justify-center gap-2 py-3 text-gray-400">
                  <Lock className="h-4 w-4" />
                  <span className="text-sm">Only channel admins can send messages</span>
                </div>
              ) : isRecording ? (
                /* Voice Recording UI */
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2 flex-1">
                    <div className="h-3 w-3 rounded-full bg-red-500 animate-pulse" />
                    <span className="text-red-400 font-medium">{formatRecordingTime(recordingTime)}</span>
                    <span className="text-gray-400 text-sm">Recording...</span>
                  </div>
                  <button
                    onClick={cancelRecording}
                    className="rounded-lg p-2.5 text-gray-400 transition hover:bg-white/10 hover:text-red-400"
                    title="Cancel"
                  >
                    <X className="h-5 w-5" />
                  </button>
                  <button
                    onClick={stopRecording}
                    className="rounded-xl bg-gradient-to-r from-red-500 to-pink-600 p-2.5 text-white shadow-lg transition hover:shadow-red-500/30 active:scale-95"
                    title="Stop & Send"
                  >
                    <Square className="h-5 w-5 fill-current" />
                  </button>
                </div>
              ) : (
              <div className="flex items-end gap-2">
                <input ref={fileInputRef} type="file" className="hidden" onChange={handleFileUpload} />
                <button onClick={() => fileInputRef.current?.click()} className="rounded-lg p-2.5 text-gray-400 transition hover:bg-white/10 hover:text-white shrink-0" title="Attach file">
                  <Paperclip className="h-5 w-5" />
                </button>
                {/* Poll button - only for groups and channels */}
                {(chat.type === 'group' || chat.isChannel) && (
                  <button onClick={() => setShowPollModal(true)} className="rounded-lg p-2.5 text-gray-400 transition hover:bg-white/10 hover:text-white shrink-0" title="Create poll">
                    <BarChart2 className="h-5 w-5" />
                  </button>
                )}
                <div className="relative flex-1">
                  <textarea
                    value={editingId ? editText : msgInput}
                    onChange={e => editingId ? setEditText(e.target.value) : setMsgInput(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        editingId ? handleEditSave() : handleSend();
                      }
                    }}
                    placeholder="Type a message..."
                    rows={1}
                    className="max-h-32 w-full resize-none rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                  />
                </div>
                <div className="relative shrink-0">
                  <button 
                    onClick={e => { e.stopPropagation(); setShowStickerPicker(!showStickerPicker); setShowEmoji(false); }} 
                    className="rounded-lg p-2.5 text-gray-400 transition hover:bg-white/10 hover:text-white"
                    title="Stickers"
                  >
                    <Image className="h-5 w-5" />
                  </button>
                  <StickerPicker
                    isOpen={showStickerPicker}
                    onClose={() => setShowStickerPicker(false)}
                    onSelectSticker={handleSendSticker}
                  />
                </div>
                <div className="relative shrink-0">
                  <button onClick={e => { e.stopPropagation(); setShowEmoji(!showEmoji); setShowStickerPicker(false); }} className="rounded-lg p-2.5 text-gray-400 transition hover:bg-white/10 hover:text-white">
                    <Smile className="h-5 w-5" />
                  </button>
                  {showEmoji && (
                    <div className="absolute bottom-12 right-0 z-50 rounded-xl border border-white/10 bg-gray-800 p-3 shadow-xl w-[280px]" onClick={e => e.stopPropagation()}>
                      <div className="grid grid-cols-5 gap-2">
                        {emojis.map(em => (
                          <button
                            key={em}
                            onClick={() => { editingId ? setEditText(p => p + em) : setMsgInput(p => p + em); setShowEmoji(false); }}
                            className="w-12 h-12 rounded-lg text-2xl transition hover:bg-white/10 flex items-center justify-center"
                          >
                            {em}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                {/* Voice message or Send button */}
                {msgInput.trim() || editingId ? (
                  <button
                    onClick={editingId ? handleEditSave : handleSend}
                    className="rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 p-2.5 text-white shadow-lg transition hover:shadow-indigo-500/30 active:scale-95 shrink-0"
                  >
                    <Send className="h-5 w-5" />
                  </button>
                ) : (
                  <button
                    onClick={startRecording}
                    className="rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 p-2.5 text-white shadow-lg transition hover:shadow-indigo-500/30 active:scale-95 shrink-0"
                    title="Record voice message"
                  >
                    <Mic className="h-5 w-5" />
                  </button>
                )}
              </div>
              )}
            </div>
          </>
        ) : null}
      </div>

      {/* Chat Info Panel */}
      {showChatInfo && chat && (
        <div className="w-80 shrink-0 border-l border-white/10 bg-gray-900/80 overflow-y-auto hidden lg:block">
          <div className="p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-white">Chat Info</h3>
              <div className="flex items-center gap-1">
                {canEditChatSettings(chat) && !editingChatSettings && (
                  <button onClick={startEditingChatSettings} className="text-gray-400 hover:text-white p-1" title="Edit settings">
                    <Edit2 className="h-4 w-4" />
                  </button>
                )}
                <button onClick={() => { setShowChatInfo(false); cancelEditingChatSettings(); }} className="text-gray-400 hover:text-white"><X className="h-5 w-5" /></button>
              </div>
            </div>

            {editingChatSettings ? (
              /* Edit Mode */
              <div className="mb-6">
                {/* Avatar Upload */}
                <div className="text-center mb-4">
                  <input 
                    ref={chatAvatarInputRef} 
                    type="file" 
                    accept="image/*" 
                    className="hidden" 
                    onChange={handleChatAvatarUpload} 
                  />
                  <button 
                    onClick={() => chatAvatarInputRef.current?.click()}
                    className={`relative mx-auto mb-3 flex h-20 w-20 items-center justify-center rounded-full text-2xl font-bold text-white overflow-hidden ${chat.isChannel ? 'bg-gradient-to-br from-amber-500 to-orange-600' : chat.type === 'group' ? 'bg-gradient-to-br from-emerald-500 to-teal-600' : 'bg-gradient-to-br from-indigo-500 to-purple-600'} hover:opacity-80 transition`}
                    title="Click to change avatar"
                  >
                    {editChatAvatar ? (
                      <img src={editChatAvatar} alt="" className="w-full h-full object-cover" />
                    ) : chat.avatar ? (
                      <img src={chat.avatar} alt="" className="w-full h-full object-cover" />
                    ) : chat.isChannel ? (
                      '📢'
                    ) : (
                      <Users className="h-8 w-8" />
                    )}
                    <div className="absolute inset-0 flex items-center justify-center bg-black/50 opacity-0 hover:opacity-100 transition">
                      <Image className="h-6 w-6" />
                    </div>
                  </button>
                  <p className="text-xs text-gray-500">Click to change icon</p>
                </div>
                
                {/* Name Input */}
                <div className="mb-3">
                  <label className="block text-xs font-medium text-gray-400 mb-1">{chat.isChannel ? 'Channel Name' : 'Group Name'}</label>
                  <input
                    type="text"
                    value={editChatName}
                    onChange={e => setEditChatName(e.target.value)}
                    placeholder={chat.isChannel ? 'Channel name' : 'Group name'}
                    className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-indigo-500"
                  />
                </div>
                
                {/* Description Input */}
                <div className="mb-4">
                  <label className="block text-xs font-medium text-gray-400 mb-1">Description</label>
                  <textarea
                    value={editChatDescription}
                    onChange={e => setEditChatDescription(e.target.value)}
                    placeholder="Description (optional)"
                    rows={3}
                    className="w-full resize-none rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-indigo-500"
                  />
                </div>
                
                {/* Save/Cancel buttons */}
                <div className="flex gap-2">
                  <button
                    onClick={cancelEditingChatSettings}
                    className="flex-1 rounded-lg border border-white/10 py-2 text-sm text-gray-400 hover:bg-white/5"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveChatSettings}
                    disabled={savingChatSettings || !editChatName.trim()}
                    className="flex-1 rounded-lg bg-gradient-to-r from-indigo-500 to-purple-600 py-2 text-sm font-medium text-white disabled:opacity-50"
                  >
                    {savingChatSettings ? 'Saving...' : 'Save'}
                  </button>
                </div>
              </div>
            ) : (
              /* View Mode */
              <div className="text-center mb-6">
                <div className={`mx-auto mb-3 flex h-20 w-20 items-center justify-center rounded-full text-2xl font-bold text-white overflow-hidden ${chat.isChannel ? 'bg-gradient-to-br from-amber-500 to-orange-600' : chat.type === 'group' ? 'bg-gradient-to-br from-emerald-500 to-teal-600' : 'bg-gradient-to-br from-indigo-500 to-purple-600'}`}>
                  {chat.avatar ? (
                    <img src={chat.avatar} alt="" className="w-full h-full object-cover" />
                  ) : chat.isChannel ? (
                    '📢'
                  ) : chat.type === 'group' ? (
                    <Users className="h-8 w-8" />
                  ) : (() => {
                    const av = getChatAvatar(chat);
                    return av.type === 'image' ? <img src={av.value} alt="" className="w-full h-full rounded-full object-cover" /> : av.value;
                  })()}
                </div>
                <h4 className="text-lg font-semibold text-white">{getChatDisplayName(chat)}</h4>
                <p className="text-xs text-gray-500 mt-0.5">
                  {chat.isChannel ? 'Channel' : chat.type === 'group' ? 'Group' : 'Direct'}
                </p>
                {chat.description && <p className="text-sm text-gray-400 mt-2">{chat.description}</p>}
                {(chat.type === 'group' || chat.isChannel) && <p className="text-xs text-gray-500 mt-1">{chat.participants.length} {chat.isChannel ? 'subscribers' : 'members'}</p>}
              </div>
            )}

            {/* Channel Admins Section */}
            {chat.isChannel && (
              <div className="mb-6">
                <h5 className="text-sm font-medium text-gray-300 mb-2">Channel Admins</h5>
                <div className="space-y-2">
                  {(chat.channelAdmins || []).map(adminId => {
                    const admin = users.find(u => u.id === adminId);
                    if (!admin) return null;
                    return (
                      <div key={adminId} className="flex items-center justify-between py-1">
                        <div className="flex items-center gap-2">
                          <div className="h-6 w-6 rounded-full bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-xs font-bold text-white">
                            {admin.username[0].toUpperCase()}
                          </div>
                          <span className="text-sm text-white">{admin.displayName || admin.username}</span>
                        </div>
                        {chat.isChannelAdmin && adminId !== currentUser.id && (
                          <button
                            onClick={() => removeChannelAdmin(chat.id, adminId)}
                            className="text-xs text-red-400 hover:text-red-300"
                          >
                            Remove
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
                {chat.isChannelAdmin && (
                  <div className="mt-2">
                    <select
                      onChange={(e) => {
                        if (e.target.value) {
                          makeChannelAdmin(chat.id, e.target.value);
                          e.target.value = '';
                        }
                      }}
                      className="w-full rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-sm text-white outline-none"
                      defaultValue=""
                    >
                      <option value="" disabled>Add channel admin...</option>
                      {chat.participants
                        .filter(p => !chat.channelAdmins?.includes(p))
                        .map(pid => {
                          const member = users.find(u => u.id === pid);
                          return member ? (
                            <option key={pid} value={pid} className="bg-gray-800">
                              {member.displayName || member.username}
                            </option>
                          ) : null;
                        })}
                    </select>
                  </div>
                )}
              </div>
            )}
            
            {chat.type === 'group' && (
              <>
                <div className="mb-3 flex items-center justify-between">
                  <h5 className="text-sm font-medium text-gray-300">Members</h5>
                  {(chat.admins?.includes(currentUser.id) || currentUser.role === 'admin') && (
                    <button
                      onClick={() => {
                        const available = users.filter(u => !chat.participants.includes(u.id) && u.role !== 'banned');
                        if (available.length > 0) {
                          addToGroup(chat.id, available[0].id);
                        }
                      }}
                      className="text-indigo-400 hover:text-indigo-300"
                    >
                      <UserPlus className="h-4 w-4" />
                    </button>
                  )}
                </div>
                {chat.participants.map(pid => {
                  const member = users.find(u => u.id === pid);
                  if (!member) return null;
                  return (
                    <div key={pid} className="flex items-center gap-3 py-2">
                      <div className="relative">
                        <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 text-sm font-bold text-white">
                          {member.username[0].toUpperCase()}
                        </div>
                        {member.online && <div className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-gray-900 bg-green-500" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-1">
                          <span className="text-sm text-white truncate">{member.username}</span>
                          {roleIcon(member.role)}
                          {chat.admins?.includes(pid) && <span className="text-[10px] text-amber-400">admin</span>}
                        </div>
                      </div>
                      {pid !== currentUser.id && (chat.admins?.includes(currentUser.id) || currentUser.role === 'admin') && (
                        <button onClick={() => removeFromGroup(chat.id, pid)} className="text-gray-500 hover:text-red-400">
                          <X className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  );
                })}

                <div className="mt-4 space-y-2">
                  <button
                    onClick={() => leaveGroup(chat.id)}
                    className="w-full rounded-lg border border-red-500/20 bg-red-500/5 py-2 text-sm text-red-400 transition hover:bg-red-500/10"
                  >
                    Leave Group
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* New Chat Modal */}
      {showNewChat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => { setShowNewChat(false); clearUserSearch(); }}>
          <div className="w-full max-w-sm rounded-2xl border border-white/10 bg-gray-900 p-6 shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">New Conversation</h3>
              <button onClick={() => { setShowNewChat(false); clearUserSearch(); }} className="text-gray-400 hover:text-white"><X className="h-5 w-5" /></button>
            </div>
            <button
              onClick={() => { setShowNewChat(false); setShowNewGroup(true); clearUserSearch(); }}
              className="mb-3 flex w-full items-center gap-3 rounded-xl border border-white/10 bg-white/5 p-3 text-left transition hover:bg-white/10"
            >
              <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-emerald-500 to-teal-600">
                <Users className="h-5 w-5 text-white" />
              </div>
              <div>
                <p className="font-medium text-white">New Group / Channel</p>
                <p className="text-xs text-gray-400">Create a group or channel</p>
              </div>
            </button>
            
            {/* User Search */}
            <div className="mb-3">
              <p className="mb-2 text-sm font-medium text-gray-400">Find User</p>
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                  <input
                    type="text"
                    value={userSearchQuery}
                    onChange={e => setUserSearchQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleUserSearch()}
                    placeholder={currentUser.role === 'admin' ? "Search users..." : "Enter exact username"}
                    className="w-full rounded-xl border border-white/10 bg-white/5 py-2 pl-10 pr-3 text-sm text-white placeholder-gray-500 outline-none focus:border-indigo-500"
                  />
                  {userSearchQuery && (
                    <button onClick={clearUserSearch} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white">
                      <X className="h-4 w-4" />
                    </button>
                  )}
                </div>
                <button
                  onClick={handleUserSearch}
                  disabled={isSearching || !userSearchQuery.trim()}
                  className="rounded-xl bg-indigo-500/20 px-4 py-2 text-sm text-indigo-400 transition hover:bg-indigo-500/30 disabled:opacity-50"
                >
                  {isSearching ? '...' : 'Search'}
                </button>
              </div>
              <p className="mt-1 text-xs text-gray-500">
                {currentUser.role === 'admin' 
                  ? "Search by username, email, or display name" 
                  : "To find a user, enter their exact username"}
              </p>
            </div>
            
            <p className="mb-2 text-sm font-medium text-gray-400">
              {userSearchQuery ? 'Search Results' : 'Recent Contacts'}
            </p>
            <div className="max-h-60 overflow-y-auto space-y-1">
              {(userSearchQuery ? searchedUsers : users).filter(u => u.id !== currentUser.id && u.role !== 'banned').length === 0 ? (
                <p className="text-center text-sm text-gray-500 py-4">
                  {userSearchQuery ? 'No user found. Check the username.' : 'No recent contacts. Search for a user by their exact username.'}
                </p>
              ) : (
                (userSearchQuery ? searchedUsers : users).filter(u => u.id !== currentUser.id && u.role !== 'banned').map(u => (
                  <button
                    key={u.id}
                    onClick={async () => { await createDirectChat(u.id); }}
                    className="flex w-full items-center gap-3 rounded-xl p-3 transition hover:bg-white/5"
                  >
                    <div className="relative">
                      <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 font-bold text-white">
                        {u.username[0].toUpperCase()}
                      </div>
                      {u.online && <div className="absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-gray-900 bg-green-500" />}
                    </div>
                    <div className="text-left">
                      <div className="flex items-center gap-1">
                        <span className="font-medium text-white">{u.username}</span>
                        {roleIcon(u.role)}
                      </div>
                      <span className="text-xs text-gray-400">{u.role === 'bot' ? 'Bot' : (u.online ? 'Online' : 'Offline')}</span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </div>
          
          {/* Start Bot Button */}
          {chat?.type === 'direct' && (() => {
            const otherUserId = chat.participants.find(p => p !== currentUser.id);
            const otherUser = otherUserId ? users.find(u => u.id === otherUserId) : null;
            if (otherUser?.isBot && chatMessages.length === 0) {
              return (
                <div className="absolute bottom-24 left-0 right-0 flex justify-center z-10 px-4">
                  <button
                    onClick={() => handleStartBot()}
                    className="w-full max-w-md bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 px-6 rounded-xl shadow-lg transition-transform transform hover:scale-[1.02] flex items-center justify-center space-x-2"
                  >
                    <Bot className="w-5 h-5" />
                    <span>Start Bot</span>
                  </button>
                </div>
              );
            }
            return null;
          })()}
        </div>
      )}

      {/* New Group Modal */}
      {showNewGroup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => { setShowNewGroup(false); setIsCreatingChannel(false); }}>
          <div className="w-full max-w-sm rounded-2xl border border-white/10 bg-gray-900 p-6 shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">{isCreatingChannel ? 'Create Channel' : 'Create Group'}</h3>
              <button onClick={() => { setShowNewGroup(false); setIsCreatingChannel(false); }} className="text-gray-400 hover:text-white"><X className="h-5 w-5" /></button>
            </div>
            
            {/* Channel Toggle */}
            <div className="mb-4 flex items-center justify-between rounded-xl bg-white/5 p-3">
              <div className="flex items-center gap-2">
                <span className="text-xl">{isCreatingChannel ? '📢' : '👥'}</span>
                <div>
                  <p className="text-sm font-medium text-white">Channel</p>
                  <p className="text-xs text-gray-500">Only admins can post</p>
                </div>
              </div>
              <button
                onClick={() => setIsCreatingChannel(!isCreatingChannel)}
                className={`relative h-6 w-11 rounded-full transition ${isCreatingChannel ? 'bg-indigo-500' : 'bg-gray-600'}`}
              >
                <span className={`absolute top-1 left-1 h-4 w-4 rounded-full bg-white transition-transform ${isCreatingChannel ? 'translate-x-5' : ''}`} />
              </button>
            </div>
            
            <input
              type="text"
              value={groupName}
              onChange={e => setGroupName(e.target.value)}
              placeholder={isCreatingChannel ? "Channel name" : "Group name"}
              className="mb-3 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white placeholder-gray-500 outline-none focus:border-indigo-500"
            />
            <textarea
              value={groupDesc}
              onChange={e => setGroupDesc(e.target.value)}
              placeholder="Description (optional)"
              rows={2}
              className="mb-3 w-full resize-none rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-white placeholder-gray-500 outline-none focus:border-indigo-500"
            />
            <p className="mb-2 text-sm font-medium text-gray-400">Add Members</p>
            <div className="max-h-40 overflow-y-auto space-y-1 mb-4">
              {users.filter(u => u.id !== currentUser.id && u.role !== 'banned').length === 0 ? (
                <p className="text-center text-sm text-gray-500 py-4">No users available to add</p>
              ) : (
                users.filter(u => u.id !== currentUser.id && u.role !== 'banned').map(u => (
                  <label key={u.id} className="flex items-center gap-3 rounded-lg p-2 transition hover:bg-white/5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedMembers.includes(u.id)}
                      onChange={e => {
                        if (e.target.checked) setSelectedMembers(prev => [...prev, u.id]);
                        else setSelectedMembers(prev => prev.filter(id => id !== u.id));
                      }}
                      className="rounded border-white/20 bg-white/5 text-indigo-500 focus:ring-indigo-500"
                    />
                    <span className="text-sm text-white">{u.username}</span>
                    {roleIcon(u.role)}
                  </label>
                ))
              )}
            </div>
            <button
              onClick={handleCreateGroup}
              disabled={!groupName.trim() || selectedMembers.length === 0}
              className="w-full rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-2.5 font-semibold text-white shadow-lg transition disabled:opacity-50 active:scale-[0.98]"
            >
              {isCreatingChannel ? `Create Channel (${selectedMembers.length} subscribers)` : `Create Group (${selectedMembers.length} selected)`}
            </button>
          </div>
        </div>
      )}

      {/* Poll Modal */}
      {showPollModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setShowPollModal(false)}>
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-gray-900 p-6 shadow-2xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <BarChart2 className="h-5 w-5 text-indigo-400" />
                <h3 className="text-lg font-semibold text-white">Create Poll</h3>
              </div>
              <button onClick={() => setShowPollModal(false)} className="text-gray-400 hover:text-white"><X className="h-5 w-5" /></button>
            </div>
            
            <input
              type="text"
              value={pollQuestion}
              onChange={e => setPollQuestion(e.target.value)}
              placeholder="Ask a question..."
              className="mb-4 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-gray-500 outline-none focus:border-indigo-500"
            />
            
            <p className="mb-2 text-sm font-medium text-gray-400">Options</p>
            <div className="space-y-2 mb-4 max-h-40 overflow-y-auto">
              {pollOptions.map((option, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <input
                    type="text"
                    value={option}
                    onChange={e => updatePollOption(idx, e.target.value)}
                    placeholder={`Option ${idx + 1}`}
                    className="flex-1 rounded-lg border border-white/10 bg-white/5 px-3 py-2 text-white placeholder-gray-500 outline-none focus:border-indigo-500"
                  />
                  {pollOptions.length > 2 && (
                    <button onClick={() => removePollOption(idx)} className="text-gray-500 hover:text-red-400">
                      <X className="h-4 w-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>
            
            {pollOptions.length < 10 && (
              <button
                onClick={addPollOption}
                className="mb-4 flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300"
              >
                <Plus className="h-4 w-4" /> Add option
              </button>
            )}
            
            <div className="space-y-3 mb-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={pollMultipleChoice}
                  onChange={e => setPollMultipleChoice(e.target.checked)}
                  className="rounded border-white/20 bg-white/5 text-indigo-500 focus:ring-indigo-500"
                />
                <span className="text-sm text-gray-300">Allow multiple choices</span>
              </label>
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={pollAnonymous}
                  onChange={e => setPollAnonymous(e.target.checked)}
                  className="rounded border-white/20 bg-white/5 text-indigo-500 focus:ring-indigo-500"
                />
                <span className="text-sm text-gray-300">Anonymous voting</span>
              </label>
            </div>
            
            <button
              onClick={handleCreatePoll}
              disabled={!pollQuestion.trim() || pollOptions.filter(o => o.trim()).length < 2}
              className="w-full rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-2.5 font-semibold text-white shadow-lg transition disabled:opacity-50 active:scale-[0.98]"
            >
              Create Poll
            </button>
          </div>
        </div>
      )}

      {/* Media Viewer */}
      {mediaViewer && (
        <MediaViewer
          type={mediaViewer.type}
          src={mediaViewer.src}
          fileName={mediaViewer.fileName}
          onClose={() => setMediaViewer(null)}
        />
      )}

      {/* File Upload Indicator */}
      {uploadingFile && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 backdrop-blur-sm">
          <div className="rounded-xl bg-gray-800 p-6 text-center">
            <div className="mx-auto mb-3 h-12 w-12 animate-spin rounded-full border-4 border-indigo-500 border-t-transparent" />
            <p className="text-white">Uploading file...</p>
          </div>
        </div>
      )}

      {/* User Settings Modal */}
      {showSettings && (
        <UserSettings onClose={() => setShowSettings(false)} />
      )}

      {/* Call Overlay */}
      <CallOverlay />

      {/* YouTube Player */}
      {youtubePlayer && (
        <YouTubePlayer url={youtubePlayer} onClose={() => setYoutubePlayer(null)} />
      )}
    </div>
  );
}
