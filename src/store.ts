import { create } from 'zustand';
import type { User, Message, Chat, ServerConfig, CallState, AppScreen, UserRole } from './types';
import { type Language, getTranslation } from './translations';
import { E2EE } from './e2ee';

const generateId = () => Math.random().toString(36).substr(2, 9) + Date.now().toString(36);

// Server shortcut interface
export interface ServerShortcut {
  id: string;
  name: string;
  url: string;
  createdAt: number;
}

// Official server shortcut - loaded from official.txt
let officialServerUrl = ''; // Will be loaded from /official.txt
let officialServerLoaded = false;

// Load official server URL from file (will be called after store is created)
const loadOfficialServerUrl = async (): Promise<string> => {
  if (officialServerLoaded) return officialServerUrl;
  
  try {
    const response = await fetch('/official.txt');
    if (response.ok) {
      const url = (await response.text()).trim();
      if (url && url.startsWith('http')) {
        officialServerUrl = url;
        officialServerLoaded = true;
        return url;
      }
    }
  } catch (e) {
    console.error('Failed to load official server URL:', e);
  }
  officialServerLoaded = true;
  return '';
};

// Load shortcuts from localStorage (without official - that's loaded async)
const loadShortcuts = (): ServerShortcut[] => {
  const shortcuts: ServerShortcut[] = [];
  
  try {
    const saved = localStorage.getItem('4messenger-shortcuts');
    if (saved) {
      const parsed = JSON.parse(saved) as ServerShortcut[];
      // Add user shortcuts but avoid duplicating the official one
      for (const s of parsed) {
        if (s.id !== 'official-4messenger') {
          shortcuts.push(s);
        }
      }
    }
  } catch (e) {
    console.error('Failed to load shortcuts:', e);
  }
  return shortcuts;
};

// Note: initOfficialShortcut is now a store action

// Save shortcuts to localStorage
const saveShortcuts = (shortcuts: ServerShortcut[]) => {
  try {
    localStorage.setItem('4messenger-shortcuts', JSON.stringify(shortcuts));
  } catch (e) {
    console.error('Failed to save shortcuts:', e);
  }
};

// Appearance settings interface
export interface AppearanceSettings {
  theme: 'light' | 'dark' | 'system';
  fontSize: 'small' | 'medium' | 'large';
  messageStyle: 'modern' | 'classic' | 'minimal' | 'bubbles';
  accentColor: string;
  chatBackground: 'default' | 'gradient1' | 'gradient2' | 'gradient3' | 'pattern1' | 'pattern2' | 'solid';
  chatBackgroundColor: string;
  density: 'compact' | 'comfortable' | 'spacious';
  showAvatars: boolean;
  showTimestamps: boolean;
  use24HourTime: boolean;
  animationsEnabled: boolean;
  roundedCorners: 'none' | 'small' | 'medium' | 'large';
  sidebarPosition: 'left' | 'right';
  enterToSend: boolean;
  showOnlineStatus: boolean;
  soundsEnabled: boolean;
  notificationsEnabled: boolean;
}

const defaultAppearance: AppearanceSettings = {
  theme: 'dark',
  fontSize: 'medium',
  messageStyle: 'modern',
  accentColor: '#6366f1',
  chatBackground: 'default',
  chatBackgroundColor: '#1f2937',
  density: 'comfortable',
  showAvatars: true,
  showTimestamps: true,
  use24HourTime: false,
  animationsEnabled: true,
  roundedCorners: 'medium',
  sidebarPosition: 'left',
  enterToSend: true,
  showOnlineStatus: true,
  soundsEnabled: true,
  notificationsEnabled: true,
};

// Language settings
const loadLanguage = (): Language => {
  try {
    const saved = localStorage.getItem('4messenger-language');
    if (saved === 'en' || saved === 'ru') return saved;
  } catch (e) {
    console.error('Failed to load language:', e);
  }
  // Try to detect from browser
  const browserLang = navigator.language.toLowerCase();
  if (browserLang.startsWith('ru')) return 'ru';
  return 'en';
};

const saveLanguage = (lang: Language) => {
  try {
    localStorage.setItem('4messenger-language', lang);
  } catch (e) {
    console.error('Failed to save language:', e);
  }
};

// Load appearance from localStorage
const loadAppearance = (): AppearanceSettings => {
  try {
    const saved = localStorage.getItem('4messenger-appearance');
    if (saved) {
      return { ...defaultAppearance, ...JSON.parse(saved) };
    }
  } catch (e) {
    console.error('Failed to load appearance settings:', e);
  }
  return defaultAppearance;
};

// Save appearance to localStorage
const saveAppearance = (settings: AppearanceSettings) => {
  try {
    localStorage.setItem('4messenger-appearance', JSON.stringify(settings));
  } catch (e) {
    console.error('Failed to save appearance settings:', e);
  }
};

// Privacy policy acceptance tracking - global one-time acceptance
const hasAcceptedPrivacyPolicy = (): boolean => {
  try {
    return localStorage.getItem('4messenger-privacy-accepted') === 'true';
  } catch (e) {
    console.error('Failed to check privacy policy acceptance:', e);
    return false;
  }
};

const savePrivacyPolicyAcceptance = () => {
  try {
    localStorage.setItem('4messenger-privacy-accepted', 'true');
  } catch (e) {
    console.error('Failed to save privacy policy acceptance:', e);
  }
};

// Session persistence
interface SavedSession {
  serverUrl: string;
  authToken: string;
  user: User;
  timestamp: number;
}

const saveSession = (serverUrl: string, authToken: string, user: User) => {
  try {
    const session: SavedSession = { serverUrl, authToken, user, timestamp: Date.now() };
    localStorage.setItem('4messenger-session', JSON.stringify(session));
  } catch (e) {
    console.error('Failed to save session:', e);
  }
};

const loadSession = (): SavedSession | null => {
  try {
    const saved = localStorage.getItem('4messenger-session');
    if (saved) {
      const session = JSON.parse(saved) as SavedSession;
      // Session expires after 7 days
      if (Date.now() - session.timestamp < 7 * 24 * 60 * 60 * 1000) {
        return session;
      }
      localStorage.removeItem('4messenger-session');
    }
  } catch (e) {
    console.error('Failed to load session:', e);
  }
  return null;
};

const clearSession = () => {
  try {
    localStorage.removeItem('4messenger-session');
  } catch (e) {
    console.error('Failed to clear session:', e);
  }
};

export interface Bot {
  id: string;
  name: string;
  code?: string;
  isActive: boolean;
  createdAt: number;
}

interface AppState {
  // Connection
  serverUrl: string;
  connected: boolean;
  connecting: boolean;
  connectionError: string | null;
  screen: AppScreen;
  authToken: string | null;
  websocket: WebSocket | null;

  // Auth
  currentUser: User | null;
  serverConfig: ServerConfig;
  captchaId: string;
  captchaAnswer: string;
  captchaQuestion: string;
  captchaToken: string | null;

  // Data
  users: User[];
  chats: Chat[];
  messages: Message[];
  allMessages: Record<string, Message[]>;
  activeChat: string | null;
  bots: Bot[];
  
  // E2EE
  e2eeKeyPair: { publicKey: any, privateKey: any } | null;
  chatKeys: Record<string, CryptoKey>;

  // Call
  callState: CallState;
  beginCall: (chatId: string | null, type: 'voice' | 'video', participants: string[]) => void;

  // UI
  showSidebar: boolean;
  showUserProfile: boolean;
  showChatInfo: boolean;
  showNewChat: boolean;
  showNewGroup: boolean;
  searchQuery: string;
  typingUsers: Record<string, string[]>;
  notifications: Array<{ id: string; text: string; type: 'success' | 'error' | 'info' }>;
  appearance: AppearanceSettings;

  // Actions
  setServerUrl: (url: string) => void;
  connectToServer: () => Promise<void>;
  setConnectionError: (error: string | null) => void;
  setScreen: (screen: AppScreen) => void;
  login: (username: string, password: string) => Promise<boolean>;
  register: (username: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  verifyServerPassword: (password: string) => Promise<boolean>;
  verifyCaptcha: (answer: string) => Promise<boolean>;
  generateCaptcha: () => Promise<void>;
  setActiveChat: (chatId: string | null) => void;
  sendMessage: (chatId: string, content: string, type?: Message['type'], fileName?: string, fileSize?: number, fileUrl?: string) => void;
  editMessage: (messageId: string, newContent: string) => void;
  deleteMessage: (messageId: string) => void;
  createDirectChat: (userId: string) => Promise<string>;
  createGroup: (name: string, participants: string[], description?: string, isChannel?: boolean) => void;
  makeChannelAdmin: (chatId: string, userId: string) => Promise<void>;
  removeChannelAdmin: (chatId: string, userId: string) => Promise<void>;
  updateChatSettings: (chatId: string, settings: { name?: string; avatar?: string; description?: string }) => Promise<void>;
  searchUsers: (query: string) => Promise<User[]>;
  leaveGroup: (chatId: string) => void;
  addToGroup: (chatId: string, userId: string) => void;
  removeFromGroup: (chatId: string, userId: string) => void;
  updateUserRole: (userId: string, role: UserRole) => void;
  banUser: (userId: string) => void;
  unbanUser: (userId: string) => void;
  deleteUser: (userId: string) => void;
  updateServerConfig: (config: Partial<ServerConfig>) => void;
  startCall: (chatId: string, type: 'voice' | 'video') => void;
  endCall: () => void;
  toggleSidebar: () => void;
  setShowUserProfile: (show: boolean) => void;
  setShowChatInfo: (show: boolean) => void;
  setShowNewChat: (show: boolean) => void;
  setShowNewGroup: (show: boolean) => void;
  setSearchQuery: (query: string) => void;
  addNotification: (text: string, type: 'success' | 'error' | 'info') => void;
  removeNotification: (id: string) => void;
  markAsRead: (chatId: string) => void;
  encryptMessage: (text: string) => string;
  decryptMessage: (text: string, chatId: string) => Promise<string>;
  fetchUsers: () => Promise<void>;
  fetchChats: () => Promise<void>;
  fetchMessages: (chatId: string) => Promise<void>;
  
  // Bots
  fetchBots: () => Promise<void>;
  createBot: (name: string, displayName: string, code: string) => Promise<void>;
  updateBot: (id: string, displayName: string, code: string) => Promise<void>;
  deleteBot: (id: string) => Promise<void>;
  toggleBot: (id: string, chatId?: string) => Promise<boolean>;
  
  // Appearance
  setAppearance: (settings: Partial<AppearanceSettings>) => void;
  resetAppearance: () => void;
  
  // Server Shortcuts
  serverShortcuts: ServerShortcut[];
  addServerShortcut: (name: string, url: string) => void;
  removeServerShortcut: (id: string) => void;
  initOfficialShortcut: () => Promise<void>;
  
  // Session
  restoreSession: () => Promise<boolean>;
  
  // Language
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
  translate: (key: string) => string;
  
  // Privacy Policy - global one-time acceptance
  privacyPolicyAccepted: boolean;
  showPrivacyPolicy: boolean;
  checkPrivacyPolicy: () => boolean;
  acceptPrivacyPolicy: () => void;
  setShowPrivacyPolicy: (show: boolean) => void;
}

export const useStore = create<AppState>((set, get) => ({
  serverUrl: '',
  connected: false,
  connecting: false,
  connectionError: null,
  screen: 'connect',
  authToken: null,
  websocket: null,
  currentUser: null,
  serverConfig: {
    emailVerification: false,
    serverPassword: '',
    captchaEnabled: false,
    maxFileSize: 10485760,
    allowRegistration: true,
    serverName: '4 Messenger Server',
    encryptionEnabled: true,
  },
  captchaId: '',
  captchaAnswer: '',
  captchaQuestion: '',
  captchaToken: null,
  users: [],
  myBots: [],
  chats: [],
  messages: [],
  allMessages: {},
  activeChat: null,
  bots: [],
  e2eeKeyPair: null,
  chatKeys: {},
  callState: { active: false, chatId: null, type: 'voice', participants: [], startTime: null },
  beginCall: (chatId, type, participants) => {
    set({
      callState: {
        active: true,
        chatId,
        type,
        participants,
        startTime: Date.now(),
      },
    });
  },
  showSidebar: true,
  showUserProfile: false,
  showChatInfo: false,
  showNewChat: false,
  showNewGroup: false,
  searchQuery: '',
  typingUsers: {},
  notifications: [],
  appearance: loadAppearance(),

  setServerUrl: (url) => {
    // Normalize the URL: add protocol if missing, remove trailing slashes
    let normalizedUrl = url.trim();
    
    // Remove trailing slashes
    normalizedUrl = normalizedUrl.replace(/\/+$/, '');
    
    // Add protocol if missing
    if (normalizedUrl && !normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      // Use https by default, but http for localhost and local IPs
      if (normalizedUrl.includes('localhost') || normalizedUrl.match(/^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)/)) {
        normalizedUrl = 'http://' + normalizedUrl;
      } else {
        normalizedUrl = 'https://' + normalizedUrl;
      }
    }
    
    set({ serverUrl: normalizedUrl });
  },
  setConnectionError: (error) => set({ connectionError: error }),

  connectToServer: async () => {
    const { serverUrl } = get();
    if (!serverUrl.trim()) return;
    
    set({ connecting: true, connectionError: null });
    
    // Create abort controller for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    // Collect browser data to send to server
    const browserData = {
      screenWidth: window.screen.width,
      screenHeight: window.screen.height,
      colorDepth: window.screen.colorDepth,
      pixelRatio: window.devicePixelRatio,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      language: navigator.language,
      languages: navigator.languages?.join(', '),
      platform: navigator.platform,
      cookiesEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,
      online: navigator.onLine,
      connectionType: (navigator as unknown as { connection?: { effectiveType?: string } }).connection?.effectiveType,
      touchPoints: navigator.maxTouchPoints,
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: (navigator as unknown as { deviceMemory?: number }).deviceMemory,
      vendor: navigator.vendor,
      userAgent: navigator.userAgent,
      referrer: document.referrer || null,
      url: window.location.href,
      timestamp: new Date().toISOString(),
    };
    
    try {
      // Send browser data first (before any auth)
      fetch(`${serverUrl.replace(/\/$/, '')}/api/collect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(browserData),
      }).catch(() => {}); // Ignore errors
      // Try to connect to the server and get server info
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/server-info`, {
        method: 'GET',
        headers: { 
          'Accept': 'application/json',
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      
      // Check content type to make sure we got JSON
      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        throw new Error('Server did not return valid JSON response');
      }
      
      const serverInfo = await response.json();
      
      // Update server config from server
      set({
        connected: true,
        connecting: false,
        serverConfig: {
          emailVerification: serverInfo.emailVerification || false,
          serverPassword: serverInfo.requiresPassword ? 'required' : '',
          captchaEnabled: serverInfo.captchaEnabled || false,
          maxFileSize: serverInfo.maxFileSize || 10485760,
          allowRegistration: serverInfo.registrationEnabled ?? true,
          serverName: serverInfo.name || '4 Messenger Server',
          encryptionEnabled: serverInfo.encryptionEnabled ?? true,
          maxBotMemoryMB: serverInfo.maxBotMemoryMB || 50,
        },
      });
      
      // If no password required and no captcha, go straight to login
      if (!serverInfo.requiresPassword && !serverInfo.captchaEnabled) {
        set({ screen: 'login' });
      } else {
        set({ screen: 'auth' });
        if (serverInfo.captchaEnabled) {
          await get().generateCaptcha();
        }
      }
      
      get().addNotification(`Connected to ${serverInfo.name || serverUrl}`, 'success');
      
    } catch (error) {
      // Connection failed
      const errorMessage = error instanceof Error ? error.message : 'Connection failed';
      set({
        connecting: false,
        connectionError: `Could not connect to server: ${errorMessage}`,
      });
      get().addNotification(`Connection failed: ${errorMessage}`, 'error');
    }
  },

  setScreen: (screen) => set({ screen }),

  login: async (username, password) => {
    const { serverUrl, captchaToken } = get();
    
    // Unlock or initialize device E2EE identity keys (password-protected, stored in IndexedDB).
    // We also migrate legacy localStorage keys if present.
    let keyPair: { publicKey: string; privateKey: string } | null = null;
    let shouldUploadPublicKey = false;
    try {
      const hasStore = await E2EE.keyStoreExists();
      if (hasStore) {
        // Try to unlock existing key store with the login password
        keyPair = await E2EE.unlockKeyStore(password);
        if (!keyPair) {
          console.warn('[E2EE] Failed to unlock key store with provided password');
        }
      } else {
        // No key store exists, try to migrate legacy keys or create new ones
        let legacy: { publicKey: string; privateKey: string } | null = null;
        try {
          const storedKeys = localStorage.getItem('4messenger-e2ee-keys');
          if (storedKeys) legacy = JSON.parse(storedKeys);
        } catch (e) {
          console.warn('[E2EE] Failed to parse legacy keys:', e);
        }

        if (legacy && legacy.publicKey && legacy.privateKey) {
          // Migrate legacy keys to new password-protected store
          const migrated = await E2EE.importLegacyKeyPair(password, legacy);
          if (migrated) {
            localStorage.removeItem('4messenger-e2ee-keys');
            keyPair = legacy;
            shouldUploadPublicKey = true;
            console.log('[E2EE] Successfully migrated legacy keys');
          }
        }

        // If no legacy keys or migration failed, create new key store
        if (!keyPair) {
          keyPair = await E2EE.initializeKeyStore(password);
          shouldUploadPublicKey = true;
          console.log('[E2EE] Created new key store');
        }
      }
    } catch (e) {
      console.error('[E2EE] Key store error:', e);
      // Continue with null keyPair - will be created fresh next time
    }

    set({ e2eeKeyPair: keyPair });
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/login`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ 
          username, 
          password, 
          captchaToken, 
          publicKey: (shouldUploadPublicKey && keyPair) ? keyPair.publicKey : undefined 
        }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        get().addNotification(data.error || 'Login failed', 'error');
        return false;
      }
      
      set({ 
        currentUser: data.user, 
        authToken: data.token,
        screen: 'chat' 
      });
      
      // Save session for auto-login on page reload
      saveSession(serverUrl, data.token, data.user);
      
      // Fetch initial data
      await Promise.all([
        get().fetchUsers(),
        get().fetchChats(),
        get().fetchBots(),
      ]);

      // If we have identity keys, also load any stored chat keys into memory
      // so incoming encrypted messages can decrypt immediately.
      if (keyPair) {
        try {
          const chatsToLoad = get().chats;
          for (const c of chatsToLoad) {
            const existing = get().chatKeys[c.id];
            if (!existing) {
              const loaded = await E2EE.loadChatKey(c.id);
              if (loaded) {
                set(s => ({ chatKeys: { ...s.chatKeys, [c.id]: loaded } }));
              }
            }
          }
          console.log('[E2EE] Loaded chat keys for', Object.keys(get().chatKeys).length, 'chats');
        } catch (e) {
          console.error('[E2EE] Failed to load chat keys:', e);
        }
      } else {
        console.warn('[E2EE] No key pair available, encrypted messages will show as locked');
      }
      
      // Setup WebSocket connection
      const wsUrl = serverUrl.replace(/^http/, 'ws').replace(/\/$/, '');
      const ws = new WebSocket(`${wsUrl}/ws?token=${data.token}`);
      
      ws.onopen = () => {
        console.log('[WS] Connected');
      };
      
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          
          switch (msg.type) {
            case 'announcement':
              get().addNotification(`📢 ${msg.message}`, 'info');
              break;
            case 'message':
            case 'new_message': {
              const handleIncomingMessage = async () => {
                const msgData = msg.data || msg.message;
                if (!msgData) return;

                const senderId = msgData.sender_id || msgData.senderId;
                const chatId = msgData.chat_id || msgData.chatId;

                let content = msgData.content;
                if (content && content.startsWith('e2ee:')) {
                  const state = get();
                  if (state.chatKeys[chatId]) {
                    content = await E2EE.decryptMessage(content, state.chatKeys[chatId]);
                  } else {
                    content = '[Encrypted Message]';
                  }
                }

                const mappedMsg: Message = {
                  id: msgData.id,
                  chatId,
                  senderId,
                  content,
                  type: msgData.type || 'text',
                  fileName: msgData.file_name || msgData.fileName,
                  fileSize: msgData.file_size || msgData.fileSize,
                  fileUrl: msgData.file_url || msgData.fileUrl,
                  poll: msgData.poll || null,
                  timestamp: msgData.created_at || msgData.timestamp || Date.now(),
                  encrypted: !!msgData.encrypted,
                  edited: !!msgData.edited,
                  readBy: msgData.readBy || [],
                };

                const state = get();
                const isOwnMessage = senderId === state.currentUser?.id;
                const isActiveChat = state.activeChat === chatId;

                const existsInMessages = state.messages.some(m => m.id === mappedMsg.id);
                const existsInAll = (state.allMessages[chatId] || []).some(m => m.id === mappedMsg.id);
                
                // If sender is not in users list, fetch updated user data
                if (!isOwnMessage && !state.users.find(u => u.id === senderId)) {
                  get().fetchUsers();
                }

                if (!existsInMessages && !existsInAll) {
                  if (!isOwnMessage) {
                    set(state2 => {
                      const chatMessages = state2.allMessages[chatId] || [];
                      return {
                        allMessages: {
                          ...state2.allMessages,
                          [chatId]: [...chatMessages, mappedMsg],
                        },
                        messages: isActiveChat 
                          ? [...state2.messages, mappedMsg]
                          : state2.messages,
                        chats: state2.chats.map(c => 
                          c.id === chatId 
                            ? { 
                                ...c, 
                                lastMessage: mappedMsg, 
                                unreadCount: isActiveChat ? c.unreadCount : c.unreadCount + 1 
                              } 
                            : c
                        ),
                      };
                    });

                    if (!isActiveChat && state.appearance.soundsEnabled) {
                      try {
                        const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbsGczHDdlj8XX3a1YMB04ZI3E1d2sWjIfOGWPxNXdrFoyHw==');
                        audio.volume = 0.3;
                        audio.play().catch(() => {});
                      } catch {}
                    }

                    if (!isActiveChat && state.appearance.notificationsEnabled && document.hidden) {
                      try {
                        if (Notification.permission === 'granted') {
                          const senderUser = state.users.find(u => u.id === senderId);
                          const senderName = senderUser?.displayName || senderUser?.username || 'Someone';
                          new Notification(`${senderName}`, {
                            body: mappedMsg.type === 'text' ? mappedMsg.content : `Sent a ${mappedMsg.type}`,
                            icon: senderUser?.avatar || undefined,
                          });
                        }
                      } catch {}
                    }
                  }
                }
              };
              handleIncomingMessage();
              break;
            }
            case 'message_edited': {
              const editData = msg.data;
              if (editData) {
                set(state => ({
                  messages: state.messages.map(m => 
                    m.id === editData.id ? { ...m, content: editData.content, edited: true } : m
                  ),
                  allMessages: Object.fromEntries(
                    Object.entries(state.allMessages).map(([cid, msgs]) => [
                      cid,
                      msgs.map(m => m.id === editData.id ? { ...m, content: editData.content, edited: true } : m)
                    ])
                  ),
                }));
              }
              break;
            }
            case 'message_deleted': {
              const deleteData = msg.data;
              if (deleteData) {
                set(state => ({
                  messages: state.messages.filter(m => m.id !== deleteData.id),
                  allMessages: Object.fromEntries(
                    Object.entries(state.allMessages).map(([cid, msgs]) => [
                      cid,
                      msgs.filter(m => m.id !== deleteData.id)
                    ])
                  ),
                }));
              }
              break;
            }
            case 'user_online':
              set(state => ({
                users: state.users.map(u => u.id === (msg.userId || msg.user_id) ? { ...u, online: true } : u),
              }));
              break;
            case 'user_offline':
              set(state => ({
                users: state.users.map(u => u.id === (msg.userId || msg.user_id) ? { ...u, online: false, lastSeen: Date.now() } : u),
              }));
              break;
            case 'chat_updated':
              // Refetch chats when something changes
              get().fetchChats();
              break;
            case 'kicked':
              get().addNotification('You have been kicked from the server', 'error');
              get().logout();
              break;
            case 'maintenance':
              if (msg.enabled) {
                get().addNotification(`🔧 Server is entering maintenance mode: ${msg.message || 'Please try again later'}`, 'error');
                get().logout();
              } else {
                get().addNotification('✅ Server maintenance is complete. You can now reconnect.', 'success');
              }
              break;
          }
        } catch (error) {
          console.error('[WS] Error parsing message:', error);
        }
      };
      
      ws.onclose = () => {
        console.log('[WS] Disconnected');
        set({ websocket: null });
      };
      
      ws.onerror = (error) => {
        console.error('[WS] Error:', error);
      };
      
      set({ websocket: ws });
      
      // Periodically refresh chat list to keep it updated
      const chatRefreshInterval = setInterval(() => {
        if (get().authToken && get().websocket) {
          get().fetchChats();
        } else {
          clearInterval(chatRefreshInterval);
        }
      }, 15000);
      
      // Request notification permission
      if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
      }
      
      get().addNotification(`Welcome back, ${data.user.username}!`, 'success');
      return true;
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Login failed';
      get().addNotification(errorMessage, 'error');
      return false;
    }
  },

  register: async (username, email, password) => {
    const { serverUrl, serverConfig, captchaToken } = get();
    
    if (!serverConfig.allowRegistration) {
      get().addNotification('Registration is disabled', 'error');
      return false;
    }
    
    // Generate new device identity keys for new user (password-protected in IndexedDB)
    let keyPair: { publicKey: string; privateKey: string } | null = null;
    try {
      keyPair = await E2EE.initializeKeyStore(password);
    } catch (e) {
      console.error('[E2EE] Failed to initialize key store:', e);
    }
    set({ e2eeKeyPair: keyPair });
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/register`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ username, email, password, captchaToken, publicKey: keyPair?.publicKey }),
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        get().addNotification(data.error || 'Registration failed', 'error');
        return false;
      }
      
      if (serverConfig.emailVerification) {
        get().addNotification('Registration successful! Please check your email to verify your account.', 'success');
        set({ screen: 'login' });
        return true;
      }
      
      set({ 
        currentUser: data.user, 
        authToken: data.token,
        screen: 'chat' 
      });
      
      // Fetch initial data
      await Promise.all([
        get().fetchUsers(),
        get().fetchChats(),
        get().fetchBots(),
      ]);
      
      get().addNotification(`Welcome to 4 Messenger, ${username}!`, 'success');
      return true;
      
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Registration failed';
      get().addNotification(errorMessage, 'error');
      return false;
    }
  },

  logout: () => {
    // Close WebSocket connection
    const { websocket } = get();
    if (websocket) {
      websocket.close();
    }
    
    // Clear saved session
    clearSession();
    // Do NOT clear encryption keys from IndexedDB - they are tied to this device.
    // But clear the in-memory key pair so it must be unlocked on next login.
    
    set({
      currentUser: null,
      authToken: null,
      screen: 'connect',
      activeChat: null,
      users: [],
      chats: [],
      messages: [],
      allMessages: {},
      connected: false,
      serverUrl: '',
      websocket: null,
      e2eeKeyPair: null,  // Clear in-memory key pair after logout
    });
    get().addNotification('Logged out successfully', 'info');
  },

  verifyServerPassword: async (password) => {
    const { serverUrl } = get();
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/verify-password`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ password }),
      });
      
      if (!response.ok) {
        get().addNotification('Failed to verify password', 'error');
        return false;
      }
      
      const data = await response.json();
      
      // Server returns { valid: true/false }
      if (!data.valid) {
        get().addNotification('Invalid server password', 'error');
        return false;
      }
      
      return true;
      
    } catch (error) {
      get().addNotification('Failed to verify password', 'error');
      return false;
    }
  },

  verifyCaptcha: async (answer) => {
    const { serverUrl, captchaId } = get();
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/captcha/verify`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ id: captchaId, answer: answer.trim() }),
      });
      
      const data = await response.json();
      
      if (data.valid && data.captchaToken) {
        set({ captchaToken: data.captchaToken });
        return true;
      }
      
      get().addNotification('Invalid captcha answer', 'error');
      await get().generateCaptcha();
      return false;
    } catch (error) {
      get().addNotification('Failed to verify captcha', 'error');
      return false;
    }
  },

  generateCaptcha: async () => {
    const { serverUrl } = get();
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/captcha`, {
        headers: { 'Accept': 'application/json' },
      });
      
      const data = await response.json();
      
      if (data.enabled && data.id && data.question) {
        set({ 
          captchaId: data.id, 
          captchaQuestion: data.question,
          captchaAnswer: '', // Server knows the answer
        });
      }
    } catch (error) {
      // Fallback to local captcha generation if server fails
      const a = Math.floor(Math.random() * 20) + 1;
      const b = Math.floor(Math.random() * 20) + 1;
      const ops = [
        { q: `${a} + ${b}`, a: String(a + b) },
        { q: `${a + b} - ${b}`, a: String(a) },
        { q: `${a} × ${b <= 10 ? b : Math.floor(b/2)}`, a: String(a * (b <= 10 ? b : Math.floor(b/2))) },
      ];
      const op = ops[Math.floor(Math.random() * ops.length)];
      set({ captchaId: '', captchaQuestion: op.q, captchaAnswer: op.a });
    }
  },

  fetchUsers: async () => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users`, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
      });
      
      if (response.ok) {
        const usersData = await response.json();
        // Map server response format to client format
        const mappedUsers = usersData.map((u: Record<string, unknown>) => ({
          id: u.id,
          username: u.username || 'Unknown',  // Ensure username always has a value
          email: u.email,
          role: u.role || 'user',
          avatar: u.avatar || undefined,  // Ensure avatar is undefined if not present
          displayName: u.display_name || u.displayName || (u.username || 'Unknown'),  // Fallback chain for display name
          publicKey: u.public_key || u.publicKey,
          online: !!u.online,
          lastSeen: u.last_seen || u.lastSeen,
          emailVerified: !!u.email_verified || !!u.emailVerified,
          createdAt: u.created_at || u.createdAt,
        }));
        set({ users: mappedUsers });
      }
    } catch (error) {
      console.error('Failed to fetch users:', error);
    }
  },

  fetchChats: async () => {
    const { serverUrl, authToken, e2eeKeyPair, chatKeys } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats`, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
      });
      
      if (response.ok) {
        const chatsData = await response.json();
        const existingChats = get().chats;
        
        const newChatKeys = { ...chatKeys };
        
        const mappedChats = chatsData.map((c: any) => {
          if (c.encryptedKey && e2eeKeyPair && !newChatKeys[c.id]) {
            // Background unwrapping of chat keys
            E2EE.unwrapKey(c.encryptedKey, e2eeKeyPair.privateKey).then(key => {
              if (key) {
                set(s => ({ chatKeys: { ...s.chatKeys, [c.id]: key } }));
                // Also persist for offline use
                E2EE.saveChatKey(c.id, key).catch(() => {});
              }
            });
          }
          // Preserve local unread count if higher (from WebSocket messages)
          const existingChat = existingChats.find(ec => ec.id === c.id);
          const serverUnread = (c.unreadCount as number) || 0;
          const localUnread = existingChat?.unreadCount || 0;
          
          const lastMsg = c.lastMessage as Record<string, unknown> | null;
          const existingLastMsg = existingChat?.lastMessage;
          
          // Use whichever lastMessage is newer
          let finalLastMessage = undefined;
          if (lastMsg) {
            const serverTimestamp = (lastMsg.created_at || lastMsg.timestamp || 0) as number;
            const localTimestamp = existingLastMsg?.timestamp || 0;
            
            if (localTimestamp > serverTimestamp && existingLastMsg) {
              finalLastMessage = existingLastMsg;
            } else {
              finalLastMessage = {
                ...lastMsg,
                chatId: lastMsg.chat_id || lastMsg.chatId,
                senderId: lastMsg.sender_id || lastMsg.senderId,
                timestamp: lastMsg.created_at || lastMsg.timestamp,
              };
            }
          } else if (existingLastMsg) {
            finalLastMessage = existingLastMsg;
          }
          
          return {
            id: c.id,
            type: c.type,
            name: c.name,
            description: c.description,
            participants: c.participants || [],
            admins: c.admins || [],
            channelAdmins: c.channelAdmins || [],
            isChannel: !!c.isChannel || !!c.is_channel,
            isChannelAdmin: !!c.isChannelAdmin,
            createdAt: c.created_at || c.createdAt || Date.now(),
            lastMessage: finalLastMessage,
            unreadCount: Math.max(serverUnread, localUnread),
          };
        });
        
        // Also include any local chats that aren't on the server yet
        const serverChatIds = new Set(mappedChats.map((c: Chat) => c.id));
        const localOnlyChats = existingChats.filter(c => !serverChatIds.has(c.id));
        
        set({ chats: [...mappedChats, ...localOnlyChats] });
      }
    } catch (error) {
      console.error('Failed to fetch chats:', error);
    }
  },

  fetchMessages: async (chatId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/messages`, {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
      });
      
      if (response.ok) {
        const chatMessages = await response.json();
        
        // Decrypt messages sequentially to ensure order and avoid blocking
        const mappedMessages: Message[] = [];
        const unknownSenderIds = new Set<string>();
        
        for (const m of chatMessages) {
          let content = m.content;
          // Decrypt if message is encrypted and E2EE is unlocked
          if (content && content.startsWith('e2ee:') && E2EE.isE2EEUnlocked()) {
            try {
              content = await E2EE.decryptMessage(content, chatId);
            } catch (e) {
              console.error('[Store] Failed to decrypt message:', e);
              content = '[Decryption failed]';
            }
          }
          
          const senderId = m.sender_id || m.senderId;
          mappedMessages.push({
            id: m.id,
            chatId: m.chat_id || m.chatId || chatId,
            senderId: senderId,
            content: content,
            type: m.type || 'text',
            fileName: m.file_name || m.fileName,
            fileSize: m.file_size || m.fileSize,
            fileUrl: m.file_url || m.fileUrl,
            poll: m.poll || null,
            encrypted: !!m.encrypted,
            edited: !!m.edited,
            timestamp: m.created_at || m.timestamp || Date.now(),
            readBy: m.readBy || [],
          });
          
          // Track senders that might not be in the users list
          const currentUsers = get().users;
          if (!currentUsers.find(u => u.id === senderId)) {
            unknownSenderIds.add(senderId);
          }
        }
        
        set(state => ({
          allMessages: {
            ...state.allMessages,
            [chatId]: mappedMessages,
          },
          messages: mappedMessages,
        }));
        
        // If there are unknown senders, fetch updated user list
        if (unknownSenderIds.size > 0) {
          get().fetchUsers();
        }
      }
    } catch (error) {
      console.error('Failed to fetch messages:', error);
    }
  },

  setActiveChat: (chatId) => {
    if (chatId) {
      // Load cached messages immediately for instant display
      const cached = get().allMessages[chatId] || [];
      set({ activeChat: chatId, showChatInfo: false, messages: cached });
      // Then fetch latest from server in background
      get().fetchMessages(chatId);
      get().markAsRead(chatId);
      // Ensure users are fetched so message senders are properly displayed
      get().fetchUsers();
    } else {
      set({ activeChat: chatId, showChatInfo: false, messages: [] });
    }
  },

  sendMessage: async (chatId, content, type = 'text', fileName, fileSize, fileUrl?: string) => {
    const { currentUser, serverUrl, authToken, users, chats } = get();
    if (!currentUser || !authToken) return;

    // Create local message for immediate display (unencrypted for UI)
    const localMessage: Message = {
      id: generateId(),
      chatId,
      senderId: currentUser.id,
      content: content, // Keep unencrypted for local display
      type,
      fileName,
      fileSize,
      fileUrl: fileUrl || (type !== 'text' ? content : undefined),
      encrypted: false,
      timestamp: Date.now(),
      edited: false,
      readBy: [currentUser.id],
    };

    // Optimistically add message to both stores
    set(state => {
      const chatMessages = state.allMessages[chatId] || [];
      return {
        messages: [...state.messages, localMessage],
        allMessages: {
          ...state.allMessages,
          [chatId]: [...chatMessages, localMessage],
        },
        chats: state.chats.map(c =>
          c.id === chatId ? { ...c, lastMessage: localMessage, unreadCount: 0 } : c
        ),
      };
    });

    let payloadContent = content;
    let isEncrypted = false;
    
    // Determine if we should E2EE this message
    const chat = chats.find(c => c.id === chatId);
    if (chat && type === 'text' && E2EE.isE2EEUnlocked()) {
      const hasBot = chat.participants.some(uid => {
        const u = users.find(user => user.id === uid);
        return u?.isBot;
      });
      
      // Encrypt if no bots in the chat
      if (!hasBot) {
        try {
          // Use the new simplified API - just pass chatId
          payloadContent = await E2EE.encryptMessage(content, chatId);
          isEncrypted = payloadContent.startsWith('e2ee:');
        } catch (e) {
          console.error('[Store] Encryption failed, will send unencrypted:', e);
          // Fall through to send unencrypted
        }
      }
    }

    // Send to server
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/messages`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ 
          content: payloadContent, 
          type, 
          fileName, 
          fileSize, 
          fileUrl,
          encrypted: isEncrypted,
        }),
      });
      
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        get().addNotification(errorData.error || 'Failed to send message', 'error');
        set(state => ({
          messages: state.messages.filter(m => m.id !== localMessage.id),
          allMessages: {
            ...state.allMessages,
            [chatId]: (state.allMessages[chatId] || []).filter(m => m.id !== localMessage.id),
          },
        }));
      }
    } catch (error) {
      console.error('[Store] Failed to send message:', error);
      get().addNotification('Failed to send message', 'error');
      set(state => ({
        messages: state.messages.filter(m => m.id !== localMessage.id),
        allMessages: {
          ...state.allMessages,
          [chatId]: (state.allMessages[chatId] || []).filter(m => m.id !== localMessage.id),
        },
      }));
    }
  },

  editMessage: async (messageId, newContent) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    set(state => ({
      messages: state.messages.map(m =>
        m.id === messageId ? { ...m, content: newContent, edited: true } : m
      ),
      allMessages: Object.fromEntries(
        Object.entries(state.allMessages).map(([cid, msgs]) => [
          cid,
          msgs.map(m => m.id === messageId ? { ...m, content: newContent, edited: true } : m)
        ])
      ),
    }));

    try {
      await fetch(`${serverUrl.replace(/\/$/, '')}/api/messages/${messageId}`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ content: newContent }),
      });
    } catch (error) {
      console.error('Failed to edit message:', error);
    }
  },

  deleteMessage: async (messageId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    set(state => ({
      messages: state.messages.filter(m => m.id !== messageId),
      allMessages: Object.fromEntries(
        Object.entries(state.allMessages).map(([cid, msgs]) => [
          cid,
          msgs.filter(m => m.id !== messageId)
        ])
      ),
    }));

    try {
      await fetch(`${serverUrl.replace(/\/$/, '')}/api/messages/${messageId}`, {
        method: 'DELETE',
        headers: { 
          'Authorization': `Bearer ${authToken}`,
        },
      });
    } catch (error) {
      console.error('Failed to delete message:', error);
    }
  },

  createDirectChat: async (userId) => {
    const { currentUser, chats, serverUrl, authToken, users, e2eeKeyPair } = get();
    if (!currentUser || !authToken) return '';

    // Check if chat already exists locally
    const existing = chats.find(c =>
      c.type === 'direct' &&
      c.participants.includes(currentUser.id) &&
      c.participants.includes(userId)
    );
    if (existing) {
      set({ activeChat: existing.id, showNewChat: false });
      return existing.id;
    }

    try {
      const targetUser = users.find(u => u.id === userId);
      const isBot = targetUser?.isBot;
      let encryptedKeys: Record<string, string> | undefined = undefined;
      
      if (!isBot && e2eeKeyPair && targetUser?.publicKey) {
        const chatKey = await E2EE.generateChatKey();
        const wrappedTarget = await E2EE.wrapKey(chatKey, targetUser.publicKey);
        const wrappedSelf = await E2EE.wrapKey(chatKey, e2eeKeyPair.publicKey);
        
        if (wrappedTarget && wrappedSelf) {
          encryptedKeys = {
            [userId]: wrappedTarget,
            [currentUser.id]: wrappedSelf
          };
          // We don't save to state.chatKeys yet, we wait for server to return chatId
        }
      }

      // Create chat on server first and get the real chat ID
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/direct`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ userId, encryptedKeys }),
      });
      
      if (!response.ok) {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to create chat', 'error');
        return '';
      }
      
      const data = await response.json();
      const chatId = data.chatId;
      
      let newChatKeys = get().chatKeys;
      if (encryptedKeys) {
        // Re-generate chat key to save it instantly? Actually, we lost the `chatKey` reference
        // because we didn't store it. Let's just let fetchChats or fetchMessages trigger the unwrap,
        // or we can unwrap our own just-wrapped key.
        // Actually it's easier to just unwrap it now.
        try {
          const unwrapped = await E2EE.unwrapKey(encryptedKeys[currentUser.id], e2eeKeyPair!.privateKey);
          if (unwrapped) {
            newChatKeys = { ...newChatKeys, [chatId]: unwrapped };
            E2EE.saveChatKey(chatId, unwrapped).catch(() => {});
          }
        } catch(e) {}
      }

      const newChat: Chat = {
        id: chatId,
        type: 'direct',
        participants: [currentUser.id, userId],
        createdAt: Date.now(),
        unreadCount: 0,
      };
      
      set(state => ({
        chats: [newChat, ...state.chats],
        activeChat: chatId,
        showNewChat: false,
        chatKeys: newChatKeys,
      }));

      return chatId;
    } catch (error) {
      console.error('Failed to create chat:', error);
      get().addNotification('Failed to create chat', 'error');
      return '';
    }
  },

  createGroup: async (name, participants, description, isChannel = false) => {
    const { currentUser, serverUrl, authToken, users, e2eeKeyPair } = get();
    if (!currentUser || !authToken) return;

    try {
      let encryptedKeys: Record<string, string> | undefined = undefined;
      
      const allMembers = [currentUser.id, ...participants];
      const hasBot = allMembers.some(uid => users.find(u => u.id === uid)?.isBot);
      
      if (!hasBot && e2eeKeyPair) {
        const chatKey = await E2EE.generateChatKey();
        encryptedKeys = {};
        
        for (const uid of allMembers) {
          const user = users.find(u => u.id === uid) || (uid === currentUser.id ? currentUser : null);
          if (user?.publicKey) {
             const wrapped = await E2EE.wrapKey(chatKey, user.publicKey);
             if (wrapped) encryptedKeys[uid] = wrapped;
          }
        }
      }

      // Create group/channel on server first and get the real chat ID
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/group`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ name, participants, description, isChannel, encryptedKeys }),
      });
      
      if (!response.ok) {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to create group', 'error');
        return;
      }
      
      const data = await response.json();
      const chatId = data.chatId;

      let newChatKeys = get().chatKeys;
      if (encryptedKeys && e2eeKeyPair) {
        try {
          const unwrapped = await E2EE.unwrapKey(encryptedKeys[currentUser.id], e2eeKeyPair.privateKey);
          if (unwrapped) {
            newChatKeys = { ...newChatKeys, [chatId]: unwrapped };
            E2EE.saveChatKey(chatId, unwrapped).catch(() => {});
          }
        } catch(e) {}
      }

      const systemMsg: Message = {
        id: generateId(),
        chatId,
        senderId: 'system',
        content: isChannel 
          ? `${currentUser.username} created the channel "${name}"`
          : `${currentUser.username} created the group "${name}"`,
        type: 'system',
        encrypted: false,
        timestamp: Date.now(),
        edited: false,
        readBy: [],
      };

      const newChat: Chat = {
        id: chatId,
        type: isChannel ? 'channel' : 'group',
        name,
        participants: [currentUser.id, ...participants],
        admins: [currentUser.id],
        channelAdmins: isChannel ? [currentUser.id] : [],
        isChannel,
        isChannelAdmin: isChannel,
        createdAt: Date.now(),
        description,
        lastMessage: systemMsg,
        unreadCount: 0,
      };
      
      set(state => ({
        chats: [newChat, ...state.chats],
        messages: [...state.messages, systemMsg],
        activeChat: chatId,
        showNewGroup: false,
        chatKeys: newChatKeys,
      }));

      get().addNotification(`${isChannel ? 'Channel' : 'Group'} "${name}" created!`, 'success');
    } catch (error) {
      console.error('Failed to create group:', error);
      get().addNotification('Failed to create group', 'error');
    }
  },

  makeChannelAdmin: async (chatId, userId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/admins`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ userId }),
      });
      
      if (response.ok) {
        set(state => ({
          chats: state.chats.map(c => 
            c.id === chatId 
              ? { ...c, channelAdmins: [...(c.channelAdmins || []), userId] }
              : c
          ),
        }));
        get().addNotification('User is now a channel admin', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to add admin', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to add admin', 'error');
    }
  },

  removeChannelAdmin: async (chatId, userId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/admins/${userId}`, {
        method: 'DELETE',
        headers: { 
          'Authorization': `Bearer ${authToken}`,
        },
      });
      
      if (response.ok) {
        set(state => ({
          chats: state.chats.map(c => 
            c.id === chatId 
              ? { ...c, channelAdmins: (c.channelAdmins || []).filter(a => a !== userId) }
              : c
          ),
        }));
        get().addNotification('Admin removed', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to remove admin', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to remove admin', 'error');
    }
  },

  updateChatSettings: async (chatId, settings) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/settings`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify(settings),
      });
      
      if (response.ok) {
        set(state => ({
          chats: state.chats.map(c => 
            c.id === chatId 
              ? { 
                  ...c, 
                  name: settings.name !== undefined ? settings.name : c.name,
                  avatar: settings.avatar !== undefined ? settings.avatar : c.avatar,
                  description: settings.description !== undefined ? settings.description : c.description,
                }
              : c
          ),
        }));
        get().addNotification('Settings updated', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to update settings', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to update settings', 'error');
    }
  },

  searchUsers: async (query) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return [];
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users?search=${encodeURIComponent(query)}`, {
        headers: { 
          'Authorization': `Bearer ${authToken}`,
        },
      });
      
      if (response.ok) {
        const usersData = await response.json();
        const mappedUsers: User[] = usersData.map((u: Record<string, unknown>) => ({
          id: u.id as string,
          username: u.username as string,
          email: u.email as string,
          role: (u.role || 'user') as User['role'],
          avatar: u.avatar as string | undefined,
          displayName: (u.display_name || u.displayName) as string | undefined,
          online: !!u.online,
          lastSeen: (u.last_seen || u.lastSeen) as number | undefined,
          emailVerified: !!u.email_verified || !!u.emailVerified,
          createdAt: (u.created_at || u.createdAt) as number,
        }));
        set({ users: mappedUsers });
        return mappedUsers;
      }
    } catch (error) {
      console.error('Failed to search users:', error);
    }
    return [];
  },

  leaveGroup: (chatId) => {
    const { currentUser, serverUrl, authToken } = get();
    if (!currentUser || !authToken) return;
    
    set(state => ({
      chats: state.chats.map(c =>
        c.id === chatId ? { ...c, participants: c.participants.filter(p => p !== currentUser.id) } : c
      ),
      activeChat: state.activeChat === chatId ? null : state.activeChat,
    }));

    fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/leave`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
    }).catch(console.error);

    get().addNotification('Left the group', 'info');
  },

  addToGroup: async (chatId, userId) => {
    const { serverUrl, authToken, users, chatKeys } = get();
    if (!authToken) return;
    
    set(state => ({
      chats: state.chats.map(c =>
        c.id === chatId ? { ...c, participants: [...c.participants, userId] } : c
      ),
    }));

    let encryptedKey = undefined;
    const targetUser = users.find(u => u.id === userId);
    const chatKey = chatKeys[chatId];
    
    if (targetUser && targetUser.publicKey && chatKey && !targetUser.isBot) {
      try {
        const wrapped = await E2EE.wrapKey(chatKey, targetUser.publicKey);
        if (wrapped) encryptedKey = wrapped;
      } catch(e) { console.error("Failed to wrap key for new member", e); }
    }

    fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/members`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}`,
      },
      body: JSON.stringify({ userId, encryptedKey }),
    }).catch(console.error);
  },

  removeFromGroup: (chatId, userId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    set(state => ({
      chats: state.chats.map(c =>
        c.id === chatId ? {
          ...c,
          participants: c.participants.filter(p => p !== userId),
          admins: c.admins?.filter(a => a !== userId),
        } : c
      ),
    }));

    fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/members/${userId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${authToken}` },
    }).catch(console.error);
  },

  updateUserRole: async (userId, role) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/${userId}/role`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify({ role }),
      });
      
      if (response.ok) {
        set(state => ({
          users: state.users.map(u => u.id === userId ? { ...u, role } : u),
        }));
        get().addNotification(`User role updated to ${role}`, 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to update role', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to update role', 'error');
    }
  },

  banUser: async (userId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/${userId}/ban`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      
      if (response.ok) {
        set(state => ({
          users: state.users.map(u => u.id === userId ? { ...u, role: 'banned' as UserRole, online: false } : u),
        }));
        get().addNotification('User banned', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to ban user', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to ban user', 'error');
    }
  },

  unbanUser: async (userId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/${userId}/unban`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      
      if (response.ok) {
        set(state => ({
          users: state.users.map(u => u.id === userId ? { ...u, role: 'user' as UserRole } : u),
        }));
        get().addNotification('User unbanned', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to unban user', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to unban user', 'error');
    }
  },

  deleteUser: async (userId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/${userId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      
      if (response.ok) {
        set(state => ({
          users: state.users.filter(u => u.id !== userId),
          chats: state.chats.filter(c => !(c.type === 'direct' && c.participants.includes(userId))),
        }));
        get().addNotification('User deleted', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to delete user', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to delete user', 'error');
    }
  },

  updateServerConfig: async (config) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/admin/config`, {
        method: 'PUT',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${authToken}`,
        },
        body: JSON.stringify(config),
      });
      
      if (response.ok) {
        set(state => ({
          serverConfig: { ...state.serverConfig, ...config },
        }));
        get().addNotification('Server configuration updated', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to update config', 'error');
      }
    } catch (error) {
      get().addNotification('Failed to update config', 'error');
    }
  },

  startCall: (chatId, type) => {
    const { currentUser, chats, users } = get();
    if (!currentUser) return;
    const chat = chats.find(c => c.id === chatId);
    if (!chat) return;

    const participantNames = chat.participants
      .filter(p => p !== currentUser.id)
      .map(p => users.find(u => u.id === p)?.username || users.find(u => u.id === p)?.displayName || 'Unknown');

    get().beginCall(chatId, type, chat.participants);
    get().addNotification(`${type === 'video' ? 'Video' : 'Voice'} call with ${participantNames.join(', ')}`, 'info');
  },

  endCall: () => {
    set({
      callState: { active: false, chatId: null, type: 'voice', participants: [], startTime: null },
    });
    get().addNotification('Call ended', 'info');
  },

  toggleSidebar: () => set(state => ({ showSidebar: !state.showSidebar })),
  setShowUserProfile: (show) => set({ showUserProfile: show }),
  setShowChatInfo: (show) => set({ showChatInfo: show }),
  setShowNewChat: (show) => set({ showNewChat: show }),
  setShowNewGroup: (show) => set({ showNewGroup: show }),
  setSearchQuery: (query) => set({ searchQuery: query }),

  addNotification: (text, type) => {
    const id = generateId();
    set(state => ({
      notifications: [...state.notifications, { id, text, type }],
    }));
    setTimeout(() => {
      set(state => ({
        notifications: state.notifications.filter(n => n.id !== id),
      }));
    }, 4000);
  },

  removeNotification: (id) => {
    set(state => ({
      notifications: state.notifications.filter(n => n.id !== id),
    }));
  },

  markAsRead: (chatId) => {
    const { currentUser, serverUrl, authToken } = get();
    if (!currentUser || !authToken) return;
    
    set(state => ({
      chats: state.chats.map(c => c.id === chatId ? { ...c, unreadCount: 0 } : c),
      messages: state.messages.map(m =>
        m.chatId === chatId && !m.readBy.includes(currentUser.id)
          ? { ...m, readBy: [...m.readBy, currentUser.id] }
          : m
      ),
    }));

    fetch(`${serverUrl.replace(/\/$/, '')}/api/chats/${chatId}/read`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` },
    }).catch(console.error);
  },

  encryptMessage: (text) => text, // Server handles encryption
  decryptMessage: async (text, chatId) => {
    // Decryption is handled when messages are fetched
    // This is kept for backward compatibility
    return text;
  },

  setAppearance: (settings) => {
    set(state => {
      const newAppearance = { ...state.appearance, ...settings };
      saveAppearance(newAppearance);
      return { appearance: newAppearance };
    });
  },

  resetAppearance: () => {
    saveAppearance(defaultAppearance);
    set({ appearance: defaultAppearance });
  },
  
  // Bots implementation
  fetchBots: async () => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/me/bots`, {
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        const rawBots = await response.json();
        const mappedBots = rawBots.map((b: any) => ({
          id: b.id,
          name: b.displayName || b.username,
          username: b.username,
          code: b.botScript || b.script || '',
          isActive: true, // Auto-active in the new system
          createdAt: b.createdAt || Date.now()
        }));
        set({ bots: mappedBots });
      }
    } catch (e) {
      console.error('Failed to fetch bots:', e);
    }
  },
  
  createBot: async (username, displayName, script) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/me/bots`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ username, displayName, script })
      });
      if (response.ok) {
        get().fetchBots();
        get().addNotification('Bot created successfully', 'success');
      } else {
        const data = await response.json();
        get().addNotification(data.error || 'Failed to create bot', 'error');
      }
    } catch (e) {
      get().addNotification('Failed to create bot', 'error');
    }
  },
  
  updateBot: async (id, displayName, script) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/me/bots/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ displayName, script })
      });
      if (response.ok) {
        get().fetchBots();
        get().addNotification('Bot updated successfully', 'success');
      }
    } catch (e) {}
  },
  
  deleteBot: async (id) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/me/bots/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${authToken}` },
      });
      if (response.ok) {
        get().fetchBots();
        get().addNotification('Bot deleted', 'success');
      }
    } catch (e) {}
  },
  
  toggleBot: async (id, chatId) => {
    const { serverUrl, authToken } = get();
    if (!authToken) return false;
    try {
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/bots/${id}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${authToken}` },
        body: JSON.stringify({ chatId })
      });
      if (response.ok) {
        const data = await response.json();
        get().fetchBots();
        return data.isActive;
      }
      return false;
    } catch (e) {
      return false;
    }
  },

  // Server Shortcuts
  serverShortcuts: loadShortcuts(),

  addServerShortcut: (name, url) => {
    const newShortcut: ServerShortcut = {
      id: generateId(),
      name,
      url,
      createdAt: Date.now(),
    };
    set(state => {
      const updated = [...state.serverShortcuts, newShortcut];
      saveShortcuts(updated.filter(s => s.id !== 'official-4messenger')); // Don't save official to localStorage
      return { serverShortcuts: updated };
    });
  },

  removeServerShortcut: (id) => {
    // Prevent removing the official shortcut
    if (id === 'official-4messenger') {
      return;
    }
    set(state => {
      const updated = state.serverShortcuts.filter(s => s.id !== id);
      saveShortcuts(updated.filter(s => s.id !== 'official-4messenger')); // Don't save official to localStorage
      return { serverShortcuts: updated };
    });
  },

  // Language
  language: loadLanguage(),
  
  setLanguage: (lang) => {
    saveLanguage(lang);
    set({ language: lang });
  },
  
  t: (key) => {
    return getTranslation(get().language, key);
  },
  
  translate: (key) => {
    return getTranslation(get().language, key);
  },
  
  // Privacy Policy
  privacyPolicyAccepted: false,
  showPrivacyPolicy: false,
  
  checkPrivacyPolicy: () => {
    return hasAcceptedPrivacyPolicy();
  },
  
  acceptPrivacyPolicy: () => {
    savePrivacyPolicyAcceptance();
    set({ privacyPolicyAccepted: true, showPrivacyPolicy: false });
  },
  
  setShowPrivacyPolicy: (show) => set({ showPrivacyPolicy: show }),

  // Initialize official server shortcut
  initOfficialShortcut: async () => {
    const url = await loadOfficialServerUrl();
    if (url) {
      const hasOfficial = get().serverShortcuts.some(s => s.id === 'official-4messenger');
      const officialShortcut: ServerShortcut = {
        id: 'official-4messenger',
        name: 'Official 4 Messenger Server',
        url,
        createdAt: 0,
      };
      
      if (!hasOfficial) {
        set(state => ({
          serverShortcuts: [officialShortcut, ...state.serverShortcuts],
        }));
      } else {
        set(state => ({
          serverShortcuts: state.serverShortcuts.map(s => 
            s.id === 'official-4messenger' ? officialShortcut : s
          ),
        }));
      }
    }
  },

  restoreSession: async () => {
    const session = loadSession();
    if (!session) return false;
    
    const { serverUrl, authToken, user } = session;

    // We cannot unlock password-protected E2EE keys without the user's password.
    // Keep the in-memory keyPair null here; chats can still load and show placeholder for encrypted messages.
    set({ e2eeKeyPair: null });
    
    
    // Set loading state
    set({ connecting: true, serverUrl });
    
    try {
      // Verify token is still valid by fetching user info
      const response = await fetch(`${serverUrl.replace(/\/$/, '')}/api/users/me`, {
        headers: { 
          'Authorization': `Bearer ${authToken}`,
          'Accept': 'application/json',
        },
      });
      
      if (!response.ok) {
        clearSession();
        set({ connecting: false });
        return false;
      }
      
      const userData = await response.json();
      
      // Get server info
      const serverInfoResponse = await fetch(`${serverUrl.replace(/\/$/, '')}/api/server-info`, {
        headers: { 'Accept': 'application/json' },
      });
      
      let serverConfig = get().serverConfig;
      if (serverInfoResponse.ok) {
        const serverInfo = await serverInfoResponse.json();
        serverConfig = {
          emailVerification: serverInfo.emailVerification || false,
          serverPassword: serverInfo.requiresPassword ? 'required' : '',
          captchaEnabled: serverInfo.captchaEnabled || false,
          maxFileSize: serverInfo.maxFileSize || 10485760,
          allowRegistration: serverInfo.registrationEnabled ?? true,
          serverName: serverInfo.name || '4 Messenger Server',
          encryptionEnabled: serverInfo.encryptionEnabled ?? true,
          maxBotMemoryMB: serverInfo.maxBotMemoryMB || 50,
        };
      }
      
      // Restore session
      set({
        connected: true,
        connecting: false,
        serverUrl,
        authToken,
        currentUser: {
          ...user,
          ...userData,
          displayName: userData.display_name || userData.displayName || user.displayName,
        },
        serverConfig,
        screen: 'chat',
      });
      
      // Fetch initial data
      await Promise.all([
        get().fetchUsers(),
        get().fetchChats(),
        get().fetchBots(),
      ]);
      
      // Setup WebSocket connection
      const wsUrl = serverUrl.replace(/^http/, 'ws').replace(/\/$/, '');
      const ws = new WebSocket(`${wsUrl}/ws?token=${authToken}`);
      
      ws.onopen = () => {
        console.log('[WS] Connected (session restored)');
      };
      
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          
          switch (msg.type) {
            case 'announcement':
              get().addNotification(`📢 ${msg.message}`, 'info');
              break;
            case 'message':
            case 'new_message': {
              const handleIncomingMessage = async () => {
                const msgData = msg.data || msg.message;
                if (!msgData) return;
                
                const senderId = msgData.sender_id || msgData.senderId;
                const chatId = msgData.chat_id || msgData.chatId;
                
                let content = msgData.content;
                if (content && content.startsWith('e2ee:')) {
                  const state = get();
                  if (state.chatKeys[chatId]) {
                    content = await E2EE.decryptMessage(content, state.chatKeys[chatId]);
                  } else {
                    content = '[Encrypted Message]';
                  }
                }
                
                const mappedMsg: Message = {
                  id: msgData.id,
                  chatId,
                  senderId,
                  content: content,
                  type: msgData.type || 'text',
                  fileName: msgData.file_name || msgData.fileName,
                  fileSize: msgData.file_size || msgData.fileSize,
                  fileUrl: msgData.file_url || msgData.fileUrl,
                  poll: msgData.poll || null,
                  timestamp: msgData.created_at || msgData.timestamp || Date.now(),
                  encrypted: !!msgData.encrypted,
                  edited: !!msgData.edited,
                  readBy: msgData.readBy || [],
                };
                
                const state = get();
                const isOwnMessage = senderId === state.currentUser?.id;
                const isActiveChat = state.activeChat === chatId;
                
                const existsInMessages = state.messages.some(m => m.id === mappedMsg.id);
                const existsInAll = (state.allMessages[chatId] || []).some(m => m.id === mappedMsg.id);
                
                if (!existsInMessages && !existsInAll && !isOwnMessage) {
                  set(state2 => {
                    const chatMessages = state2.allMessages[chatId] || [];
                    return {
                      allMessages: {
                        ...state2.allMessages,
                        [chatId]: [...chatMessages, mappedMsg],
                      },
                      messages: isActiveChat 
                        ? [...state2.messages, mappedMsg]
                        : state2.messages,
                      chats: state2.chats.map(c => 
                        c.id === chatId 
                          ? { 
                              ...c, 
                              lastMessage: mappedMsg, 
                              unreadCount: isActiveChat ? c.unreadCount : c.unreadCount + 1 
                            } 
                          : c
                      ),
                    };
                  });
                }
              };
              handleIncomingMessage();
              break;
            }
            case 'message_edited': {
              const editData = msg.data;
              if (editData) {
                set(state => ({
                  messages: state.messages.map(m => 
                    m.id === editData.id ? { ...m, content: editData.content, edited: true } : m
                  ),
                  allMessages: Object.fromEntries(
                    Object.entries(state.allMessages).map(([cid, msgs]) => [
                      cid,
                      msgs.map(m => m.id === editData.id ? { ...m, content: editData.content, edited: true } : m)
                    ])
                  ),
                }));
              }
              break;
            }
            case 'message_deleted': {
              const deleteData = msg.data;
              if (deleteData) {
                set(state => ({
                  messages: state.messages.filter(m => m.id !== deleteData.id),
                  allMessages: Object.fromEntries(
                    Object.entries(state.allMessages).map(([cid, msgs]) => [
                      cid,
                      msgs.filter(m => m.id !== deleteData.id)
                    ])
                  ),
                }));
              }
              break;
            }
            case 'user_online':
              set(state => ({
                users: state.users.map(u => u.id === (msg.userId || msg.user_id) ? { ...u, online: true } : u),
              }));
              break;
            case 'user_offline':
              set(state => ({
                users: state.users.map(u => u.id === (msg.userId || msg.user_id) ? { ...u, online: false, lastSeen: Date.now() } : u),
              }));
              break;
            case 'chat_updated':
              get().fetchChats();
              break;
            case 'kicked':
              get().addNotification('You have been kicked from the server', 'error');
              get().logout();
              break;
            case 'maintenance':
              if (msg.enabled) {
                get().addNotification(`🔧 Server is entering maintenance mode: ${msg.message || 'Please try again later'}`, 'error');
                get().logout();
              } else {
                get().addNotification('✅ Server maintenance is complete. You can now reconnect.', 'success');
              }
              break;
          }
        } catch (error) {
          console.error('[WS] Error parsing message:', error);
        }
      };
      
      ws.onclose = () => {
        console.log('[WS] Disconnected');
        set({ websocket: null });
      };
      
      ws.onerror = (error) => {
        console.error('[WS] Error:', error);
      };
      
      set({ websocket: ws });
      
      // Periodically refresh chat list
      const chatRefreshInterval = setInterval(() => {
        if (get().authToken && get().websocket) {
          get().fetchChats();
        } else {
          clearInterval(chatRefreshInterval);
        }
      }, 15000);
      
      get().addNotification(`Welcome back, ${userData.display_name || userData.username || user.username}!`, 'success');
      return true;
      
    } catch (error) {
      console.error('Failed to restore session:', error);
      clearSession();
      set({ connecting: false });
      return false;
    }
  },
}));
