export type UserRole = 'admin' | 'moderator' | 'user' | 'banned' | 'bot';

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  avatar?: string;
  displayName?: string;
  publicKey?: string;
  online: boolean;
  lastSeen: number;
  emailVerified: boolean;
  createdAt: number;
  isBot?: boolean;
}

export interface Bot {
  id: string;
  username: string;
  displayName: string;
  script: string;
}

export interface BotConfig {
  id: string;
  username: string;
  displayName: string;
  script: string;
}

export interface PollOption {
  text: string;
  votes: string[];
}

export interface Poll {
  id: string;
  question: string;
  options: PollOption[];
  multipleChoice: boolean;
  anonymous: boolean;
  creatorId: string;
  closed: boolean;
}

export interface Message {
  id: string;
  chatId: string;
  senderId: string;
  content: string;
  type: 'text' | 'file' | 'image' | 'voice' | 'poll' | 'sticker' | 'system';
  fileName?: string;
  fileSize?: number;
  fileUrl?: string;
  poll?: Poll;
  encrypted: boolean;
  timestamp: number;
  edited: boolean;
  readBy: string[];
}

export interface Chat {
  id: string;
  type: 'direct' | 'group' | 'channel';
  name?: string;
  participants: string[];
  admins?: string[];
  channelAdmins?: string[];
  isChannel?: boolean;
  isChannelAdmin?: boolean;
  lastMessage?: Message;
  createdAt: number;
  avatar?: string;
  description?: string;
  unreadCount: number;
}

export interface ServerConfig {
  emailVerification: boolean;
  serverPassword: string;
  captchaEnabled: boolean;
  maxFileSize: number;
  allowRegistration: boolean;
  serverName: string;
  encryptionEnabled: boolean;
  maxBotMemoryMB?: number;
}

export interface CallState {
  active: boolean;
  chatId: string | null;
  type: 'voice' | 'video';
  participants: string[];
  startTime: number | null;
}

export type AppScreen = 'connect' | 'auth' | 'login' | 'register' | 'chat' | 'admin';
