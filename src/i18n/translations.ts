export type Language = 'en' | 'ru';

export const translations = {
  en: {
    // General
    appName: '4 Messenger',
    loading: 'Loading...',
    save: 'Save',
    cancel: 'Cancel',
    delete: 'Delete',
    edit: 'Edit',
    close: 'Close',
    back: 'Back',
    next: 'Next',
    confirm: 'Confirm',
    search: 'Search',
    send: 'Send',
    retry: 'Retry',
    yes: 'Yes',
    no: 'No',
    or: 'or',
    
    // Connect Screen
    connectTitle: 'Welcome to',
    connectSubtitle: 'Secure, Private, Self-hosted Messaging',
    serverUrl: 'Server URL',
    serverUrlPlaceholder: 'https://your-server.com',
    connect: 'Connect',
    connecting: 'Connecting...',
    savedServers: 'Saved Servers',
    addServer: 'Add',
    saveServer: 'Save Server',
    serverName: 'Server Name',
    serverNamePlaceholder: 'My Server',
    noSavedServers: 'No saved servers',
    connectionError: 'Connection Error',
    features: {
      encrypted: 'End-to-End Encrypted',
      groups: 'Groups & Channels',
      selfHosted: 'Self-Hosted'
    },
    
    // Connect Screen additional
    'connect.tagline': 'Secure. Private. Connected.',
    'connect.serverUrl': 'Server URL',
    'connect.connectionFailed': 'Connection Failed',
    'connect.checkServer': 'Make sure the server is running and the URL is correct.',
    'connect.connecting': 'Connecting...',
    'connect.connect': 'Connect',
    'connect.encrypted': 'Encrypted',
    'connect.groups': 'Groups',
    'connect.selfHosted': 'Self-hosted',
    'connect.startChatting': 'Connect to your 4 Messenger server to start chatting',
    'connect.savedServers': 'Saved Servers',
    'connect.add': 'Add',
    'connect.saveServer': 'Save Server',
    'connect.serverName': 'Server Name',
    
    // Common
    'common.cancel': 'Cancel',
    'common.save': 'Save',
    
    // Auth Screen
    serverPassword: 'Server Password',
    serverPasswordPlaceholder: 'Enter server password',
    verifyPassword: 'Verify Password',
    verifying: 'Verifying...',
    invalidPassword: 'Invalid password',
    captchaTitle: 'Security Check',
    captchaSubtitle: 'Complete the verification to continue',
    captchaLoading: 'Loading security check...',
    captchaError: 'Verification failed',
    captchaExpired: 'Verification expired, please try again',
    
    // Login Screen
    signIn: 'Sign In',
    signInSubtitle: 'Welcome back',
    username: 'Username',
    usernamePlaceholder: 'Enter username',
    password: 'Password',
    passwordPlaceholder: 'Enter password',
    signingIn: 'Signing in...',
    forgotPassword: 'Forgot password?',
    noAccount: "Don't have an account?",
    createAccount: 'Create Account',
    backToServer: 'Back to server selection',
    
    // Register Screen
    register: 'Create Account',
    registerSubtitle: 'Join the conversation',
    email: 'Email',
    emailPlaceholder: 'Enter email',
    confirmPassword: 'Confirm Password',
    confirmPasswordPlaceholder: 'Confirm password',
    creating: 'Creating account...',
    hasAccount: 'Already have an account?',
    
    // Forgot Password
    forgotPasswordTitle: 'Reset Password',
    enterEmail: 'Enter your email address',
    sendResetCode: 'Send Reset Code',
    sending: 'Sending...',
    resetCodeSent: 'Reset code sent to your email',
    enterCode: 'Enter the 6-digit code',
    codeExpires: 'Code expires in 15 minutes',
    verifyCode: 'Verify Code',
    newPassword: 'New Password',
    newPasswordPlaceholder: 'Enter new password',
    resetPassword: 'Reset Password',
    resetting: 'Resetting...',
    passwordReset: 'Password reset successfully!',
    backToSignIn: 'Back to Sign In',
    
    // Chat Screen
    chats: 'Chats',
    newChat: 'New Chat',
    newGroup: 'New Group',
    searchChats: 'Search chats...',
    noChats: 'No chats yet',
    startNewChat: 'Start a new conversation',
    typeMessage: 'Type a message...',
    online: 'Online',
    offline: 'Offline',
    typing: 'typing...',
    you: 'You',
    today: 'Today',
    yesterday: 'Yesterday',
    
    // New Chat Modal
    newChatTitle: 'New Chat',
    searchUsers: 'Search users...',
    searchUsersPlaceholder: 'Enter exact username',
    searchUsersPlaceholderAdmin: 'Search users...',
    searchUsersHint: 'To find a user, enter their exact username',
    searchUsersHintAdmin: 'Search by username, email, or display name',
    noUsersFound: 'No users found',
    enterUsername: 'Enter a username and click Search',
    startChat: 'Start Chat',
    
    // New Group Modal
    newGroupTitle: 'New Group',
    newChannelTitle: 'New Channel',
    groupName: 'Group Name',
    groupNamePlaceholder: 'Enter group name',
    channelNamePlaceholder: 'Enter channel name',
    selectMembers: 'Select Members',
    createGroup: 'Create Group',
    createChannel: 'Create Channel',
    channelDescription: 'Channels are for broadcasting. Only admins can post.',
    channel: 'Channel',
    noUsersAvailable: 'No users available to add',
    
    // Chat Info
    chatInfo: 'Chat Info',
    members: 'Members',
    member: 'member',
    membersCount: '{count} members',
    admin: 'Admin',
    moderator: 'Moderator',
    channelAdmin: 'Channel Admin',
    leaveGroup: 'Leave Group',
    leaveChannel: 'Leave Channel',
    deleteChat: 'Delete Chat',
    addMember: 'Add Member',
    removeMember: 'Remove Member',
    makeAdmin: 'Make Admin',
    removeAdmin: 'Remove Admin',
    description: 'Description',
    noDescription: 'No description',
    
    // Messages
    editMessage: 'Edit',
    deleteMessage: 'Delete',
    copyMessage: 'Copy',
    replyMessage: 'Reply',
    messageDeleted: 'Message deleted',
    messageEdited: 'edited',
    
    // Files
    attachFile: 'Attach file',
    sendFile: 'Send file',
    download: 'Download',
    uploading: 'Uploading...',
    fileTooLarge: 'File is too large',
    fileTypeNotAllowed: 'File type not allowed',
    
    // Voice Messages
    voiceMessage: 'Voice message',
    recording: 'Recording...',
    holdToRecord: 'Hold to record',
    releaseToSend: 'Release to send',
    
    // Polls
    createPoll: 'Create Poll',
    pollQuestion: 'Question',
    pollQuestionPlaceholder: 'What do you want to ask?',
    pollOptions: 'Options',
    pollOptionPlaceholder: 'Option {number}',
    addOption: 'Add Option',
    allowMultiple: 'Allow multiple answers',
    pollVotes: '{count} votes',
    pollVote: '{count} vote',
    vote: 'Vote',
    
    // Calls
    incomingCall: 'Incoming call',
    outgoingCall: 'Calling...',
    voiceCall: 'Voice Call',
    videoCall: 'Video Call',
    accept: 'Accept',
    decline: 'Decline',
    endCall: 'End Call',
    mute: 'Mute',
    unmute: 'Unmute',
    cameraOn: 'Camera On',
    cameraOff: 'Camera Off',
    callEnded: 'Call ended',
    callDeclined: 'Call declined',
    noAnswer: 'No answer',
    
    // User Settings
    settings: 'Settings',
    profile: 'Profile',
    appearance: 'Appearance',
    security: 'Security',
    language: 'Language',
    displayName: 'Display Name',
    displayNamePlaceholder: 'Enter display name',
    changeAvatar: 'Change Avatar',
    theme: 'Theme',
    themeLight: 'Light',
    themeDark: 'Dark',
    themeSystem: 'System',
    currentPassword: 'Current Password',
    changePassword: 'Change Password',
    passwordChanged: 'Password changed successfully',
    
    // Admin Panel
    adminPanel: 'Admin Panel',
    overview: 'Overview',
    users: 'Users',
    moderation: 'Moderation',
    sessions: 'Sessions',
    storage: 'Storage',
    systemLogs: 'System Logs',
    announcements: 'Announcements',
    serverConfig: 'Server Config',
    browserData: 'Browser Data',
    
    // Admin Overview
    totalUsers: 'Total Users',
    onlineNow: 'Online Now',
    bannedUsers: 'Banned Users',
    totalMessages: 'Total Messages',
    serverStatus: 'Server Status',
    serverOnline: 'Online',
    serverMaintenance: 'Maintenance',
    
    // Admin Users
    searchUsersAdmin: 'Search users...',
    filterByRole: 'Filter by role',
    allRoles: 'All roles',
    filterByStatus: 'Filter by status',
    allStatuses: 'All statuses',
    verified: 'Verified',
    unverified: 'Unverified',
    banUser: 'Ban',
    unbanUser: 'Unban',
    kickUser: 'Kick',
    deleteUser: 'Delete',
    changeRole: 'Change role',
    user: 'User',
    banned: 'Banned',
    
    // Admin Moderation
    bannedUsersList: 'Banned Users',
    moderatorsList: 'Moderators',
    adminsList: 'Administrators',
    noBannedUsers: 'No banned users',
    noModerators: 'No moderators',
    
    // Admin Announcements
    sendAnnouncement: 'Send Announcement',
    announcementPlaceholder: 'Enter announcement message...',
    announcementSent: 'Announcement sent',
    
    // Admin Config
    maintenanceMode: 'Maintenance Mode',
    maintenanceMessage: 'Maintenance message',
    enableMaintenance: 'Enable Maintenance',
    disableMaintenance: 'Disable Maintenance',
    encryption: 'Message Encryption',
    captcha: 'CAPTCHA Verification',
    emailVerification: 'Email Verification',
    allowRegistration: 'Allow Registration',
    maxFileSize: 'Max File Size',
    
    // Errors
    error: 'Error',
    errorOccurred: 'An error occurred',
    networkError: 'Network error',
    serverError: 'Server error',
    unauthorized: 'Unauthorized',
    notFound: 'Not found',
    invalidCredentials: 'Invalid username or password',
    usernameTaken: 'Username already taken',
    emailTaken: 'Email already registered',
    passwordMismatch: 'Passwords do not match',
    passwordTooShort: 'Password must be at least 6 characters',
    
    // Success
    success: 'Success',
    saved: 'Saved successfully',
    deleted: 'Deleted successfully',
    copied: 'Copied to clipboard',
    
    // YouTube
    watchOnYouTube: 'Watch on YouTube',
    youtubePlayer: 'YouTube Player',
  },
  
  ru: {
    // General
    appName: '4 Messenger',
    loading: 'Загрузка...',
    save: 'Сохранить',
    cancel: 'Отмена',
    delete: 'Удалить',
    edit: 'Редактировать',
    close: 'Закрыть',
    back: 'Назад',
    next: 'Далее',
    confirm: 'Подтвердить',
    search: 'Поиск',
    send: 'Отправить',
    retry: 'Повторить',
    yes: 'Да',
    no: 'Нет',
    or: 'или',
    
    // Connect Screen
    connectTitle: 'Добро пожаловать в',
    connectSubtitle: 'Безопасный, Приватный, Самостоятельный хостинг',
    serverUrl: 'URL сервера',
    serverUrlPlaceholder: 'https://ваш-сервер.com',
    connect: 'Подключиться',
    connecting: 'Подключение...',
    savedServers: 'Сохранённые серверы',
    addServer: 'Добавить',
    saveServer: 'Сохранить сервер',
    serverName: 'Название сервера',
    serverNamePlaceholder: 'Мой сервер',
    noSavedServers: 'Нет сохранённых серверов',
    connectionError: 'Ошибка подключения',
    features: {
      encrypted: 'Сквозное шифрование',
      groups: 'Группы и каналы',
      selfHosted: 'Самостоятельный хостинг'
    },
    
    // Auth Screen
    serverPassword: 'Пароль сервера',
    serverPasswordPlaceholder: 'Введите пароль сервера',
    verifyPassword: 'Проверить пароль',
    verifying: 'Проверка...',
    invalidPassword: 'Неверный пароль',
    captchaTitle: 'Проверка безопасности',
    captchaSubtitle: 'Пройдите проверку для продолжения',
    captchaLoading: 'Загрузка проверки безопасности...',
    captchaError: 'Проверка не пройдена',
    captchaExpired: 'Проверка истекла, попробуйте снова',
    
    // Login Screen
    signIn: 'Вход',
    signInSubtitle: 'С возвращением',
    username: 'Имя пользователя',
    usernamePlaceholder: 'Введите имя пользователя',
    password: 'Пароль',
    passwordPlaceholder: 'Введите пароль',
    signingIn: 'Вход...',
    forgotPassword: 'Забыли пароль?',
    noAccount: 'Нет аккаунта?',
    createAccount: 'Создать аккаунт',
    backToServer: 'Вернуться к выбору сервера',
    
    // Register Screen
    register: 'Создать аккаунт',
    registerSubtitle: 'Присоединяйтесь к общению',
    email: 'Email',
    emailPlaceholder: 'Введите email',
    confirmPassword: 'Подтвердите пароль',
    confirmPasswordPlaceholder: 'Подтвердите пароль',
    creating: 'Создание аккаунта...',
    hasAccount: 'Уже есть аккаунт?',
    
    // Forgot Password
    forgotPasswordTitle: 'Сброс пароля',
    enterEmail: 'Введите ваш email адрес',
    sendResetCode: 'Отправить код',
    sending: 'Отправка...',
    resetCodeSent: 'Код отправлен на ваш email',
    enterCode: 'Введите 6-значный код',
    codeExpires: 'Код действителен 15 минут',
    verifyCode: 'Проверить код',
    newPassword: 'Новый пароль',
    newPasswordPlaceholder: 'Введите новый пароль',
    resetPassword: 'Сбросить пароль',
    resetting: 'Сброс...',
    passwordReset: 'Пароль успешно сброшен!',
    backToSignIn: 'Вернуться к входу',
    
    // Chat Screen
    chats: 'Чаты',
    newChat: 'Новый чат',
    newGroup: 'Новая группа',
    searchChats: 'Поиск чатов...',
    noChats: 'Нет чатов',
    startNewChat: 'Начните новый разговор',
    typeMessage: 'Введите сообщение...',
    online: 'В сети',
    offline: 'Не в сети',
    typing: 'печатает...',
    you: 'Вы',
    today: 'Сегодня',
    yesterday: 'Вчера',
    
    // New Chat Modal
    newChatTitle: 'Новый чат',
    searchUsers: 'Поиск пользователей...',
    searchUsersPlaceholder: 'Введите точное имя пользователя',
    searchUsersPlaceholderAdmin: 'Поиск пользователей...',
    searchUsersHint: 'Введите точное имя пользователя для поиска',
    searchUsersHintAdmin: 'Поиск по имени, email или отображаемому имени',
    noUsersFound: 'Пользователи не найдены',
    enterUsername: 'Введите имя пользователя и нажмите Поиск',
    startChat: 'Начать чат',
    
    // New Group Modal
    newGroupTitle: 'Новая группа',
    newChannelTitle: 'Новый канал',
    groupName: 'Название группы',
    groupNamePlaceholder: 'Введите название группы',
    channelNamePlaceholder: 'Введите название канала',
    selectMembers: 'Выберите участников',
    createGroup: 'Создать группу',
    createChannel: 'Создать канал',
    channelDescription: 'Каналы для рассылки. Только админы могут писать.',
    channel: 'Канал',
    noUsersAvailable: 'Нет доступных пользователей',
    
    // Chat Info
    chatInfo: 'Информация о чате',
    members: 'Участники',
    member: 'участник',
    membersCount: '{count} участников',
    admin: 'Админ',
    moderator: 'Модератор',
    channelAdmin: 'Админ канала',
    leaveGroup: 'Покинуть группу',
    leaveChannel: 'Покинуть канал',
    deleteChat: 'Удалить чат',
    addMember: 'Добавить участника',
    removeMember: 'Удалить участника',
    makeAdmin: 'Сделать админом',
    removeAdmin: 'Снять админа',
    description: 'Описание',
    noDescription: 'Нет описания',
    
    // Messages
    editMessage: 'Редактировать',
    deleteMessage: 'Удалить',
    copyMessage: 'Копировать',
    replyMessage: 'Ответить',
    messageDeleted: 'Сообщение удалено',
    messageEdited: 'изменено',
    
    // Files
    attachFile: 'Прикрепить файл',
    sendFile: 'Отправить файл',
    download: 'Скачать',
    uploading: 'Загрузка...',
    fileTooLarge: 'Файл слишком большой',
    fileTypeNotAllowed: 'Тип файла не разрешён',
    
    // Voice Messages
    voiceMessage: 'Голосовое сообщение',
    recording: 'Запись...',
    holdToRecord: 'Удерживайте для записи',
    releaseToSend: 'Отпустите для отправки',
    
    // Polls
    createPoll: 'Создать опрос',
    pollQuestion: 'Вопрос',
    pollQuestionPlaceholder: 'Что вы хотите спросить?',
    pollOptions: 'Варианты',
    pollOptionPlaceholder: 'Вариант {number}',
    addOption: 'Добавить вариант',
    allowMultiple: 'Разрешить несколько ответов',
    pollVotes: '{count} голосов',
    pollVote: '{count} голос',
    vote: 'Голосовать',
    
    // Calls
    incomingCall: 'Входящий звонок',
    outgoingCall: 'Вызов...',
    voiceCall: 'Голосовой звонок',
    videoCall: 'Видеозвонок',
    accept: 'Принять',
    decline: 'Отклонить',
    endCall: 'Завершить',
    mute: 'Выкл. микрофон',
    unmute: 'Вкл. микрофон',
    cameraOn: 'Вкл. камеру',
    cameraOff: 'Выкл. камеру',
    callEnded: 'Звонок завершён',
    callDeclined: 'Звонок отклонён',
    noAnswer: 'Нет ответа',
    
    // User Settings
    settings: 'Настройки',
    profile: 'Профиль',
    appearance: 'Внешний вид',
    security: 'Безопасность',
    language: 'Язык',
    displayName: 'Отображаемое имя',
    displayNamePlaceholder: 'Введите отображаемое имя',
    changeAvatar: 'Изменить аватар',
    theme: 'Тема',
    themeLight: 'Светлая',
    themeDark: 'Тёмная',
    themeSystem: 'Системная',
    currentPassword: 'Текущий пароль',
    changePassword: 'Изменить пароль',
    passwordChanged: 'Пароль успешно изменён',
    
    // Admin Panel
    adminPanel: 'Панель администратора',
    overview: 'Обзор',
    users: 'Пользователи',
    moderation: 'Модерация',
    sessions: 'Сессии',
    storage: 'Хранилище',
    systemLogs: 'Системные логи',
    announcements: 'Объявления',
    serverConfig: 'Настройки сервера',
    browserData: 'Данные браузеров',
    
    // Admin Overview
    totalUsers: 'Всего пользователей',
    onlineNow: 'Сейчас онлайн',
    bannedUsers: 'Заблокировано',
    totalMessages: 'Всего сообщений',
    serverStatus: 'Статус сервера',
    serverOnline: 'Онлайн',
    serverMaintenance: 'Обслуживание',
    
    // Admin Users
    searchUsersAdmin: 'Поиск пользователей...',
    filterByRole: 'Фильтр по роли',
    allRoles: 'Все роли',
    filterByStatus: 'Фильтр по статусу',
    allStatuses: 'Все статусы',
    verified: 'Подтверждён',
    unverified: 'Не подтверждён',
    banUser: 'Заблокировать',
    unbanUser: 'Разблокировать',
    kickUser: 'Кикнуть',
    deleteUser: 'Удалить',
    changeRole: 'Изменить роль',
    user: 'Пользователь',
    banned: 'Заблокирован',
    
    // Admin Moderation
    bannedUsersList: 'Заблокированные пользователи',
    moderatorsList: 'Модераторы',
    adminsList: 'Администраторы',
    noBannedUsers: 'Нет заблокированных',
    noModerators: 'Нет модераторов',
    
    // Admin Announcements
    sendAnnouncement: 'Отправить объявление',
    announcementPlaceholder: 'Введите текст объявления...',
    announcementSent: 'Объявление отправлено',
    
    // Admin Config
    maintenanceMode: 'Режим обслуживания',
    maintenanceMessage: 'Сообщение обслуживания',
    enableMaintenance: 'Включить обслуживание',
    disableMaintenance: 'Выключить обслуживание',
    encryption: 'Шифрование сообщений',
    captcha: 'CAPTCHA проверка',
    emailVerification: 'Подтверждение email',
    allowRegistration: 'Разрешить регистрацию',
    maxFileSize: 'Макс. размер файла',
    
    // Errors
    error: 'Ошибка',
    errorOccurred: 'Произошла ошибка',
    networkError: 'Ошибка сети',
    serverError: 'Ошибка сервера',
    unauthorized: 'Не авторизован',
    notFound: 'Не найдено',
    invalidCredentials: 'Неверное имя пользователя или пароль',
    usernameTaken: 'Имя пользователя занято',
    emailTaken: 'Email уже зарегистрирован',
    passwordMismatch: 'Пароли не совпадают',
    passwordTooShort: 'Пароль должен быть не менее 6 символов',
    
    // Success
    success: 'Успешно',
    saved: 'Сохранено',
    deleted: 'Удалено',
    copied: 'Скопировано в буфер обмена',
    
    // YouTube
    watchOnYouTube: 'Смотреть на YouTube',
    youtubePlayer: 'YouTube плеер',
  }
} as const;

export type TranslationKey = keyof typeof translations.en;

export function getTranslation(lang: Language, key: string): string {
  const keys = key.split('.');
  let value: unknown = translations[lang];
  
  for (const k of keys) {
    if (value && typeof value === 'object' && k in value) {
      value = (value as Record<string, unknown>)[k];
    } else {
      // Fallback to English
      value = translations.en;
      for (const fallbackKey of keys) {
        if (value && typeof value === 'object' && fallbackKey in value) {
          value = (value as Record<string, unknown>)[fallbackKey];
        } else {
          return key; // Return key if not found
        }
      }
      break;
    }
  }
  
  return typeof value === 'string' ? value : key;
}
