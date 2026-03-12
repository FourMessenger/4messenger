import { useState, useEffect } from 'react';
import { useStore, ServerShortcut } from '../store';
import { Globe, ArrowRight, Shield, MessageSquare, AlertCircle, Loader2, Server, Plus, X, Star, Languages, FileText, CheckCircle } from 'lucide-react';
import PrivacyPolicy from './PrivacyPolicy';

export function ConnectScreen() {
  const [url, setUrl] = useState('');
  const [showAddShortcut, setShowAddShortcut] = useState(false);
  const [shortcutName, setShortcutName] = useState('');
  const [shortcutUrl, setShortcutUrl] = useState('');
  
  const { 
    setServerUrl, 
    connectToServer, 
    connecting, 
    connectionError, 
    setConnectionError,
    serverShortcuts,
    addServerShortcut,
    removeServerShortcut,
    initOfficialShortcut,
    language,
    setLanguage,
    translate,
    checkPrivacyPolicy,
    acceptPrivacyPolicy,
    serverConfig,
  } = useStore();

  const [showPrivacyModal, setShowPrivacyModal] = useState(false);
  const [pendingServerUrl, setPendingServerUrl] = useState<string | null>(null);
  const [showFullPolicy, setShowFullPolicy] = useState(false);

  const [showLanguageMenu, setShowLanguageMenu] = useState(false);

  const languages = [
    { code: 'en', name: 'English', flag: '🇬🇧' },
    { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  ] as const;

  // Load official server shortcut on mount
  useEffect(() => {
    initOfficialShortcut();
  }, [initOfficialShortcut]);

  // Check if privacy policy was already accepted globally (only once on first visit)
  useEffect(() => {
    if (!checkPrivacyPolicy()) {
      setShowPrivacyModal(true);
    }
  }, [checkPrivacyPolicy]);

  const proceedWithConnection = async (serverUrl: string) => {
    setConnectionError(null);
    setServerUrl(serverUrl);
    await connectToServer();
  };

  const handleConnect = async () => {
    if (url.trim() && !connecting) {
      const serverUrl = url.trim();
      await proceedWithConnection(serverUrl);
    }
  };

  const handleShortcutClick = async (shortcut: ServerShortcut) => {
    if (!connecting) {
      setUrl(shortcut.url);
      await proceedWithConnection(shortcut.url);
    }
  };

  const handleAcceptPrivacyPolicy = async () => {
    // Save acceptance to localStorage - this ensures it only appears once globally
    acceptPrivacyPolicy();
    setShowPrivacyModal(false);
    setShowFullPolicy(false);
    // If there was a pending connection, proceed with it
    if (pendingServerUrl) {
      const serverToConnect = pendingServerUrl;
      setPendingServerUrl(null);
      await proceedWithConnection(serverToConnect);
    }
  };

  const handleDeclinePrivacyPolicy = () => {
    setShowPrivacyModal(false);
    setPendingServerUrl(null);
    setConnectionError(translate('connect.privacyDeclined'));
  };

  const handleAddShortcut = () => {
    if (shortcutName.trim() && shortcutUrl.trim()) {
      addServerShortcut(shortcutName.trim(), shortcutUrl.trim());
      setShortcutName('');
      setShortcutUrl('');
      setShowAddShortcut(false);
    }
  };

  const handleRemoveShortcut = (e: React.MouseEvent, id: string) => {
    e.stopPropagation();
    removeServerShortcut(id);
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-gray-900 via-indigo-950 to-gray-900 p-4">
      <div className="absolute inset-0 overflow-hidden">
        {[...Array(20)].map((_, i) => (
          <div
            key={i}
            className="absolute rounded-full bg-indigo-500/5"
            style={{
              width: Math.random() * 300 + 50,
              height: Math.random() * 300 + 50,
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              animationDuration: `${Math.random() * 10 + 5}s`,
              animationDelay: `${Math.random() * 5}s`,
            }}
          />
        ))}
      </div>

      <div className="relative z-10 w-full max-w-md px-6">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg shadow-indigo-500/30">
            <span className="text-4xl font-black text-white">4</span>
          </div>
          <h1 className="mb-2 text-4xl font-black tracking-tight text-white">
            4 Messenger
          </h1>
          <p className="text-gray-400">{translate('connect.tagline')}</p>
        </div>

        {/* Language Selector */}
        <div className="absolute top-4 right-4">
          <div className="relative">
            <button
              onClick={() => setShowLanguageMenu(!showLanguageMenu)}
              className="flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-300 hover:bg-white/10 transition"
            >
              <Languages className="h-4 w-4" />
              {languages.find(l => l.code === language)?.flag}
            </button>
            
            {showLanguageMenu && (
              <>
                <div 
                  className="fixed inset-0 z-40" 
                  onClick={() => setShowLanguageMenu(false)}
                />
                <div className="absolute right-0 mt-2 z-50 w-40 rounded-xl border border-white/10 bg-gray-900 shadow-xl overflow-hidden">
                  {languages.map((lang) => (
                    <button
                      key={lang.code}
                      onClick={() => {
                        setLanguage(lang.code);
                        setShowLanguageMenu(false);
                      }}
                      className={`w-full flex items-center gap-3 px-4 py-2.5 text-left text-sm transition ${
                        language === lang.code 
                          ? 'bg-indigo-500/20 text-indigo-300' 
                          : 'text-gray-300 hover:bg-white/5'
                      }`}
                    >
                      <span className="text-lg">{lang.flag}</span>
                      <span>{lang.name}</span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>

        {/* Server Shortcuts */}
        {serverShortcuts.length > 0 && (
          <div className="mb-6">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-gray-300 flex items-center gap-2">
                <Star className="h-4 w-4 text-yellow-500" />
                {translate('connect.savedServers')}
              </h2>
              <button
                onClick={() => setShowAddShortcut(true)}
                className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
              >
                <Plus className="h-3 w-3" />
                {translate('connect.add')}
              </button>
            </div>
            <div className="space-y-2">
              {serverShortcuts.map((shortcut) => (
                <button
                  key={shortcut.id}
                  onClick={() => handleShortcutClick(shortcut)}
                  disabled={connecting}
                  className="group w-full flex items-center gap-3 rounded-xl border border-white/10 bg-white/5 p-3 text-left transition hover:bg-white/10 hover:border-indigo-500/30 disabled:opacity-50"
                >
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 font-bold text-white">
                    {shortcut.name.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-white truncate">{shortcut.name}</p>
                    <p className="text-xs text-gray-500 truncate">{shortcut.url}</p>
                  </div>
                  {shortcut.id !== 'official-4messenger' && (
                    <button
                      onClick={(e) => handleRemoveShortcut(e, shortcut.id)}
                      className="p-1.5 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition"
                      title="Remove shortcut"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  )}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <label className="block text-sm font-medium text-gray-300">
              {translate('connect.serverUrl')}
            </label>
            {serverShortcuts.length === 0 && (
              <button
                onClick={() => setShowAddShortcut(true)}
                className="text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1"
              >
                <Plus className="h-3 w-3" />
                {translate('connect.saveServer')}
              </button>
            )}
          </div>
          <div className="relative mb-4">
            <Globe className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
            <input
              type="text"
              value={url}
              onChange={e => { setUrl(e.target.value); setConnectionError(null); }}
              onKeyDown={e => e.key === 'Enter' && handleConnect()}
              placeholder="https://your-server.com"
              disabled={connecting}
              className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 disabled:opacity-50"
            />
          </div>

          {/* Connection Error */}
          {connectionError && (
            <div className="mb-4 flex items-start gap-2 rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-sm text-red-400">
              <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-medium">{translate('connect.connectionFailed')}</p>
                <p className="text-xs text-red-400/80 mt-0.5">{connectionError}</p>
                <p className="text-xs text-gray-500 mt-1">{translate('connect.checkServer')}</p>
              </div>
            </div>
          )}

          <button
            onClick={handleConnect}
            disabled={connecting || !url.trim()}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg shadow-indigo-500/25 transition hover:shadow-indigo-500/40 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {connecting ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" />
                {translate('connect.connecting')}
              </>
            ) : (
              <>
                {translate('connect.connect')} <ArrowRight className="h-5 w-5" />
              </>
            )}
          </button>
        </div>

        <div className="mt-8 grid grid-cols-3 gap-4">
          <div className="rounded-xl border border-white/5 bg-white/5 p-4 text-center backdrop-blur">
            <Shield className="mx-auto mb-2 h-6 w-6 text-indigo-400" />
            <span className="text-xs text-gray-400">{translate('connect.encrypted')}</span>
          </div>
          <div className="rounded-xl border border-white/5 bg-white/5 p-4 text-center backdrop-blur">
            <MessageSquare className="mx-auto mb-2 h-6 w-6 text-purple-400" />
            <span className="text-xs text-gray-400">{translate('connect.groups')}</span>
          </div>
          <div className="rounded-xl border border-white/5 bg-white/5 p-4 text-center backdrop-blur">
            <Server className="mx-auto mb-2 h-6 w-6 text-blue-400" />
            <span className="text-xs text-gray-400">{translate('connect.selfHosted')}</span>
          </div>
        </div>

        <p className="mt-6 text-center text-xs text-gray-500">
          {translate('connect.startChatting')}
        </p>
      </div>

      {/* Add Shortcut Modal */}
      {showAddShortcut && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-2xl border border-white/10 bg-gray-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Star className="h-5 w-5 text-yellow-500" />
                {translate('connect.saveServer')}
              </h3>
              <button
                onClick={() => setShowAddShortcut(false)}
                className="p-1 rounded-lg hover:bg-white/10 text-gray-400"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">
                  {translate('connect.serverName')}
                </label>
                <input
                  type="text"
                  value={shortcutName}
                  onChange={e => setShortcutName(e.target.value)}
                  placeholder="My Server"
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-2.5 px-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1.5">
                  {translate('connect.serverUrl')}
                </label>
                <input
                  type="text"
                  value={shortcutUrl}
                  onChange={e => setShortcutUrl(e.target.value)}
                  placeholder="https://myserver.com:3000"
                  className="w-full rounded-xl border border-white/10 bg-white/5 py-2.5 px-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                />
              </div>

              <div className="flex gap-3 pt-2">
                <button
                  onClick={() => setShowAddShortcut(false)}
                  className="flex-1 rounded-xl border border-white/10 bg-white/5 py-2.5 font-medium text-gray-300 hover:bg-white/10 transition"
                >
                  {translate('common.cancel')}
                </button>
                <button
                  onClick={handleAddShortcut}
                  disabled={!shortcutName.trim() || !shortcutUrl.trim()}
                  className="flex-1 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-2.5 font-medium text-white shadow-lg shadow-indigo-500/25 transition hover:shadow-indigo-500/40 disabled:opacity-50"
                >
                  {translate('common.save')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Privacy Policy Acceptance Modal */}
      {showPrivacyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-2 sm:p-4">
          <div className="w-full max-w-lg rounded-xl sm:rounded-2xl border border-white/10 bg-gray-900 shadow-2xl overflow-hidden max-h-[95vh] flex flex-col">
            {/* Header */}
            <div className="p-4 sm:p-6 border-b border-white/10 bg-gradient-to-r from-indigo-900/50 to-purple-900/50 shrink-0">
              <div className="flex items-center gap-2 sm:gap-3">
                <div className="w-10 h-10 sm:w-12 sm:h-12 bg-indigo-600 rounded-lg sm:rounded-xl flex items-center justify-center shrink-0">
                  <FileText className="w-5 h-5 sm:w-6 sm:h-6 text-white" />
                </div>
                <div className="min-w-0">
                  <h2 className="text-lg sm:text-xl font-bold text-white">
                    {translate('privacy.title')}
                  </h2>
                  <p className="text-xs sm:text-sm text-gray-400 truncate">
                    {serverConfig.serverName || pendingServerUrl}
                  </p>
                </div>
              </div>
            </div>

            {/* Content */}
            <div className="p-4 sm:p-6 flex-1 overflow-y-auto">
              <p className="text-sm sm:text-base text-gray-300 mb-4">
                {translate('privacy.description')}
              </p>
              
              <div className="space-y-2 sm:space-y-3 mb-4 sm:mb-6">
                <div className="flex items-start gap-2 sm:gap-3 p-2.5 sm:p-3 rounded-lg sm:rounded-xl bg-white/5 border border-white/10">
                  <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-green-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs sm:text-sm text-white font-medium">{translate('privacy.dataCollection')}</p>
                    <p className="text-xs text-gray-400 hidden sm:block">{translate('privacy.dataCollectionDesc')}</p>
                  </div>
                </div>
                <div className="flex items-start gap-2 sm:gap-3 p-2.5 sm:p-3 rounded-lg sm:rounded-xl bg-white/5 border border-white/10">
                  <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-green-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs sm:text-sm text-white font-medium">{translate('privacy.browserData')}</p>
                    <p className="text-xs text-gray-400 hidden sm:block">{translate('privacy.browserDataDesc')}</p>
                  </div>
                </div>
                <div className="flex items-start gap-2 sm:gap-3 p-2.5 sm:p-3 rounded-lg sm:rounded-xl bg-white/5 border border-white/10">
                  <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-green-400 shrink-0 mt-0.5" />
                  <div>
                    <p className="text-xs sm:text-sm text-white font-medium">{translate('privacy.encryption')}</p>
                    <p className="text-xs text-gray-400 hidden sm:block">{translate('privacy.encryptionDesc')}</p>
                  </div>
                </div>
              </div>

              <button
                onClick={() => setShowFullPolicy(true)}
                className="w-full text-center text-xs sm:text-sm text-indigo-400 hover:text-indigo-300 mb-4 sm:mb-6 flex items-center justify-center gap-2"
              >
                <FileText className="w-4 h-4" />
                {translate('privacy.readFull')}
              </button>

              <div className="flex gap-2 sm:gap-3">
                <button
                  onClick={handleDeclinePrivacyPolicy}
                  className="flex-1 rounded-lg sm:rounded-xl border border-white/10 bg-white/5 py-2.5 sm:py-3 text-sm sm:text-base font-medium text-gray-300 hover:bg-white/10 transition"
                >
                  {translate('privacy.decline')}
                </button>
                <button
                  onClick={handleAcceptPrivacyPolicy}
                  className="flex-1 rounded-lg sm:rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-2.5 sm:py-3 text-sm sm:text-base font-medium text-white shadow-lg shadow-indigo-500/25 transition hover:shadow-indigo-500/40"
                >
                  {translate('privacy.accept')}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Full Privacy Policy Modal */}
      {showFullPolicy && (
        <PrivacyPolicy 
          onClose={() => setShowFullPolicy(false)}
          serverName={serverConfig.serverName || pendingServerUrl || '4 Messenger Server'}
          language={language}
        />
      )}
    </div>
  );
}
