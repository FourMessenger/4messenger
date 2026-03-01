import { useState } from 'react';
import { useStore } from '../store';
import { User, Lock, Mail, ArrowRight, ArrowLeft, Loader2 } from 'lucide-react';

export function RegisterScreen() {
  const { register, setScreen, serverConfig } = useStore();
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    if (!username.trim() || !email.trim() || !password.trim()) {
      useStore.getState().addNotification('Please fill all fields', 'error');
      return;
    }
    if (password !== confirmPass) {
      useStore.getState().addNotification('Passwords do not match', 'error');
      return;
    }
    if (password.length < 6) {
      useStore.getState().addNotification('Password must be at least 6 characters', 'error');
      return;
    }
    
    setLoading(true);
    try {
      await register(username.trim(), email.trim(), password);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-gray-900 via-indigo-950 to-gray-900 p-4">
      <div className="w-full max-w-md px-6">
        <button onClick={() => setScreen('login')} className="mb-6 flex items-center gap-2 text-sm text-gray-400 transition hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to login
        </button>

        <div className="mb-6 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg shadow-indigo-500/30">
            <span className="text-3xl font-black text-white">4</span>
          </div>
          <h2 className="text-2xl font-bold text-white">Create Account</h2>
          <p className="mt-1 text-sm text-gray-400">{serverConfig.serverName}</p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl">
          <div className="mb-4">
            <label className="mb-1.5 block text-sm font-medium text-gray-300">Username</label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="Choose a username"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                autoFocus
                disabled={loading}
              />
            </div>
          </div>

          <div className="mb-4">
            <label className="mb-1.5 block text-sm font-medium text-gray-300">Email</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="your@email.com"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                disabled={loading}
              />
            </div>
            {serverConfig.emailVerification && (
              <p className="mt-1 text-xs text-amber-400">Email verification is required</p>
            )}
          </div>

          <div className="mb-4">
            <label className="mb-1.5 block text-sm font-medium text-gray-300">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Min 6 characters"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                disabled={loading}
              />
            </div>
          </div>

          <div className="mb-6">
            <label className="mb-1.5 block text-sm font-medium text-gray-300">Confirm Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
              <input
                type="password"
                value={confirmPass}
                onChange={e => setConfirmPass(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleRegister()}
                placeholder="Repeat password"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                disabled={loading}
              />
            </div>
          </div>

          <button
            onClick={handleRegister}
            disabled={loading || !username.trim() || !email.trim() || !password.trim() || !confirmPass.trim()}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg shadow-indigo-500/25 transition hover:shadow-indigo-500/40 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" /> Creating account...
              </>
            ) : (
              <>
                Create Account <ArrowRight className="h-5 w-5" />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
