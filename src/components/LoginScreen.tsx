import { useState } from 'react';
import { useStore } from '../store';
import { User, Lock, ArrowRight, UserPlus, Loader2, ArrowLeft, Mail, KeyRound, Eye, EyeOff, CheckCircle, X } from 'lucide-react';

export function LoginScreen() {
  const { login, setScreen, serverConfig, serverUrl } = useStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  
  // Forgot password state
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [forgotStep, setForgotStep] = useState<'email' | 'code' | 'newPassword' | 'success'>('email');
  const [forgotEmail, setForgotEmail] = useState('');
  const [resetCode, setResetCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [forgotLoading, setForgotLoading] = useState(false);
  const [forgotError, setForgotError] = useState('');
  const [resetToken, setResetToken] = useState('');

  const handleLogin = async () => {
    if (username.trim() && password.trim()) {
      setLoading(true);
      try {
        await login(username.trim(), password);
      } finally {
        setLoading(false);
      }
    }
  };

  const handleBack = () => {
    useStore.getState().setScreen('connect');
    useStore.getState().setServerUrl('');
    useStore.getState().setConnectionError(null);
  };

  const handleForgotPasswordSubmit = async () => {
    if (!forgotEmail.trim()) return;
    
    setForgotLoading(true);
    setForgotError('');
    
    try {
      const response = await fetch(`${serverUrl}/api/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: forgotEmail.trim().toLowerCase() }),
      });
      
      const data = await response.json();
      
      // Always show code entry screen (whether email exists or not - for security)
      if (data.success) {
        setResetToken(data.resetToken || '');
        setForgotStep('code');
      } else {
        // Still proceed to code screen to not reveal if email exists
        setForgotStep('code');
      }
    } catch {
      // Still proceed to not reveal if email exists
      setForgotStep('code');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleCodeSubmit = async () => {
    if (!resetCode.trim()) return;
    
    setForgotLoading(true);
    setForgotError('');
    
    try {
      const response = await fetch(`${serverUrl}/api/verify-reset-code`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          email: forgotEmail.trim().toLowerCase(),
          code: resetCode.trim(),
        }),
      });
      
      const data = await response.json();
      
      if (data.valid) {
        setResetToken(data.resetToken);
        setForgotStep('newPassword');
      } else {
        setForgotError('Invalid or expired code. Please try again.');
      }
    } catch {
      setForgotError('Failed to verify code. Please try again.');
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async () => {
    if (!newPassword.trim() || newPassword !== confirmNewPassword) return;
    
    if (newPassword.length < 6) {
      setForgotError('Password must be at least 6 characters');
      return;
    }
    
    setForgotLoading(true);
    setForgotError('');
    
    try {
      const response = await fetch(`${serverUrl}/api/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          email: forgotEmail.trim().toLowerCase(),
          resetToken,
          newPassword,
        }),
      });
      
      const data = await response.json();
      
      if (data.success) {
        setForgotStep('success');
      } else {
        setForgotError(data.error || 'Failed to reset password');
      }
    } catch {
      setForgotError('Failed to reset password. Please try again.');
    } finally {
      setForgotLoading(false);
    }
  };

  const closeForgotPassword = () => {
    setShowForgotPassword(false);
    setForgotStep('email');
    setForgotEmail('');
    setResetCode('');
    setNewPassword('');
    setConfirmNewPassword('');
    setForgotError('');
    setResetToken('');
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-gray-900 via-indigo-950 to-gray-900 p-4">
      <div className="w-full max-w-md px-6">
        <button onClick={handleBack} className="mb-6 flex items-center gap-2 text-sm text-gray-400 transition hover:text-white">
          <ArrowLeft className="h-4 w-4" /> Back to server selection
        </button>

        <div className="mb-6 text-center">
          <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 shadow-lg shadow-indigo-500/30">
            <span className="text-3xl font-black text-white">4</span>
          </div>
          <h2 className="text-2xl font-bold text-white">Welcome</h2>
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
                onKeyDown={e => e.key === 'Enter' && handleLogin()}
                placeholder="Enter username"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                autoFocus
                disabled={loading}
              />
            </div>
          </div>

          <div className="mb-2">
            <label className="mb-1.5 block text-sm font-medium text-gray-300">Password</label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLogin()}
                placeholder="Enter password"
                className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                disabled={loading}
              />
            </div>
          </div>

          <div className="mb-6 text-right">
            <button
              onClick={() => setShowForgotPassword(true)}
              className="text-sm text-indigo-400 hover:text-indigo-300 transition"
            >
              Forgot password?
            </button>
          </div>

          <button
            onClick={handleLogin}
            disabled={loading || !username.trim() || !password.trim()}
            className="mb-4 flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg shadow-indigo-500/25 transition hover:shadow-indigo-500/40 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" /> Signing in...
              </>
            ) : (
              <>
                Sign In <ArrowRight className="h-5 w-5" />
              </>
            )}
          </button>

          {serverConfig.allowRegistration && (
            <>
              <div className="relative mb-4">
                <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-white/10" /></div>
                <div className="relative flex justify-center text-xs"><span className="bg-transparent px-2 text-gray-500">or</span></div>
              </div>

              <button
                onClick={() => setScreen('register')}
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/5 py-3 font-medium text-gray-300 transition hover:bg-white/10 active:scale-[0.98] disabled:opacity-50"
              >
                <UserPlus className="h-5 w-5" /> Create Account
              </button>
            </>
          )}
        </div>
      </div>

      {/* Forgot Password Modal */}
      {showForgotPassword && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl border border-white/10 bg-gray-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-bold text-white">
                {forgotStep === 'email' && 'Reset Password'}
                {forgotStep === 'code' && 'Enter Code'}
                {forgotStep === 'newPassword' && 'New Password'}
                {forgotStep === 'success' && 'Password Reset'}
              </h3>
              <button onClick={closeForgotPassword} className="text-gray-400 hover:text-white transition">
                <X className="h-5 w-5" />
              </button>
            </div>

            {forgotError && (
              <div className="mb-4 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3 text-sm text-red-400">
                {forgotError}
              </div>
            )}

            {/* Step 1: Enter Email */}
            {forgotStep === 'email' && (
              <>
                <p className="text-gray-400 text-sm mb-4">
                  Enter the email address associated with your account. We'll send you a code to reset your password.
                </p>
                <div className="mb-4">
                  <label className="mb-1.5 block text-sm font-medium text-gray-300">Email Address</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                    <input
                      type="email"
                      value={forgotEmail}
                      onChange={e => setForgotEmail(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleForgotPasswordSubmit()}
                      placeholder="you@example.com"
                      className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                      autoFocus
                      disabled={forgotLoading}
                    />
                  </div>
                </div>
                <button
                  onClick={handleForgotPasswordSubmit}
                  disabled={forgotLoading || !forgotEmail.trim()}
                  className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg transition hover:shadow-indigo-500/40 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {forgotLoading ? (
                    <><Loader2 className="h-5 w-5 animate-spin" /> Sending...</>
                  ) : (
                    <>Send Reset Code <ArrowRight className="h-5 w-5" /></>
                  )}
                </button>
              </>
            )}

            {/* Step 2: Enter Code */}
            {forgotStep === 'code' && (
              <>
                <p className="text-gray-400 text-sm mb-4">
                  If an account exists with that email, we've sent a 6-digit code. Enter it below.
                </p>
                <div className="mb-4">
                  <label className="mb-1.5 block text-sm font-medium text-gray-300">Reset Code</label>
                  <div className="relative">
                    <KeyRound className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                    <input
                      type="text"
                      value={resetCode}
                      onChange={e => setResetCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      onKeyDown={e => e.key === 'Enter' && handleCodeSubmit()}
                      placeholder="000000"
                      maxLength={6}
                      className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20 text-center text-2xl tracking-[0.5em] font-mono"
                      autoFocus
                      disabled={forgotLoading}
                    />
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => setForgotStep('email')}
                    className="flex-1 rounded-xl border border-white/10 bg-white/5 py-3 font-medium text-gray-300 transition hover:bg-white/10"
                  >
                    Back
                  </button>
                  <button
                    onClick={handleCodeSubmit}
                    disabled={forgotLoading || resetCode.length !== 6}
                    className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg transition hover:shadow-indigo-500/40 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {forgotLoading ? (
                      <Loader2 className="h-5 w-5 animate-spin" />
                    ) : (
                      <>Verify</>
                    )}
                  </button>
                </div>
                <p className="mt-4 text-center text-xs text-gray-500">
                  Code expires in 15 minutes
                </p>
              </>
            )}

            {/* Step 3: New Password */}
            {forgotStep === 'newPassword' && (
              <>
                <p className="text-gray-400 text-sm mb-4">
                  Enter your new password. Make sure it's at least 6 characters.
                </p>
                <div className="mb-4">
                  <label className="mb-1.5 block text-sm font-medium text-gray-300">New Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                    <input
                      type={showNewPassword ? 'text' : 'password'}
                      value={newPassword}
                      onChange={e => setNewPassword(e.target.value)}
                      placeholder="Enter new password"
                      className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-11 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                      autoFocus
                      disabled={forgotLoading}
                    />
                    <button
                      type="button"
                      onClick={() => setShowNewPassword(!showNewPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                    >
                      {showNewPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                    </button>
                  </div>
                </div>
                <div className="mb-6">
                  <label className="mb-1.5 block text-sm font-medium text-gray-300">Confirm Password</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                    <input
                      type={showNewPassword ? 'text' : 'password'}
                      value={confirmNewPassword}
                      onChange={e => setConfirmNewPassword(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleResetPassword()}
                      placeholder="Confirm new password"
                      className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-11 pr-4 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                      disabled={forgotLoading}
                    />
                  </div>
                  {newPassword && confirmNewPassword && newPassword !== confirmNewPassword && (
                    <p className="mt-1 text-xs text-red-400">Passwords do not match</p>
                  )}
                </div>
                <button
                  onClick={handleResetPassword}
                  disabled={forgotLoading || !newPassword || newPassword !== confirmNewPassword || newPassword.length < 6}
                  className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg transition hover:shadow-indigo-500/40 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {forgotLoading ? (
                    <><Loader2 className="h-5 w-5 animate-spin" /> Resetting...</>
                  ) : (
                    <>Reset Password</>
                  )}
                </button>
              </>
            )}

            {/* Step 4: Success */}
            {forgotStep === 'success' && (
              <div className="text-center py-4">
                <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-green-500/20">
                  <CheckCircle className="h-8 w-8 text-green-400" />
                </div>
                <h4 className="text-lg font-semibold text-white mb-2">Password Reset Successfully</h4>
                <p className="text-gray-400 text-sm mb-6">
                  Your password has been changed. You can now sign in with your new password.
                </p>
                <button
                  onClick={closeForgotPassword}
                  className="w-full rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg transition hover:shadow-indigo-500/40 active:scale-[0.98]"
                >
                  Back to Sign In
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
