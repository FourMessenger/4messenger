import { useState, useEffect, useRef } from 'react';
import { useStore } from '../store';
import { Lock, ShieldCheck, ArrowRight, ArrowLeft, Loader2, AlertTriangle, RefreshCw } from 'lucide-react';
import { Turnstile, type TurnstileInstance } from '@marsidev/react-turnstile';

export function AuthScreen() {
  const { serverConfig, verifyServerPassword, setScreen, serverUrl } = useStore();
  const [serverPass, setServerPass] = useState('');
  const [loading, setLoading] = useState(false);
  const [captchaLoading, setCaptchaLoading] = useState(false);
  const [turnstileSiteKey, setTurnstileSiteKey] = useState<string | null>(null);
  const [captchaError, setCaptchaError] = useState<string | null>(null);
  const turnstileRef = useRef<TurnstileInstance | null>(null);
  const verifiedRef = useRef(false);
  
  // Determine if password is required based on serverConfig
  const requiresPassword = serverConfig.serverPassword && serverConfig.serverPassword.length > 0;
  const requiresCaptcha = serverConfig.captchaEnabled;
  
  const [step, setStep] = useState<'password' | 'captcha'>(requiresPassword ? 'password' : 'captcha');
  const [passVerified, setPassVerified] = useState(!requiresPassword);

  // Fetch captcha config on mount
  useEffect(() => {
    if (!serverUrl) return;
    if (requiresCaptcha) {
      fetchCaptchaConfig();
    }
  }, [requiresCaptcha, serverUrl]);

  const fetchCaptchaConfig = async () => {
    if (!serverUrl) {
      setCaptchaError('Server URL is not set. Please go back and connect again.');
      return;
    }
    
    try {
      const response = await fetch(`${serverUrl}/api/captcha`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
      
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.enabled && data.type === 'cloudflare' && data.siteKey) {
        setTurnstileSiteKey(data.siteKey);
      } else if (!data.enabled) {
        // CAPTCHA not enabled, skip to login
        setScreen('login');
      } else {
        setCaptchaError('Invalid CAPTCHA configuration. Please contact the server administrator.');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';
      if (errorMessage.includes('Failed to fetch') || errorMessage.includes('NetworkError')) {
        setCaptchaError('Could not connect to the server. Please check your connection.');
      } else {
        setCaptchaError(`Failed to load CAPTCHA: ${errorMessage}`);
      }
    }
  };

  // If neither password nor captcha is required, go straight to login
  useEffect(() => {
    if (!requiresPassword && !requiresCaptcha) {
      setScreen('login');
    } else if (!requiresPassword && requiresCaptcha) {
      setStep('captcha');
    }
  }, [requiresPassword, requiresCaptcha, setScreen]);

  const handlePasswordSubmit = async () => {
    setLoading(true);
    try {
      const verified = await verifyServerPassword(serverPass);
      if (verified) {
        setPassVerified(true);
        if (requiresCaptcha) {
          setStep('captcha');
        } else {
          setScreen('login');
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const handleTurnstileSuccess = async (token: string) => {
    if (verifiedRef.current) return;
    verifiedRef.current = true;
    
    setCaptchaLoading(true);
    setCaptchaError(null);
    
    try {
      const response = await fetch(`${serverUrl}/api/captcha/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      
      const data = await response.json();
      
      if (data.valid && data.captchaToken) {
        useStore.setState({ captchaToken: data.captchaToken });
        setScreen('login');
      } else {
        setCaptchaError(data.error || 'CAPTCHA verification failed');
        verifiedRef.current = false;
        turnstileRef.current?.reset();
      }
    } catch {
      setCaptchaError('Failed to verify CAPTCHA');
      verifiedRef.current = false;
      turnstileRef.current?.reset();
    } finally {
      setCaptchaLoading(false);
    }
  };

  const handleTurnstileError = (error?: string | Error) => {
    const errorMsg = error instanceof Error ? error.message : (typeof error === 'string' ? error : 'Unknown error');
    setCaptchaError(`CAPTCHA challenge failed: ${errorMsg}. Please ensure the domain is added to Turnstile settings.`);
    setCaptchaLoading(false);
    verifiedRef.current = false;
  };

  const handleTurnstileExpire = () => {
    setCaptchaError('CAPTCHA expired. Please try again.');
    turnstileRef.current?.reset();
  };

  const handleRetry = () => {
    setCaptchaError(null);
    setTurnstileSiteKey(null);
    verifiedRef.current = false;
    fetchCaptchaConfig();
  };

  const handleBack = () => {
    useStore.getState().setScreen('connect');
    useStore.getState().setServerUrl('');
    useStore.getState().setConnectionError(null);
  };

  // Show nothing if we're about to redirect to login
  if (!requiresPassword && !requiresCaptcha) {
    return null;
  }

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
          <h2 className="text-2xl font-bold text-white">Server Verification</h2>
          <p className="mt-1 text-sm text-gray-400 truncate">{serverConfig.serverName || serverUrl}</p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-2xl backdrop-blur-xl">
          {step === 'password' && !passVerified && requiresPassword && (
            <>
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/10">
                  <Lock className="h-5 w-5 text-amber-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Server Password</h3>
                  <p className="text-xs text-gray-400">This server requires a password</p>
                </div>
              </div>
              <input
                type="password"
                value={serverPass}
                onChange={e => setServerPass(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handlePasswordSubmit()}
                placeholder="Enter server password"
                className="mb-4 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-white placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500/20"
                autoFocus
                disabled={loading}
              />
              <button
                onClick={handlePasswordSubmit}
                disabled={loading || !serverPass.trim()}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-indigo-500 to-purple-600 py-3 font-semibold text-white shadow-lg transition active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-5 w-5 animate-spin" /> Verifying...
                  </>
                ) : (
                  <>
                    Verify <ArrowRight className="h-5 w-5" />
                  </>
                )}
              </button>
            </>
          )}

          {step === 'captcha' && requiresCaptcha && (
            <>
              <div className="mb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-green-500/10">
                  <ShieldCheck className="h-5 w-5 text-green-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-white">Security Check</h3>
                  <p className="text-xs text-gray-400">Please complete the CAPTCHA</p>
                </div>
              </div>
              
              {captchaError && (
                <div className="mb-4 rounded-xl border border-red-500/30 bg-red-500/10 p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-red-400">{captchaError}</p>
                  </div>
                  <button
                    onClick={handleRetry}
                    className="mt-3 flex items-center gap-2 text-sm text-indigo-400 hover:text-indigo-300"
                  >
                    <RefreshCw className="h-4 w-4" /> Try Again
                  </button>
                </div>
              )}
              
              <div className="relative flex flex-col items-center justify-center min-h-[120px]">
                {captchaLoading && (
                  <div className="absolute inset-0 flex items-center justify-center bg-gray-900/80 rounded-xl z-10">
                    <div className="flex items-center gap-2 text-gray-400">
                      <Loader2 className="h-5 w-5 animate-spin" />
                      <span>Verifying...</span>
                    </div>
                  </div>
                )}
                
                {turnstileSiteKey && (
                  <div className={captchaLoading ? 'opacity-50 pointer-events-none' : ''}>
                    <Turnstile
                      ref={turnstileRef}
                      siteKey={turnstileSiteKey}
                      onSuccess={handleTurnstileSuccess}
                      onError={handleTurnstileError}
                      onExpire={handleTurnstileExpire}
                      options={{
                        theme: 'dark',
                        size: 'normal',
                      }}
                    />
                  </div>
                )}
                
                {!turnstileSiteKey && !captchaError && (
                  <div className="flex items-center gap-2 text-gray-400">
                    <Loader2 className="h-5 w-5 animate-spin" />
                    <span>Loading CAPTCHA...</span>
                  </div>
                )}
              </div>
              
              <p className="mt-4 text-center text-xs text-gray-500">
                Protected by Cloudflare Turnstile
              </p>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
