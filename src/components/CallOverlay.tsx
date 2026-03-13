import { useState, useEffect, useRef, useCallback } from 'react';
import { Phone, PhoneOff, Video, VideoOff, Mic, MicOff, X, RefreshCw } from 'lucide-react';
import { useStore } from '../store';

// Multiple public STUN servers for better NAT traversal
const ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
  { urls: 'stun:stun3.l.google.com:19302' },
  { urls: 'stun:stun4.l.google.com:19302' },
  { urls: 'stun:stun.stunprotocol.org:3478' },
  { urls: 'stun:stun.voip.blackberry.com:3478' },
  { urls: 'stun:stun.nextcloud.com:443' },
];

interface IncomingCallData {
  from: string;
  type: 'voice' | 'video';
  offer?: RTCSessionDescriptionInit;
}

export function CallOverlay() {
  const { 
    currentUser, 
    users, 
    chats,
    callState, 
    endCall,
    beginCall,
    websocket
  } = useStore();
  
  const [isMuted, setIsMuted] = useState(false);
  const [isVideoOff, setIsVideoOff] = useState(false);
  const [callDuration, setCallDuration] = useState(0);
  const [callStatus, setCallStatus] = useState<'connecting' | 'ringing' | 'connected' | 'failed' | 'ended'>('connecting');
  const [incomingCall, setIncomingCall] = useState<IncomingCallData | null>(null);
  const [connectionInfo, setConnectionInfo] = useState<string>('');
  
  const localVideoRef = useRef<HTMLVideoElement>(null);
  const remoteVideoRef = useRef<HTMLVideoElement>(null);
  const peerConnectionRef = useRef<RTCPeerConnection | null>(null);
  const localStreamRef = useRef<MediaStream | null>(null);
  const pendingCandidatesRef = useRef<RTCIceCandidateInit[]>([]);
  const isInitiatorRef = useRef(false);
  const callStartTimeRef = useRef<number>(0);
  const incomingAcceptedRef = useRef(false);

  const chat = callState.chatId ? chats.find(c => c.id === callState.chatId) : null;
  const otherUserId = chat?.type === 'direct' 
    ? chat.participants.find(p => p !== currentUser?.id) 
    : null;
  const otherUser = otherUserId ? users.find(u => u.id === otherUserId) : null;
  const signalingTargetUserId = incomingCall?.from || otherUserId;

  // Cleanup function
  const cleanup = useCallback(() => {
    console.log('[Call] Cleaning up...');
    incomingAcceptedRef.current = false;
    
    if (localStreamRef.current) {
      localStreamRef.current.getTracks().forEach(track => {
        track.stop();
        console.log('[Call] Stopped track:', track.kind);
      });
      localStreamRef.current = null;
    }

    if (peerConnectionRef.current) {
      peerConnectionRef.current.close();
      peerConnectionRef.current = null;
    }

    pendingCandidatesRef.current = [];
  }, []);

  // Create peer connection with proper configuration
  const createPeerConnection = useCallback(() => {
    console.log('[Call] Creating peer connection with STUN servers');
    
    const pc = new RTCPeerConnection({
      iceServers: ICE_SERVERS,
      iceCandidatePoolSize: 10,
    });

    // Log ICE connection state changes
    pc.oniceconnectionstatechange = () => {
      console.log('[Call] ICE connection state:', pc.iceConnectionState);
      setConnectionInfo(`ICE: ${pc.iceConnectionState}`);
      
      if (pc.iceConnectionState === 'connected' || pc.iceConnectionState === 'completed') {
        setCallStatus('connected');
        if (callStartTimeRef.current === 0) {
          callStartTimeRef.current = Date.now();
        }
      } else if (pc.iceConnectionState === 'failed') {
        console.log('[Call] ICE connection failed, attempting restart...');
        // Try ICE restart
        pc.restartIce();
      } else if (pc.iceConnectionState === 'disconnected') {
        setConnectionInfo('Reconnecting...');
      }
    };

    // Log ICE gathering state
    pc.onicegatheringstatechange = () => {
      console.log('[Call] ICE gathering state:', pc.iceGatheringState);
    };

    // Log signaling state
    pc.onsignalingstatechange = () => {
      console.log('[Call] Signaling state:', pc.signalingState);
    };

    // Handle connection state
    pc.onconnectionstatechange = () => {
      console.log('[Call] Connection state:', pc.connectionState);
      
      if (pc.connectionState === 'connected') {
        setCallStatus('connected');
      } else if (pc.connectionState === 'failed') {
        setCallStatus('failed');
      } else if (pc.connectionState === 'disconnected') {
        // Give it a moment to reconnect
        setTimeout(() => {
          if (peerConnectionRef.current?.connectionState === 'disconnected') {
            setCallStatus('failed');
          }
        }, 5000);
      }
    };

    // Handle incoming tracks (remote stream)
    pc.ontrack = (event) => {
      console.log('[Call] Received remote track:', event.track.kind);
      
      if (remoteVideoRef.current && event.streams[0]) {
        remoteVideoRef.current.srcObject = event.streams[0];
        setCallStatus('connected');
      }
    };

    // Handle ICE candidates - send to peer via signaling server
    pc.onicecandidate = (event) => {
      if (event.candidate) {
        console.log('[Call] Got ICE candidate:', event.candidate.candidate.substring(0, 50) + '...');
        
        if (websocket?.readyState === WebSocket.OPEN && signalingTargetUserId) {
          websocket.send(JSON.stringify({
            type: 'call_ice_candidate',
            targetUserId: signalingTargetUserId,
            candidate: event.candidate.toJSON()
          }));
        }
      } else {
        console.log('[Call] ICE gathering completed');
      }
    };

    return pc;
  }, [websocket, signalingTargetUserId]);

  // Add pending ICE candidates
  const addPendingCandidates = useCallback(async (pc: RTCPeerConnection) => {
    if (pendingCandidatesRef.current.length > 0 && pc.remoteDescription) {
      console.log('[Call] Adding', pendingCandidatesRef.current.length, 'pending ICE candidates');
      
      for (const candidate of pendingCandidatesRef.current) {
        try {
          await pc.addIceCandidate(new RTCIceCandidate(candidate));
        } catch (e) {
          console.warn('[Call] Failed to add pending candidate:', e);
        }
      }
      pendingCandidatesRef.current = [];
    }
  }, []);

  // Initialize outgoing call
  const initOutgoingCall = useCallback(async () => {
    if (!websocket || !otherUserId || !currentUser) return;
    
    console.log('[Call] Initializing outgoing call to:', otherUserId);
    isInitiatorRef.current = true;
    setCallStatus('ringing');

    try {
      // Get local media stream
      const stream = await navigator.mediaDevices.getUserMedia({
        video: callState.type === 'video',
        audio: true
      });
      
      localStreamRef.current = stream;
      
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }

      // Create peer connection
      const pc = createPeerConnection();
      peerConnectionRef.current = pc;

      // Add local tracks to connection
      stream.getTracks().forEach(track => {
        console.log('[Call] Adding local track:', track.kind);
        pc.addTrack(track, stream);
      });

      // Create offer with ICE restart capability
      const offer = await pc.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: callState.type === 'video',
        iceRestart: false
      });
      
      await pc.setLocalDescription(offer);
      console.log('[Call] Created and set local offer');

      // Send offer to peer
      websocket.send(JSON.stringify({
        type: 'call_offer',
        targetUserId: otherUserId,
        offer: pc.localDescription,
        callType: callState.type
      }));

    } catch (error) {
      console.error('[Call] Failed to initialize call:', error);
      setCallStatus('failed');
    }
  }, [websocket, otherUserId, currentUser, callState.type, createPeerConnection]);

  // Handle incoming call answer
  const handleAnswer = useCallback(async (answer: RTCSessionDescriptionInit) => {
    const pc = peerConnectionRef.current;
    if (!pc) {
      console.error('[Call] No peer connection for answer');
      return;
    }

    try {
      console.log('[Call] Received answer, setting remote description');
      await pc.setRemoteDescription(new RTCSessionDescription(answer));
      await addPendingCandidates(pc);
      setCallStatus('connected');
    } catch (error) {
      console.error('[Call] Failed to set remote description:', error);
      setCallStatus('failed');
    }
  }, [addPendingCandidates]);

  // Answer incoming call
  const handleAnswerCall = useCallback(async () => {
    if (!incomingCall || !websocket || !incomingCall.offer) {
      console.error('[Call] Missing data to answer call');
      return;
    }

    console.log('[Call] Answering incoming call');
    isInitiatorRef.current = false;
    incomingAcceptedRef.current = true;
    setCallStatus('connecting');

    try {
      // Ensure call overlay stays mounted after accepting by activating callState for callee
      if (currentUser?.id) {
        const directChat = chats.find(c => 
          c.type === 'direct' && c.participants.includes(currentUser.id) && c.participants.includes(incomingCall.from)
        );
        beginCall(directChat?.id || null, incomingCall.type, [currentUser.id, incomingCall.from]);
      }

      // Get local media stream
      const stream = await navigator.mediaDevices.getUserMedia({
        video: incomingCall.type === 'video',
        audio: true
      });
      
      localStreamRef.current = stream;
      
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
      }

      // Create peer connection
      const pc = createPeerConnection();
      peerConnectionRef.current = pc;

      // Add local tracks
      stream.getTracks().forEach(track => {
        console.log('[Call] Adding local track:', track.kind);
        pc.addTrack(track, stream);
      });

      // Set remote description (the offer)
      await pc.setRemoteDescription(new RTCSessionDescription(incomingCall.offer));
      console.log('[Call] Set remote offer');

      // Add any pending ICE candidates
      await addPendingCandidates(pc);

      // Create answer
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      console.log('[Call] Created and set local answer');

      // Send answer to caller
      websocket.send(JSON.stringify({
        type: 'call_answer',
        targetUserId: incomingCall.from,
        answer: pc.localDescription
      }));

      setIncomingCall(null);

    } catch (error) {
      console.error('[Call] Failed to answer call:', error);
      setCallStatus('failed');
      setIncomingCall(null);
    }
  }, [incomingCall, websocket, createPeerConnection, addPendingCandidates]);

  // Reject incoming call
  const handleRejectCall = useCallback(() => {
    if (websocket?.readyState === WebSocket.OPEN && incomingCall) {
      websocket.send(JSON.stringify({
        type: 'call_reject',
        targetUserId: incomingCall.from
      }));
    }
    setIncomingCall(null);
    cleanup();
  }, [websocket, incomingCall, cleanup]);

  // End call
  const handleEndCall = useCallback(() => {
    console.log('[Call] Ending call');
    
    if (websocket?.readyState === WebSocket.OPEN && signalingTargetUserId) {
      websocket.send(JSON.stringify({
        type: 'call_end',
        targetUserId: signalingTargetUserId
      }));
    }

    cleanup();
    setCallStatus('ended');
    endCall();
  }, [websocket, signalingTargetUserId, cleanup, endCall]);

  // Toggle mute
  const toggleMute = useCallback(() => {
    if (localStreamRef.current) {
      localStreamRef.current.getAudioTracks().forEach(track => {
        track.enabled = isMuted;
      });
      setIsMuted(!isMuted);
    }
  }, [isMuted]);

  // Toggle video
  const toggleVideo = useCallback(() => {
    if (localStreamRef.current) {
      localStreamRef.current.getVideoTracks().forEach(track => {
        track.enabled = isVideoOff;
      });
      setIsVideoOff(!isVideoOff);
    }
  }, [isVideoOff]);

  // Retry connection
  const retryConnection = useCallback(async () => {
    console.log('[Call] Retrying connection...');
    cleanup();
    setCallStatus('connecting');
    setCallDuration(0);
    callStartTimeRef.current = 0;
    
    setTimeout(() => {
      initOutgoingCall();
    }, 500);
  }, [cleanup, initOutgoingCall]);

  // Initialize call on mount
  useEffect(() => {
    // Only auto-start signaling for outgoing calls.
    // For incoming calls, we accept and create the peer connection in `handleAnswerCall`.
    if (callState.active && !incomingCall && !incomingAcceptedRef.current) {
      initOutgoingCall();
    }

    return () => {
      cleanup();
    };
  }, [callState.active]);

  // Handle WebSocket messages for call signaling
  useEffect(() => {
    if (!websocket) return;

    const handleMessage = async (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'incoming_call': {
            console.log('[Call] Incoming call from:', data.fromUserId);
            setIncomingCall({
              from: data.fromUserId,
              type: data.callType || 'voice',
              offer: data.offer
            });
            break;
          }
          
          case 'call_answer': {
            console.log('[Call] Received call answer');
            if (data.answer) {
              await handleAnswer(data.answer);
            }
            break;
          }
          
          case 'call_ice_candidate': {
            console.log('[Call] Received ICE candidate');
            const pc = peerConnectionRef.current;
            
            if (data.candidate) {
              if (pc && pc.remoteDescription) {
                try {
                  await pc.addIceCandidate(new RTCIceCandidate(data.candidate));
                } catch (e) {
                  console.warn('[Call] Failed to add ICE candidate:', e);
                }
              } else {
                // Queue candidate if remote description not set yet
                console.log('[Call] Queuing ICE candidate');
                pendingCandidatesRef.current.push(data.candidate);
              }
            }
            break;
          }
          
          case 'call_reject': {
            console.log('[Call] Call rejected');
            cleanup();
            setCallStatus('ended');
            endCall();
            break;
          }
          
          case 'call_end': {
            console.log('[Call] Call ended by peer');
            cleanup();
            setCallStatus('ended');
            endCall();
            break;
          }
        }
      } catch (error) {
        console.error('[Call] Error handling message:', error);
      }
    };

    websocket.addEventListener('message', handleMessage);
    return () => {
      websocket.removeEventListener('message', handleMessage);
    };
  }, [websocket, handleAnswer, cleanup, endCall]);

  // Call duration timer
  useEffect(() => {
    if (callStatus !== 'connected') return;
    
    const interval = setInterval(() => {
      if (callStartTimeRef.current > 0) {
        setCallDuration(Math.floor((Date.now() - callStartTimeRef.current) / 1000));
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [callStatus]);

  // Format duration as MM:SS
  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  if (!callState.active && !incomingCall) return null;

  // Incoming call UI
  if (incomingCall) {
    const caller = users.find(u => u.id === incomingCall.from);
    return (
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/95 backdrop-blur-xl animate-fadeIn">
        <div className="text-center p-8">
          {/* Animated rings */}
          <div className="relative mx-auto w-40 h-40 mb-8">
            <div className="absolute inset-0 rounded-full border-4 border-green-500/30 animate-ping" />
            <div className="absolute inset-2 rounded-full border-4 border-green-500/20 animate-ping" style={{ animationDelay: '0.2s' }} />
            <div className="absolute inset-4 rounded-full border-4 border-green-500/10 animate-ping" style={{ animationDelay: '0.4s' }} />
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="h-28 w-28 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-4xl font-bold text-white shadow-2xl shadow-indigo-500/30">
                {caller?.avatar ? (
                  <img src={caller.avatar} alt="" className="h-full w-full rounded-full object-cover" />
                ) : (
                  caller?.username?.[0]?.toUpperCase() || '?'
                )}
              </div>
            </div>
          </div>
          
          <h2 className="text-3xl font-bold text-white mb-2">
            {caller?.displayName || caller?.username || `Caller (${caller?.id?.slice(0,8)})`}
          </h2>
          <p className="text-gray-400 text-lg mb-10">
            Incoming {incomingCall.type === 'video' ? 'video' : 'voice'} call...
          </p>
          
          <div className="flex items-center justify-center gap-8">
            <button
              onClick={handleRejectCall}
              className="group relative h-20 w-20 rounded-full bg-red-500 flex items-center justify-center text-white shadow-lg shadow-red-500/40 hover:bg-red-600 hover:scale-110 transition-all duration-200"
            >
              <PhoneOff className="h-8 w-8" />
              <span className="absolute -bottom-8 text-sm text-gray-400 opacity-0 group-hover:opacity-100 transition">Decline</span>
            </button>
            <button
              onClick={handleAnswerCall}
              className="group relative h-20 w-20 rounded-full bg-green-500 flex items-center justify-center text-white shadow-lg shadow-green-500/40 hover:bg-green-600 hover:scale-110 transition-all duration-200 animate-pulse"
            >
              <Phone className="h-8 w-8" />
              <span className="absolute -bottom-8 text-sm text-gray-400 opacity-0 group-hover:opacity-100 transition">Accept</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Active call UI
  return (
    <div className="fixed inset-0 z-[100] flex flex-col bg-gray-950 animate-fadeIn">
      {/* Remote video / Avatar */}
      <div className="flex-1 relative bg-black flex items-center justify-center overflow-hidden">
        {callState.type === 'video' && callStatus === 'connected' ? (
          <video
            ref={remoteVideoRef}
            autoPlay
            playsInline
            className="h-full w-full object-cover"
          />
        ) : (
          <div className="text-center">
            {/* Background gradient effect */}
            <div className="absolute inset-0 bg-gradient-to-b from-indigo-900/20 via-transparent to-purple-900/20" />
            
            <div className="relative">
              <div className={`mx-auto h-44 w-44 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-6xl font-bold text-white shadow-2xl ${
                callStatus === 'ringing' ? 'animate-pulse' : ''
              }`}>
                {otherUser?.avatar ? (
                  <img src={otherUser.avatar} alt="" className="h-full w-full rounded-full object-cover" />
                ) : (
                  otherUser?.username?.[0]?.toUpperCase() || '?'
                )}
              </div>
              
              {callStatus === 'connected' && (
                <div className="absolute -bottom-2 left-1/2 -translate-x-1/2 flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-green-500/20 border border-green-500/30">
                  <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                  <span className="text-green-400 text-sm font-medium">Connected</span>
                </div>
              )}
            </div>
            
            <h2 className="mt-8 text-3xl font-bold text-white">
              {otherUser?.displayName || otherUser?.username || `User (${otherUser?.id?.slice(0,8)})`}
            </h2>
            <p className="mt-3 text-xl text-gray-400">
              {callStatus === 'connecting' && (
                <span className="flex items-center justify-center gap-2">
                  <RefreshCw className="h-5 w-5 animate-spin" />
                  Connecting...
                </span>
              )}
              {callStatus === 'ringing' && 'Ringing...'}
              {callStatus === 'connected' && formatDuration(callDuration)}
              {callStatus === 'failed' && (
                <span className="text-red-400">Connection failed</span>
              )}
            </p>
            
            {/* Connection info for debugging */}
            {connectionInfo && callStatus !== 'connected' && (
              <p className="mt-2 text-sm text-gray-500">{connectionInfo}</p>
            )}
            
            {/* Retry button for failed calls */}
            {callStatus === 'failed' && (
              <button
                onClick={retryConnection}
                className="mt-6 px-6 py-3 rounded-full bg-indigo-500 text-white hover:bg-indigo-600 transition flex items-center gap-2 mx-auto"
              >
                <RefreshCw className="h-5 w-5" />
                Retry Connection
              </button>
            )}
          </div>
        )}

        {/* Local video (picture-in-picture) */}
        {callState.type === 'video' && (
          <div className="absolute bottom-4 right-4 w-32 h-24 md:w-48 md:h-36 rounded-xl overflow-hidden border-2 border-white/20 shadow-2xl bg-gray-900">
            <video
              ref={localVideoRef}
              autoPlay
              playsInline
              muted
              className={`h-full w-full object-cover ${isVideoOff ? 'hidden' : ''}`}
            />
            {isVideoOff && (
              <div className="h-full w-full bg-gray-800 flex items-center justify-center">
                <VideoOff className="h-8 w-8 text-gray-500" />
              </div>
            )}
          </div>
        )}

        {/* Close button */}
        <button
          onClick={handleEndCall}
          className="absolute top-4 right-4 p-3 rounded-full bg-white/10 text-white hover:bg-white/20 transition backdrop-blur"
        >
          <X className="h-6 w-6" />
        </button>

        {/* Call timer (top left when connected) */}
        {callStatus === 'connected' && (
          <div className="absolute top-4 left-4 px-4 py-2 rounded-full bg-black/50 backdrop-blur text-white text-sm font-medium flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
            {formatDuration(callDuration)}
          </div>
        )}
      </div>

      {/* Controls */}
      <div className="bg-gray-900/95 backdrop-blur py-8 border-t border-white/10">
        <div className="flex items-center justify-center gap-6">
          <button
            onClick={toggleMute}
            className={`h-16 w-16 rounded-full flex items-center justify-center transition-all duration-200 ${
              isMuted 
                ? 'bg-red-500 text-white shadow-lg shadow-red-500/30' 
                : 'bg-white/10 text-white hover:bg-white/20'
            }`}
          >
            {isMuted ? <MicOff className="h-7 w-7" /> : <Mic className="h-7 w-7" />}
          </button>

          {callState.type === 'video' && (
            <button
              onClick={toggleVideo}
              className={`h-16 w-16 rounded-full flex items-center justify-center transition-all duration-200 ${
                isVideoOff 
                  ? 'bg-red-500 text-white shadow-lg shadow-red-500/30' 
                  : 'bg-white/10 text-white hover:bg-white/20'
              }`}
            >
              {isVideoOff ? <VideoOff className="h-7 w-7" /> : <Video className="h-7 w-7" />}
            </button>
          )}

          <button
            onClick={handleEndCall}
            className="h-16 w-16 rounded-full bg-red-500 flex items-center justify-center text-white shadow-lg shadow-red-500/40 hover:bg-red-600 hover:scale-105 transition-all duration-200"
          >
            <PhoneOff className="h-7 w-7" />
          </button>
        </div>
      </div>
    </div>
  );
}
