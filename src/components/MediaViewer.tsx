import React, { useState, useRef, useEffect, useCallback } from 'react';
import { X, Download, Play, Pause, Volume2, VolumeX, Maximize, Minimize, SkipBack, SkipForward, ChevronLeft, ChevronRight, ZoomIn, ZoomOut, RotateCw, RefreshCw } from 'lucide-react';
import { useStore } from '../store';

interface MediaViewerProps {
  type: 'image' | 'video' | 'audio';
  src: string;
  fileName: string;
  onClose: () => void;
  // For gallery mode (multiple images)
  gallery?: { src: string; fileName: string }[];
  initialIndex?: number;
}

export const MediaViewer: React.FC<MediaViewerProps> = ({
  type,
  src,
  fileName,
  onClose,
  gallery,
  initialIndex = 0,
}) => {
  const { serverUrl, authToken } = useStore();
  const [isPlaying, setIsPlaying] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(1);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  
  // Image specific
  const [zoom, setZoom] = useState(1);
  const [rotation, setRotation] = useState(0);
  const [currentIndex, setCurrentIndex] = useState(initialIndex);
  
  const mediaRef = useRef<HTMLVideoElement | HTMLAudioElement | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const currentSrc = gallery ? gallery[currentIndex].src : src;
  const currentFileName = gallery ? gallery[currentIndex].fileName : fileName;

  // Fetch media as blob to handle encrypted files
  const fetchMedia = useCallback(async (mediaUrl: string) => {
    setIsLoading(true);
    setError(null);
    
    // Clean up previous blob URL
    if (blobUrl) {
      URL.revokeObjectURL(blobUrl);
      setBlobUrl(null);
    }

    try {
      let fetchUrl = mediaUrl;
      const headers: Record<string, string> = {};
      
      // Handle API file URLs
      if (mediaUrl.startsWith('/api/files/') || mediaUrl.startsWith('/uploads/')) {
        const baseUrl = serverUrl.replace(/\/$/, '');
        fetchUrl = `${baseUrl}${mediaUrl}`;
      }
      
      // Add auth token
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response = await fetch(fetchUrl, { headers });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const blob = await response.blob();
      
      // Determine correct MIME type
      let mimeType = blob.type;
      if (!mimeType || mimeType === 'application/octet-stream') {
        // Infer from file extension
        const ext = currentFileName.split('.').pop()?.toLowerCase();
        const mimeTypes: Record<string, string> = {
          // Images
          'jpg': 'image/jpeg',
          'jpeg': 'image/jpeg',
          'png': 'image/png',
          'gif': 'image/gif',
          'webp': 'image/webp',
          'svg': 'image/svg+xml',
          'bmp': 'image/bmp',
          'ico': 'image/x-icon',
          // Videos
          'mp4': 'video/mp4',
          'webm': 'video/webm',
          'ogg': 'video/ogg',
          'mov': 'video/quicktime',
          'avi': 'video/x-msvideo',
          'mkv': 'video/x-matroska',
          // Audio
          'mp3': 'audio/mpeg',
          'wav': 'audio/wav',
          'flac': 'audio/flac',
          'm4a': 'audio/mp4',
          'aac': 'audio/aac',
          'oga': 'audio/ogg',
        };
        mimeType = mimeTypes[ext || ''] || blob.type;
      }

      // Create new blob with correct MIME type
      const typedBlob = new Blob([blob], { type: mimeType });
      const url = URL.createObjectURL(typedBlob);
      setBlobUrl(url);
      setIsLoading(false);
    } catch (err) {
      console.error('Failed to load media:', err);
      setError(err instanceof Error ? err.message : 'Failed to load media');
      setIsLoading(false);
    }
  }, [serverUrl, authToken, currentFileName, blobUrl]);

  // Fetch media when source changes
  useEffect(() => {
    fetchMedia(currentSrc);
    
    return () => {
      if (blobUrl) {
        URL.revokeObjectURL(blobUrl);
      }
    };
  }, [currentSrc]); // eslint-disable-line react-hooks/exhaustive-deps

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      switch (e.key) {
        case 'Escape':
          onClose();
          break;
        case ' ':
          if (type !== 'image') {
            e.preventDefault();
            togglePlay();
          }
          break;
        case 'ArrowLeft':
          if (gallery && currentIndex > 0) {
            setCurrentIndex(currentIndex - 1);
            resetImageState();
          } else if (type !== 'image' && mediaRef.current) {
            mediaRef.current.currentTime -= 5;
          }
          break;
        case 'ArrowRight':
          if (gallery && currentIndex < gallery.length - 1) {
            setCurrentIndex(currentIndex + 1);
            resetImageState();
          } else if (type !== 'image' && mediaRef.current) {
            mediaRef.current.currentTime += 5;
          }
          break;
        case 'ArrowUp':
          if (type !== 'image') {
            setVolume(Math.min(1, volume + 0.1));
          } else {
            setZoom(Math.min(5, zoom + 0.25));
          }
          break;
        case 'ArrowDown':
          if (type !== 'image') {
            setVolume(Math.max(0, volume - 0.1));
          } else {
            setZoom(Math.max(0.25, zoom - 0.25));
          }
          break;
        case 'm':
          if (type !== 'image') setIsMuted(!isMuted);
          break;
        case 'f':
          toggleFullscreen();
          break;
        case 'r':
          if (type === 'image') setRotation((rotation + 90) % 360);
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [type, gallery, currentIndex, volume, zoom, rotation, isMuted, onClose]);

  // Update media volume
  useEffect(() => {
    if (mediaRef.current) {
      mediaRef.current.volume = volume;
      mediaRef.current.muted = isMuted;
    }
  }, [volume, isMuted]);

  const resetImageState = () => {
    setZoom(1);
    setRotation(0);
    setIsLoading(true);
    setError(null);
  };

  const togglePlay = () => {
    if (mediaRef.current) {
      if (isPlaying) {
        mediaRef.current.pause();
      } else {
        mediaRef.current.play().catch(console.error);
      }
      setIsPlaying(!isPlaying);
    }
  };

  const toggleFullscreen = () => {
    if (!document.fullscreenElement && containerRef.current) {
      containerRef.current.requestFullscreen().catch(console.error);
      setIsFullscreen(true);
    } else if (document.fullscreenElement) {
      document.exitFullscreen().catch(console.error);
      setIsFullscreen(false);
    }
  };

  const handleTimeUpdate = () => {
    if (mediaRef.current) {
      setCurrentTime(mediaRef.current.currentTime);
    }
  };

  const handleLoadedMetadata = () => {
    if (mediaRef.current) {
      setDuration(mediaRef.current.duration);
    }
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    const time = parseFloat(e.target.value);
    if (mediaRef.current) {
      mediaRef.current.currentTime = time;
      setCurrentTime(time);
    }
  };

  const formatTime = (seconds: number) => {
    if (!isFinite(seconds)) return '0:00';
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const handleDownload = async () => {
    try {
      let fetchUrl = currentSrc;
      const headers: Record<string, string> = {};
      
      if (currentSrc.startsWith('/api/files/') || currentSrc.startsWith('/uploads/')) {
        const baseUrl = serverUrl.replace(/\/$/, '');
        // Use download endpoint
        const fileId = currentSrc.split('/').pop()?.split('?')[0];
        fetchUrl = `${baseUrl}/api/files/${fileId}/download`;
      }
      
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }

      const response = await fetch(fetchUrl, { headers });
      
      if (!response.ok) {
        throw new Error('Download failed');
      }
      
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = currentFileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download failed:', err);
      alert('Download failed. Please try again.');
    }
  };

  const handleMediaEnded = () => {
    setIsPlaying(false);
    if (mediaRef.current) {
      mediaRef.current.currentTime = 0;
    }
  };

  const handleRetry = () => {
    fetchMedia(currentSrc);
  };

  return (
    <div 
      ref={containerRef}
      className="fixed inset-0 z-50 bg-black/95 flex flex-col"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      {/* Header */}
      <div className="flex items-center justify-between p-4 bg-gradient-to-b from-black/80 to-transparent">
        <div className="flex items-center gap-3">
          <h3 className="text-white font-medium truncate max-w-xs sm:max-w-md">
            {currentFileName}
          </h3>
          {gallery && (
            <span className="text-gray-400 text-sm">
              {currentIndex + 1} / {gallery.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownload}
            className="p-2 text-white/80 hover:text-white hover:bg-white/10 rounded-full transition-colors"
            title="Download"
          >
            <Download size={20} />
          </button>
          <button
            onClick={onClose}
            className="p-2 text-white/80 hover:text-white hover:bg-white/10 rounded-full transition-colors"
            title="Close (Esc)"
          >
            <X size={20} />
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 flex items-center justify-center relative overflow-hidden">
        {isLoading && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-12 h-12 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {error && (
          <div className="text-red-400 text-center p-4">
            <p className="text-lg font-medium">Failed to load media</p>
            <p className="text-sm mt-2 text-gray-400">{error}</p>
            <button
              onClick={handleRetry}
              className="mt-4 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg flex items-center gap-2 mx-auto transition-colors"
            >
              <RefreshCw size={16} />
              Retry
            </button>
          </div>
        )}

        {/* Image Viewer */}
        {type === 'image' && blobUrl && !error && (
          <>
            <img
              src={blobUrl}
              alt={currentFileName}
              className="max-h-full max-w-full object-contain transition-transform duration-200"
              style={{
                transform: `scale(${zoom}) rotate(${rotation}deg)`,
                opacity: isLoading ? 0 : 1,
              }}
              onLoad={() => setIsLoading(false)}
              onError={() => {
                setIsLoading(false);
                setError('Failed to display image');
              }}
              draggable={false}
            />

            {/* Gallery navigation */}
            {gallery && gallery.length > 1 && (
              <>
                <button
                  onClick={() => {
                    if (currentIndex > 0) {
                      setCurrentIndex(currentIndex - 1);
                      resetImageState();
                    }
                  }}
                  disabled={currentIndex === 0}
                  className="absolute left-4 p-3 bg-black/50 hover:bg-black/70 text-white rounded-full disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronLeft size={24} />
                </button>
                <button
                  onClick={() => {
                    if (currentIndex < gallery.length - 1) {
                      setCurrentIndex(currentIndex + 1);
                      resetImageState();
                    }
                  }}
                  disabled={currentIndex === gallery.length - 1}
                  className="absolute right-4 p-3 bg-black/50 hover:bg-black/70 text-white rounded-full disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                >
                  <ChevronRight size={24} />
                </button>
              </>
            )}

            {/* Image controls */}
            <div className="absolute bottom-20 left-1/2 -translate-x-1/2 flex items-center gap-2 bg-black/70 rounded-full px-4 py-2">
              <button
                onClick={() => setZoom(Math.max(0.25, zoom - 0.25))}
                className="p-2 text-white/80 hover:text-white hover:bg-white/10 rounded-full transition-colors"
                title="Zoom out"
              >
                <ZoomOut size={18} />
              </button>
              <span className="text-white text-sm min-w-[50px] text-center">
                {Math.round(zoom * 100)}%
              </span>
              <button
                onClick={() => setZoom(Math.min(5, zoom + 0.25))}
                className="p-2 text-white/80 hover:text-white hover:bg-white/10 rounded-full transition-colors"
                title="Zoom in"
              >
                <ZoomIn size={18} />
              </button>
              <div className="w-px h-6 bg-white/30 mx-2" />
              <button
                onClick={() => setRotation((rotation + 90) % 360)}
                className="p-2 text-white/80 hover:text-white hover:bg-white/10 rounded-full transition-colors"
                title="Rotate (R)"
              >
                <RotateCw size={18} />
              </button>
              <button
                onClick={toggleFullscreen}
                className="p-2 text-white/80 hover:text-white hover:bg-white/10 rounded-full transition-colors"
                title="Fullscreen (F)"
              >
                {isFullscreen ? <Minimize size={18} /> : <Maximize size={18} />}
              </button>
            </div>
          </>
        )}

        {/* Video Viewer */}
        {type === 'video' && blobUrl && !error && (
          <video
            ref={mediaRef as React.RefObject<HTMLVideoElement>}
            src={blobUrl}
            className="max-h-full max-w-full"
            onTimeUpdate={handleTimeUpdate}
            onLoadedMetadata={handleLoadedMetadata}
            onEnded={handleMediaEnded}
            onPlay={() => setIsPlaying(true)}
            onPause={() => setIsPlaying(false)}
            onCanPlay={() => setIsLoading(false)}
            onError={() => {
              setIsLoading(false);
              setError('Failed to play video');
            }}
            onClick={togglePlay}
            playsInline
          />
        )}

        {/* Audio Viewer */}
        {type === 'audio' && blobUrl && !error && (
          <div className="flex flex-col items-center gap-8 p-8">
            {/* Album art placeholder */}
            <div className="w-64 h-64 bg-gradient-to-br from-indigo-600 to-purple-700 rounded-2xl flex items-center justify-center shadow-2xl">
              <div className="text-white text-6xl">🎵</div>
            </div>
            
            <audio
              ref={mediaRef as React.RefObject<HTMLAudioElement>}
              src={blobUrl}
              onTimeUpdate={handleTimeUpdate}
              onLoadedMetadata={handleLoadedMetadata}
              onEnded={handleMediaEnded}
              onPlay={() => setIsPlaying(true)}
              onPause={() => setIsPlaying(false)}
              onCanPlay={() => setIsLoading(false)}
              onError={() => {
                setIsLoading(false);
                setError('Failed to play audio');
              }}
            />

            <div className="text-center">
              <h2 className="text-white text-xl font-semibold">{currentFileName}</h2>
              <p className="text-gray-400 text-sm mt-1">
                {formatTime(currentTime)} / {formatTime(duration)}
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Video/Audio Controls */}
      {(type === 'video' || type === 'audio') && blobUrl && !error && (
        <div className="p-4 bg-gradient-to-t from-black/80 to-transparent">
          {/* Progress bar */}
          <div className="flex items-center gap-3 mb-3">
            <span className="text-white/70 text-xs min-w-[40px]">
              {formatTime(currentTime)}
            </span>
            <input
              type="range"
              min={0}
              max={duration || 100}
              value={currentTime}
              onChange={handleSeek}
              className="flex-1 h-1 bg-white/30 rounded-full appearance-none cursor-pointer
                [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 
                [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-indigo-500
                [&::-webkit-slider-thumb]:hover:bg-indigo-400 [&::-webkit-slider-thumb]:transition-colors"
            />
            <span className="text-white/70 text-xs min-w-[40px] text-right">
              {formatTime(duration)}
            </span>
          </div>

          {/* Control buttons */}
          <div className="flex items-center justify-center gap-4">
            <button
              onClick={() => mediaRef.current && (mediaRef.current.currentTime -= 10)}
              className="p-2 text-white/70 hover:text-white transition-colors"
              title="Rewind 10s"
            >
              <SkipBack size={20} />
            </button>
            
            <button
              onClick={togglePlay}
              className="p-4 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full transition-colors"
              title={isPlaying ? 'Pause' : 'Play'}
            >
              {isPlaying ? <Pause size={24} /> : <Play size={24} className="ml-1" />}
            </button>
            
            <button
              onClick={() => mediaRef.current && (mediaRef.current.currentTime += 10)}
              className="p-2 text-white/70 hover:text-white transition-colors"
              title="Forward 10s"
            >
              <SkipForward size={20} />
            </button>

            <div className="flex items-center gap-2 ml-4">
              <button
                onClick={() => setIsMuted(!isMuted)}
                className="p-2 text-white/70 hover:text-white transition-colors"
                title={isMuted ? 'Unmute' : 'Mute'}
              >
                {isMuted ? <VolumeX size={20} /> : <Volume2 size={20} />}
              </button>
              <input
                type="range"
                min={0}
                max={1}
                step={0.1}
                value={isMuted ? 0 : volume}
                onChange={(e) => {
                  setVolume(parseFloat(e.target.value));
                  setIsMuted(false);
                }}
                className="w-20 h-1 bg-white/30 rounded-full appearance-none cursor-pointer
                  [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 
                  [&::-webkit-slider-thumb]:rounded-full [&::-webkit-slider-thumb]:bg-white"
              />
            </div>

            {type === 'video' && (
              <button
                onClick={toggleFullscreen}
                className="p-2 text-white/70 hover:text-white transition-colors ml-4"
                title="Fullscreen (F)"
              >
                {isFullscreen ? <Minimize size={20} /> : <Maximize size={20} />}
              </button>
            )}
          </div>
        </div>
      )}

      {/* Keyboard shortcuts hint */}
      <div className="absolute bottom-4 left-4 text-white/40 text-xs hidden sm:block">
        {type === 'image' && 'Shortcuts: ←→ Navigate • ↑↓ Zoom • R Rotate • F Fullscreen • Esc Close'}
        {type === 'video' && 'Shortcuts: Space Play/Pause • ←→ Seek • M Mute • F Fullscreen • Esc Close'}
        {type === 'audio' && 'Shortcuts: Space Play/Pause • ←→ Seek • M Mute • Esc Close'}
      </div>
    </div>
  );
};

export default MediaViewer;
