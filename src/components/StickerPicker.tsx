import { useState, useEffect, useRef } from 'react';
import { X, Plus, Smile, Save, Image } from 'lucide-react';
import { useStore } from '../store';

interface Sticker {
  id: string;
  name: string;
  imageData: string;
  creatorId: string;
  createdAt: number;
}

interface StickerPickerProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectSticker: (sticker: Sticker) => void;
}

export function StickerPicker({ isOpen, onClose, onSelectSticker }: StickerPickerProps) {
  const { serverUrl, authToken, translate } = useStore();
  const [stickers, setStickers] = useState<Sticker[]>([]);
  const [loading, setLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newStickerName, setNewStickerName] = useState('');
  const [newStickerImage, setNewStickerImage] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      fetchStickers();
    }
  }, [isOpen]);

  const fetchStickers = async () => {
    setLoading(true);
    try {
      const response = await fetch(`${serverUrl}/api/stickers`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setStickers(data);
      }
    } catch (err) {
      console.error('Failed to fetch stickers:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleImageSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setError('Please select an image file');
      return;
    }

    if (file.size > 500000) {
      setError('Image must be smaller than 500KB');
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const result = event.target?.result as string;
      // Resize image to max 128x128 for stickers
      const img = new window.Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        const maxSize = 128;
        let width = img.width;
        let height = img.height;

        if (width > height) {
          if (width > maxSize) {
            height = (height * maxSize) / width;
            width = maxSize;
          }
        } else {
          if (height > maxSize) {
            width = (width * maxSize) / height;
            height = maxSize;
          }
        }

        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx?.drawImage(img, 0, 0, width, height);
        setNewStickerImage(canvas.toDataURL('image/png'));
        setError('');
      };
      img.src = result;
    };
    reader.readAsDataURL(file);
  };

  const handleCreateSticker = async () => {
    if (!newStickerName.trim() || !newStickerImage) {
      setError('Please provide a name and image');
      return;
    }

    setCreating(true);
    setError('');

    try {
      const response = await fetch(`${serverUrl}/api/stickers`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          name: newStickerName.trim(),
          imageData: newStickerImage,
        }),
      });

      if (response.ok) {
        const newSticker = await response.json();
        setStickers([newSticker, ...stickers]);
        setShowCreateModal(false);
        setNewStickerName('');
        setNewStickerImage(null);
      } else {
        const data = await response.json();
        setError(data.error || 'Failed to create sticker');
      }
    } catch (err) {
      setError('Failed to create sticker');
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteSticker = async (stickerId: string) => {
    try {
      const response = await fetch(`${serverUrl}/api/stickers/${stickerId}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${authToken}` },
      });

      if (response.ok) {
        setStickers(stickers.filter((s) => s.id !== stickerId));
      }
    } catch (err) {
      console.error('Failed to delete sticker:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <>
      {/* Sticker Picker */}
      <div className="absolute bottom-full right-0 mb-2 w-72 sm:w-80 max-w-[calc(100vw-2rem)] bg-gray-800 rounded-xl shadow-xl border border-white/10 overflow-hidden z-50">
        {/* Header */}
        <div className="flex items-center justify-between p-3 border-b border-white/10">
          <div className="flex items-center gap-2">
            <Smile className="w-5 h-5 text-indigo-400" />
            <span className="font-medium text-white">{translate('stickers.title') || 'Stickers'}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowCreateModal(true)}
              className="p-1.5 hover:bg-white/10 rounded-lg transition-colors"
              title={translate('stickers.create') || 'Create Sticker'}
            >
              <Plus className="w-5 h-5 text-indigo-400" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-white/10 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-gray-400" />
            </button>
          </div>
        </div>

        {/* Stickers Grid */}
        <div className="p-3 h-48 sm:h-56 overflow-y-auto">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
            </div>
          ) : stickers.length === 0 ? (
            <div className="text-center py-8">
              <Smile className="w-12 h-12 text-gray-600 mx-auto mb-2" />
              <p className="text-gray-500 text-sm">{translate('stickers.empty') || 'No stickers yet'}</p>
              <button
                onClick={() => setShowCreateModal(true)}
                className="mt-2 text-indigo-400 text-sm hover:underline"
              >
                {translate('stickers.createFirst') || 'Create your first sticker'}
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-4 gap-2 auto-rows-min">
              {stickers.map((sticker) => (
                <div
                  key={sticker.id}
                  className="relative group"
                >
                  <button
                    onClick={() => {
                      onSelectSticker(sticker);
                      onClose();
                    }}
                    className="w-full aspect-square bg-white/5 rounded-lg p-1 hover:bg-white/10 transition-colors"
                  >
                    <img
                      src={sticker.imageData}
                      alt={sticker.name}
                      className="w-full h-full object-contain"
                    />
                  </button>
                  <button
                    onClick={() => handleDeleteSticker(sticker.id)}
                    className="absolute -top-1 -right-1 p-1 bg-red-500 rounded-full opacity-0 group-hover:opacity-100 transition-opacity"
                    title={translate('stickers.delete') || 'Remove sticker'}
                  >
                    <X className="w-3 h-3 text-white" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Create Sticker Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[60] p-4">
          <div className="bg-gray-800 rounded-xl p-4 sm:p-6 w-full max-w-sm mx-auto" style={{ marginTop: '-10vh' }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-white">
                {translate('stickers.createNew') || 'Create New Sticker'}
              </h3>
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setNewStickerName('');
                  setNewStickerImage(null);
                  setError('');
                }}
                className="p-1 hover:bg-white/10 rounded-lg"
              >
                <X className="w-5 h-5 text-gray-400" />
              </button>
            </div>

            {/* Image Upload */}
            <div className="mb-4">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleImageSelect}
                accept="image/*"
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="w-full aspect-square max-h-48 sm:max-h-56 border-2 border-dashed border-white/20 rounded-lg flex flex-col items-center justify-center hover:border-indigo-500 transition-colors overflow-hidden"
              >
                {newStickerImage ? (
                  <img
                    src={newStickerImage}
                    alt="Preview"
                    className="w-full h-full object-contain p-4"
                  />
                ) : (
                  <>
                    <Image className="w-12 h-12 text-gray-500 mb-2" />
                    <span className="text-gray-500 text-sm">
                      {translate('stickers.clickToUpload') || 'Click to upload image'}
                    </span>
                    <span className="text-gray-600 text-xs mt-1">Max 500KB</span>
                  </>
                )}
              </button>
            </div>

            {/* Name Input */}
            <div className="mb-4">
              <input
                type="text"
                value={newStickerName}
                onChange={(e) => setNewStickerName(e.target.value)}
                placeholder={translate('stickers.namePlaceholder') || 'Sticker name...'}
                className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-indigo-500"
                maxLength={32}
              />
            </div>

            {/* Error */}
            {error && (
              <p className="text-red-400 text-sm mb-4">{error}</p>
            )}

            {/* Actions */}
            <div className="flex gap-3">
              <button
                onClick={() => {
                  setShowCreateModal(false);
                  setNewStickerName('');
                  setNewStickerImage(null);
                  setError('');
                }}
                className="flex-1 px-4 py-2 bg-white/10 text-white rounded-lg hover:bg-white/20 transition-colors"
              >
                {translate('common.cancel') || 'Cancel'}
              </button>
              <button
                onClick={handleCreateSticker}
                disabled={creating || !newStickerName.trim() || !newStickerImage}
                className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
              >
                {creating ? (
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mx-auto" />
                ) : (
                  translate('stickers.create') || 'Create'
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// Sticker message component for displaying stickers in chat
interface StickerMessageProps {
  stickerId: string;
  onSave?: (stickerId: string) => void;
  isSaved?: boolean;
}

export function StickerMessage({ stickerId, onSave, isSaved }: StickerMessageProps) {
  const { serverUrl, authToken } = useStore();
  const [sticker, setSticker] = useState<Sticker | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchSticker();
  }, [stickerId]);

  const fetchSticker = async () => {
    try {
      const response = await fetch(`${serverUrl}/api/stickers/${stickerId}`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (response.ok) {
        const data = await response.json();
        setSticker(data);
      }
    } catch (err) {
      console.error('Failed to fetch sticker:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    if (!onSave || isSaved) return;
    setSaving(true);
    try {
      const response = await fetch(`${serverUrl}/api/stickers/${stickerId}/save`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` },
      });
      if (response.ok) {
        onSave(stickerId);
      }
    } catch (err) {
      console.error('Failed to save sticker:', err);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="w-32 h-32 bg-white/5 rounded-lg flex items-center justify-center">
        <div className="w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!sticker) {
    return (
      <div className="w-32 h-32 bg-white/5 rounded-lg flex items-center justify-center">
        <span className="text-gray-500 text-sm">Sticker unavailable</span>
      </div>
    );
  }

  return (
    <div className="relative group">
      <img
        src={sticker.imageData}
        alt={sticker.name}
        className="w-32 h-32 object-contain"
        title={sticker.name}
      />
      {onSave && !isSaved && (
        <button
          onClick={handleSave}
          disabled={saving}
          className="absolute bottom-1 right-1 p-1.5 bg-indigo-600 rounded-lg opacity-0 group-hover:opacity-100 transition-opacity"
          title="Save sticker"
        >
          {saving ? (
            <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
          ) : (
            <Save className="w-4 h-4 text-white" />
          )}
        </button>
      )}
    </div>
  );
}
