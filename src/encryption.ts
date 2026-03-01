import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

const STORAGE_KEY = '4messenger-keys';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

export const encryptionStore = {
  keyPair: null as KeyPair | null,

  generateKeyPair(): KeyPair {
    const keyPair = nacl.box.keyPair();
    const result = {
      publicKey: util.encodeBase64(keyPair.publicKey),
      privateKey: util.encodeBase64(keyPair.secretKey)
    };
    this.keyPair = result;
    this.saveKeys();
    return result;
  },

  saveKeys() {
    if (this.keyPair) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.keyPair));
    }
  },

  loadKeys(): KeyPair | null {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        this.keyPair = JSON.parse(saved);
        return this.keyPair;
      } catch (e) {
        console.error('Failed to parse saved keys', e);
      }
    }
    return null;
  },

  clearKeys() {
    this.keyPair = null;
    localStorage.removeItem(STORAGE_KEY);
  },

  encryptMessage(message: string, recipientPublicKeyBase64: string): string | null {
    if (!this.keyPair) return null;
    
    try {
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const messageUint8 = util.decodeUTF8(message);
      const recipientPubKeyUint8 = util.decodeBase64(recipientPublicKeyBase64);
      const mySecretKeyUint8 = util.decodeBase64(this.keyPair.privateKey);

      const encryptedMsg = nacl.box(messageUint8, nonce, recipientPubKeyUint8, mySecretKeyUint8);

      const fullMessage = new Uint8Array(nonce.length + encryptedMsg.length);
      fullMessage.set(nonce);
      fullMessage.set(encryptedMsg, nonce.length);

      return util.encodeBase64(fullMessage);
    } catch (e) {
      console.error('Encryption error:', e);
      return null;
    }
  },

  decryptMessage(encryptedMessageBase64: string, senderPublicKeyBase64: string): string | null {
    if (!this.keyPair) return null;
    
    // Fallback: If it's not base64 or seems to be server-encrypted (starts with IV hex), return as is
    // This allows backward compatibility with the old system where server encrypted things.
    // Or if it's plain text.
    if (!encryptedMessageBase64 || typeof encryptedMessageBase64 !== 'string') return encryptedMessageBase64;
    
    try {
      // Basic check if it looks like base64
      if (!/^[A-Za-z0-9+/=]+$/.test(encryptedMessageBase64)) {
         return encryptedMessageBase64; // Might be old plain text or server hex format
      }

      const fullMessage = util.decodeBase64(encryptedMessageBase64);
      
      // Ensure the message is long enough to contain a nonce
      if (fullMessage.length < nacl.box.nonceLength) {
         return encryptedMessageBase64;
      }

      const nonce = fullMessage.slice(0, nacl.box.nonceLength);
      const encryptedMsg = fullMessage.slice(nacl.box.nonceLength);

      const senderPubKeyUint8 = util.decodeBase64(senderPublicKeyBase64);
      const mySecretKeyUint8 = util.decodeBase64(this.keyPair.privateKey);

      const decryptedMsg = nacl.box.open(encryptedMsg, nonce, senderPubKeyUint8, mySecretKeyUint8);

      if (!decryptedMsg) {
        throw new Error("Could not decrypt message");
      }

      return util.encodeUTF8(decryptedMsg);
    } catch (e) {
      // If decryption fails, just return the raw text (might be old server-encrypted string)
      return encryptedMessageBase64; 
    }
  }
};
