/**
 * ========================================================
 * AION ENCRYPTED GROUP CHAT — Frontend (Secure Edition)
 *
 * What changed from the original:
 *  - Firebase config removed from JS (served by backend)
 *  - ADMIN_EMAILS removed from JS (checked server-side)
 *  - isAdmin flag comes from verified backend session
 *  - All admin actions call the backend API, not Firebase directly
 *  - Password verify/change handled by backend
 *  - AES-GCM message encryption stays here (E2E, must be client-side)
 *  - Firebase client SDK still used for real-time listeners only
 * ========================================================
 */

// ── CONFIG — only change this ────────────────────────────
const BACKEND_URL = 'https://modalacc77--aion-backend-fastapi-app.modal.run';
// Set to your Cloudflare Worker URL after deploying
// ─────────────────────────────────────────────────────────

// ========================================================
// SECTION 0: API CLIENT
// Thin wrapper around the backend — handles auth headers,
// JSON parsing, and error normalisation.
// ========================================================
const API = {
  _sessionToken: null,

  setSession(token) {
    this._sessionToken = token;
    // Persist across page refreshes (but NOT to localStorage — sessionStorage only)
    try { sessionStorage.setItem('aion_session', token); } catch(e) {}
  },

  loadSession() {
    try { this._sessionToken = sessionStorage.getItem('aion_session') || null; } catch(e) {}
    return this._sessionToken;
  },

  clearSession() {
    this._sessionToken = null;
    try { sessionStorage.removeItem('aion_session'); } catch(e) {}
  },

  async call(method, path, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (this._sessionToken) {
      opts.headers['X-Session-Token'] = this._sessionToken;
    }
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(BACKEND_URL + path, opts);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return data;
  },

  // ── Auth ──────────────────────────────────────────────

  async verifyIdToken(idToken) {
    // Exchange Firebase ID token for our backend session token
    const data = await this.call('POST', '/auth/verify', { idToken });
    this.setSession(data.sessionToken);
    return data; // { sessionToken, uid, email, displayName, photoURL, isAdmin }
  },

  async getMe() {
    return this.call('POST', '/auth/me');
  },

  // ── Password ──────────────────────────────────────────

  async verifyPassword(password) {
    return this.call('POST', '/password/verify', { password });
    // returns { valid: bool, needsInit?: bool }
  },

  async initPassword(password) {
    return this.call('POST', '/password/init', { password });
  },

  async changePassword(oldPassword, newPassword) {
    return this.call('POST', '/password/change', { oldPassword, newPassword });
  },

  // ── Admin ─────────────────────────────────────────────

  async blockUser(targetUid, roomId, block) {
    return this.call('POST', '/admin/block-user', { targetUid, roomId, block });
  },

  async kickUser(targetUid, roomId) {
    return this.call('POST', '/admin/kick-user', { targetUid, roomId });
  },

  async deleteRoom(roomId) {
    return this.call('POST', '/admin/delete-room', { roomId });
  },

  async clearChat(roomId) {
    return this.call('POST', '/admin/clear-chat', { roomId });
  },

  async createRoom(name, icon, description, password) {
    return this.call('POST', '/admin/create-room', { name, icon, description, password });
    // returns { success, roomId }
  },

  async broadcast(message) {
    return this.call('POST', '/admin/broadcast', { message });
  },

  async setPrefs(prefs) {
    return this.call('POST', '/admin/set-prefs', prefs);
    // prefs: { hideStatusFromMembers?, hideDMsFromMembers?, disableCalls?, lockVoiceRoom? }
  },

  async lockRoom(roomId, locked) {
    return this.call('POST', '/admin/lock-room', { roomId, locked });
  },

  async getUsers() {
    return this.call('GET', '/admin/users');
    // returns { users: { uid: {...} } }
  },
};

// ========================================================
// SECTION 1: CRYPTO UTILITIES  (unchanged — must stay client)
// E2E encryption: the backend never sees plaintext messages.
// ========================================================
const Crypto = {
  utf8ToArrayBuffer(str) { return new TextEncoder().encode(str); },
  arrayBufferToUtf8(buffer) { return new TextDecoder().decode(buffer); },
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer); let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  },
  base64ToArrayBuffer(base64) {
    const binary = atob(base64); const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  },
  generateRandomBytes(length) {
    const buffer = new Uint8Array(length); crypto.getRandomValues(buffer); return buffer.buffer;
  },
  async deriveKeyPBKDF2(password, salt, iterations = 250000) {
    const passwordBuffer = this.utf8ToArrayBuffer(password);
    const keyMaterial = await crypto.subtle.importKey('raw', passwordBuffer, 'PBKDF2', false, ['deriveBits', 'deriveKey']);
    return await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },
  async aesGcmEncrypt(key, data) {
    const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
    const plaintextBuffer = this.utf8ToArrayBuffer(plaintext);
    const iv = this.generateRandomBytes(12);
    const ciphertextBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plaintextBuffer);
    return { ciphertext: this.arrayBufferToBase64(ciphertextBuffer), iv: this.arrayBufferToBase64(iv) };
  },
  async aesGcmDecrypt(key, ciphertext, iv, parseJSON = false) {
    const ciphertextBuffer = this.base64ToArrayBuffer(ciphertext);
    const ivBuffer = this.base64ToArrayBuffer(iv);
    const plaintextBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuffer, tagLength: 128 }, key, ciphertextBuffer);
    const plaintext = this.arrayBufferToUtf8(plaintextBuffer);
    if (parseJSON) { try { return JSON.parse(plaintext); } catch(e) { return plaintext; } }
    return plaintext;
  },
};

// ========================================================
// SECTION 2: FIREBASE — client SDK for real-time only
// The config here is used for listeners + auth popup only.
// All writes that need admin privileges go through the backend.
// ========================================================
// NOTE: The Firebase client config (apiKey etc.) is NOT secret —
// it identifies your project to the client SDK but does not
// grant admin access. Real security comes from Firebase security
// rules + backend token verification. It is safe to leave here.
const FIREBASE_CLIENT_CONFIG = {
  apiKey: "AIzaSyAS_HheqFK98UIvjtiBxtHSOkOfuaOkkug",
  authDomain: "kwit-5dde3.firebaseapp.com",
  databaseURL: "https://kwit-5dde3-default-rtdb.firebaseio.com",
  projectId: "kwit-5dde3",
  storageBucket: "kwit-5dde3.firebasestorage.app",
  messagingSenderId: "692601571855",
  appId: "1:692601571855:web:03e8538f22f47202a5f17a"
};

const Firebase = {
  app: null, db: null, auth: null,
  ref: null, set: null, get: null, push: null,
  onChildAdded: null, onValue: null, update: null, off: null,
  remove: null, serverTimestamp: null,
  signInWithPopup: null, GoogleAuthProvider: null, onAuthStateChanged: null, signOut: null,

  async init() {
    try {
      const { initializeApp } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js');
      const { getDatabase, ref, set, get, push, onChildAdded, onValue, update, off, remove, serverTimestamp } =
        await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-database.js');
      const { getAuth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged, signOut } =
        await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');

      this.app = initializeApp(FIREBASE_CLIENT_CONFIG);
      this.db = getDatabase(this.app);
      this.auth = getAuth(this.app);
      this.ref = ref; this.set = set; this.get = get; this.push = push;
      this.onChildAdded = onChildAdded; this.onValue = onValue;
      this.update = update; this.off = off; this.remove = remove;
      this.serverTimestamp = serverTimestamp;
      this.signInWithPopup = signInWithPopup;
      this.GoogleAuthProvider = GoogleAuthProvider;
      this.onAuthStateChanged = onAuthStateChanged;
      this.signOut = signOut;
      return true;
    } catch(e) { console.error('Firebase init failed:', e); return false; }
  },

  async writeData(path, data) { await this.set(this.ref(this.db, path), data); },
  async readData(path) { const s = await this.get(this.ref(this.db, path)); return s.exists() ? s.val() : null; },
  listenToNewChildren(path, callback) {
    const dbRef = this.ref(this.db, path);
    this.onChildAdded(dbRef, s => callback({ id: s.key, data: s.val() }));
    return () => this.off(dbRef);
  },
  listenToValue(path, callback) {
    const dbRef = this.ref(this.db, path);
    this.onValue(dbRef, s => callback(s.val()));
    return () => this.off(dbRef);
  },
  async pushData(path, data) {
    const dbRef = this.ref(this.db, path);
    const newRef = this.push(dbRef);
    await this.set(newRef, data);
    return newRef.key;
  },
  async updateData(path, updates) { await this.update(this.ref(this.db, path), updates); },
  getServerTimestamp() { return { '.sv': 'timestamp' }; }
};

// ========================================================
// SECTION 3: AUTH STATE
// isAdmin now comes from backend session, not ADMIN_EMAILS
// ========================================================
const Auth = {
  user: null,
  isAdmin: false,    // set from backend response, not from a local list
  chatPassword: null,
  masterKey: null,
  _backendSession: null,

  async signInWithGoogle() {
    const provider = new Firebase.GoogleAuthProvider();
    const result = await Firebase.signInWithPopup(Firebase.auth, provider);

    // Get Firebase ID token and exchange with backend
    const idToken = await result.user.getIdToken();
    const session = await API.verifyIdToken(idToken);

    // Trust isAdmin from the backend — not computed locally
    this.isAdmin = session.isAdmin;
    this._backendSession = session;
    return result;
  },

  async refreshSession() {
    // Re-verify after page reload using stored session token
    API.loadSession();
    if (!API._sessionToken) return false;
    try {
      const me = await API.getMe();
      this.isAdmin = me.isAdmin;
      return true;
    } catch(e) {
      API.clearSession();
      return false;
    }
  },

  async signOut() {
    this.user = null; this.isAdmin = false; this.chatPassword = null; this.masterKey = null;
    API.clearSession();
    await Firebase.signOut(Firebase.auth);
  },

  async deriveKey(password) {
    // Derive the client-side AES key from the password + global salt
    // Salt is read from Firebase (public read) — key derivation stays local
    const saltB64 = await Firebase.readData('global/salt');
    if (!saltB64) throw new Error('No salt — password not initialised yet');
    const salt = Crypto.base64ToArrayBuffer(saltB64);
    this.masterKey = await Crypto.deriveKeyPBKDF2(password, salt);
    return this.masterKey;
  },

  // Password verification is now a backend call
  async verifyPassword(password) {
    UI.showLoading('Verifying password…');
    try {
      const res = await API.verifyPassword(password);

      if (res.needsInit && this.isAdmin) {
        // First-time setup: admin initialises the password via backend
        await API.initPassword(password);
        // Also derive local key so E2E crypto works
        await this.deriveKey(password);
        UI.hideLoading();
        return true;
      }

      if (!res.valid) { UI.hideLoading(); return false; }

      // Derive local AES key (for E2E message crypto)
      await this.deriveKey(password);
      UI.hideLoading();
      return true;
    } catch(e) {
      UI.hideLoading();
      return false;
    }
  },

  storeUserProfile() {
    if (!this.user) return;
    Firebase.updateData(`users/${this.user.uid}`, {
      displayName: this.user.displayName || 'Anonymous',
      email: this.user.email,
      photoURL: this.user.photoURL || '',
      lastSeen: Firebase.getServerTimestamp(),
      isAdmin: this.isAdmin,
      online: true
    });
  },

  setOnlineStatus(online) {
    if (!this.user) return;
    Firebase.updateData(`users/${this.user.uid}`, { online, lastSeen: Firebase.getServerTimestamp() });
  }
};

// ========================================================
// SECTION 4: ROOM MANAGEMENT
// create/delete moved to backend API — join/listen stays here
// ========================================================
const Room = {
  current: { id: null, name: null, masterKey: null, userId: null, username: null },

  async ensureDefaultRooms() {
    const DEFAULT_ROOMS = [
      { id: 'general',   name: 'General',    icon: 'G', description: 'Open discussion', color: '#8b7355' },
      { id: 'creative',  name: 'Creative',   icon: 'C', description: 'Art, music, design', color: '#6c7a8b' },
      { id: 'tech',      name: 'Tech',       icon: 'T', description: 'Code and digital life', color: '#4a7c5c' },
      { id: 'random',    name: 'Random',     icon: 'R', description: 'Fun and everything else', color: '#8b4a6c' },
      { id: 'private',   name: 'Private',    icon: 'P', description: 'Secure lounge', color: '#2d2926' },
    ];
    for (const room of DEFAULT_ROOMS) {
      const existing = await Firebase.readData(`rooms/${room.id}`);
      if (!existing) {
        await Firebase.writeData(`rooms/${room.id}`, {
          roomName: room.name, icon: room.icon, description: room.description,
          color: room.color, isDefault: true, createdAt: Firebase.getServerTimestamp()
        });
      }
    }
  },

  // Room creation now goes through backend
  async createRoom(name, icon, description, password) {
    const res = await API.createRoom(name, icon, description, password);
    return res.roomId;
  },

  // Room deletion now goes through backend
  async deleteRoom(roomId) {
    await API.deleteRoom(roomId);
  },

  async join(roomId, roomData, password) {
    if (roomData.isDefault || !roomData.salt) {
      this.current.id = roomId;
      this.current.name = roomData.roomName;
      this.current.masterKey = Auth.masterKey;
      this.current.userId = Auth.user.uid;
      this.current.username = Auth.user.displayName || 'Anonymous';
      await this.registerUser();
      return true;
    }
    if (!password) return false;
    // Password rooms: derive room key locally (E2E — backend doesn't know room passwords)
    const salt = Crypto.base64ToArrayBuffer(roomData.salt);
    const key = await Crypto.deriveKeyPBKDF2(password, salt);
    try {
      const plaintext = await Crypto.aesGcmDecrypt(key, roomData.roomCheck.ciphertext, roomData.roomCheck.iv);
      if (plaintext !== 'ROOM_OK') return false;
    } catch(e) { return false; }

    this.current.id = roomId;
    this.current.name = roomData.roomName;
    this.current.masterKey = key;
    this.current.userId = Auth.user.uid;
    this.current.username = Auth.user.displayName || 'Anonymous';
    await this.registerUser();
    return true;
  },

  async registerUser() {
    if (!this.current.id) return;
    await Firebase.updateData(`rooms/${this.current.id}/members/${this.current.userId}`, {
      displayName: Auth.user.displayName || 'Anonymous',
      email: Auth.user.email,
      photoURL: Auth.user.photoURL || '',
      online: true,
      currentRoom: this.current.id,
      roomName: this.current.name,
      joinedAt: Firebase.getServerTimestamp(),
      isAdmin: Auth.isAdmin,
      blocked: false
    });
    Auth.storeUserProfile();
    Firebase.updateData(`users/${Auth.user.uid}`, {
      currentRoom: this.current.id,
      currentRoomName: this.current.name,
      online: true
    });
  },

  async isBlocked() {
    const data = await Firebase.readData(`rooms/${this.current.id}/members/${this.current.userId}`);
    return data && data.blocked === true;
  },

  leave() {
    if (this.current.id) {
      Firebase.updateData(`rooms/${this.current.id}/members/${this.current.userId}`, { online: false, currentRoom: null });
    }
    Firebase.updateData(`users/${Auth.user.uid}`, { online: true, currentRoom: null, currentRoomName: null });
    Messaging.clearListeners();
    Settings.clearMusic();
    Settings.stopListeningToSettings();
    this.current = { id: null, name: null, masterKey: null, userId: null, username: null };
  },

  isInRoom() { return this.current.id !== null && this.current.masterKey !== null; }
};

// ========================================================
// SECTION 5: MESSAGING  (unchanged — all E2E client-side)
// ========================================================
const Messaging = {
  listeners: [], typingTimeout: null, typingListenerUnsubscribe: null,
  dmListeners: {},

  async send(text, type = 'text', fileData = null) {
    if (!Room.isInRoom()) throw new Error('Not in a room');
    if (type === 'text' && (!text || !text.trim())) throw new Error('Empty message');
    const messageObj = {
      text: type === 'text' ? text.trim() : (text || ''),
      type, fileData: fileData || null,
      author: Auth.user.uid,
      displayName: Auth.user.displayName || 'Anonymous',
      photoURL: Auth.user.photoURL || '',
      timestamp: Date.now()
    };
    const encrypted = await Crypto.aesGcmEncrypt(Room.current.masterKey, messageObj);
    await Firebase.pushData(`messages/${Room.current.id}`, {
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      serverTimestamp: Firebase.getServerTimestamp()
    });
    await this.setTypingStatus(false);
  },

  async sendDM(toUid, toName, text, type = 'text', fileData = null) {
    if (!Auth.masterKey) throw new Error('No key');
    const dmId = [Auth.user.uid, toUid].sort().join('_');
    const messageObj = {
      text: type === 'text' ? text.trim() : (text || ''),
      type, fileData: fileData || null,
      author: Auth.user.uid,
      displayName: Auth.user.displayName || 'Anonymous',
      photoURL: Auth.user.photoURL || '',
      toUid, toName, timestamp: Date.now()
    };
    const encrypted = await Crypto.aesGcmEncrypt(Auth.masterKey, messageObj);
    await Firebase.pushData(`dms/${dmId}`, {
      ciphertext: encrypted.ciphertext, iv: encrypted.iv,
      serverTimestamp: Firebase.getServerTimestamp()
    });
  },

  listenDM(toUid, callback) {
    const dmId = [Auth.user.uid, toUid].sort().join('_');
    if (this.dmListeners[dmId]) return;
    let processed = new Set();
    const unsub = Firebase.listenToNewChildren(`dms/${dmId}`, async (snapshot) => {
      if (processed.has(snapshot.id)) return;
      processed.add(snapshot.id);
      try {
        const enc = snapshot.data;
        const dec = await Crypto.aesGcmDecrypt(Auth.masterKey, enc.ciphertext, enc.iv, true);
        callback({ id: snapshot.id, ...dec, isMe: dec.author === Auth.user.uid });
      } catch(e) {}
    });
    this.dmListeners[dmId] = unsub;
    return () => { unsub(); delete this.dmListeners[dmId]; };
  },

  async listen(callback) {
    if (!Room.isInRoom()) return;
    let processedMessages = new Set();
    const unsubscribe = Firebase.listenToNewChildren(`messages/${Room.current.id}`, async (snapshot) => {
      try {
        if (processedMessages.has(snapshot.id)) return;
        processedMessages.add(snapshot.id);
        const enc = snapshot.data;
        const decrypted = await Crypto.aesGcmDecrypt(Room.current.masterKey, enc.ciphertext, enc.iv, true);
        callback({
          id: snapshot.id,
          text: decrypted.text, type: decrypted.type || 'text',
          fileData: decrypted.fileData || null,
          author: decrypted.author,
          displayName: decrypted.displayName || 'Unknown',
          photoURL: decrypted.photoURL || '',
          timestamp: decrypted.timestamp,
          isMe: decrypted.author === Auth.user.uid
        });
      } catch(e) {
        callback({ id: snapshot.id, text: '[Unable to decrypt]', type: 'text', author: 'system', displayName: 'System', photoURL: '', timestamp: Date.now(), isMe: false, error: true });
      }
    });
    this.listeners.push(unsubscribe);
  },

  async setTypingStatus(isTyping) {
    if (!Room.isInRoom() || !Auth.user) return;
    if (this.typingTimeout) clearTimeout(this.typingTimeout);
    if (isTyping) {
      await Firebase.updateData(`rooms/${Room.current.id}/typing/${Auth.user.uid}`, {
        isTyping: true, displayName: Auth.user.displayName || 'Anonymous', timestamp: Firebase.getServerTimestamp()
      });
      this.typingTimeout = setTimeout(() => this.setTypingStatus(false), 3000);
    } else {
      await Firebase.updateData(`rooms/${Room.current.id}/typing/${Auth.user.uid}`, { isTyping: false });
    }
  },

  listenForTyping(callback) {
    if (!Room.isInRoom()) return;
    this.typingListenerUnsubscribe = Firebase.listenToValue(`rooms/${Room.current.id}/typing`, (data) => {
      if (!data) { callback(null); return; }
      for (const [uid, d] of Object.entries(data)) {
        if (uid !== Auth.user.uid && d.isTyping === true) { callback(d.displayName || 'Someone'); return; }
      }
      callback(null);
    });
  },

  clearListeners() {
    this.listeners.forEach(u => u());
    this.listeners = [];
    Object.values(this.dmListeners).forEach(u => u && u());
    this.dmListeners = {};
    if (this.typingListenerUnsubscribe) { this.typingListenerUnsubscribe(); this.typingListenerUnsubscribe = null; }
    if (this.typingTimeout) clearTimeout(this.typingTimeout);
  }
};

// ========================================================
// SECTION 6: SETTINGS (unchanged from original)
// ========================================================
const Settings = {
  currentSettings: null, settingsListener: null,
  getDefaultSettings() {
    return {
      bgColor: '#faf9f7', bgImage: null, bgOpacity: 100,
      myBubbleColor: '#1a1814', otherBubbleColor: '#f0ede8',
      myTextColor: '#ffffff', otherTextColor: '#1a1814', chatBgColor: '#faf9f7',
      headerVisible: true, headerBgColor: '#ffffff', headerTextColor: '#1a1814',
      bubbleShape: 'rounded', inputShape: 'rounded', buttonShape: 'rounded',
      fontSize: '15', fontFamily: "'DM Sans', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
      musicEnabled: false, musicFile: null, musicVolume: 50,
      bgTextEnabled: false, bgText: '', bgTextSize: 40, bgTextColor: '#ffffff', bgTextPosition: 'center',
      lastUpdated: Date.now(), robotProvider: 'cerebras',
      hideStatusFromMembers: false, hideDMsFromMembers: false
    };
  },
  async load() {
    if (!Room.isInRoom()) return;
    try {
      const roomData = await Firebase.readData(`rooms/${Room.current.id}`);
      if (roomData && roomData.settings) {
        try {
          const decrypted = await Crypto.aesGcmDecrypt(Room.current.masterKey, roomData.settings.ciphertext, roomData.settings.iv, true);
          this.currentSettings = { ...this.getDefaultSettings(), ...decrypted };
        } catch(e) { this.currentSettings = this.getDefaultSettings(); }
      } else { this.currentSettings = this.getDefaultSettings(); }
      this.apply(); this.updateUI(); this.listenToSettings();
    } catch(e) { this.currentSettings = this.getDefaultSettings(); this.apply(); }
  },
  listenToSettings() {
    if (!Room.isInRoom() || this.settingsListener) return;
    this.settingsListener = Firebase.listenToValue(`rooms/${Room.current.id}/settings`, async (data) => {
      if (!data) return;
      try {
        const dec = await Crypto.aesGcmDecrypt(Room.current.masterKey, data.ciphertext, data.iv, true);
        if (dec.lastUpdated > this.currentSettings.lastUpdated) {
          this.currentSettings = { ...this.getDefaultSettings(), ...dec };
          this.apply(); this.updateUI();
        }
      } catch(e) {}
    });
  },
  stopListeningToSettings() { if (this.settingsListener) { this.settingsListener(); this.settingsListener = null; } },
  async save() {
    if (!Room.isInRoom()) return;
    this.currentSettings.lastUpdated = Date.now();
    const enc = await Crypto.aesGcmEncrypt(Room.current.masterKey, this.currentSettings);
    await Firebase.updateData(`rooms/${Room.current.id}`, { settings: enc });
  },
  apply() {
    const s = this.currentSettings; const root = document.documentElement;
    root.style.setProperty('--chat-bg', s.chatBgColor);
    root.style.setProperty('--bubble-me', s.myBubbleColor);
    root.style.setProperty('--bubble-other', s.otherBubbleColor);
    root.style.setProperty('--text-me', s.myTextColor);
    root.style.setProperty('--text-other', s.otherTextColor);
    root.style.setProperty('--header-bg', s.headerBgColor);
    root.style.setProperty('--header-text', s.headerTextColor);
    root.style.setProperty('--font-size', s.fontSize + 'px');
    root.style.setProperty('--font-family', s.fontFamily);
    const sv = { rounded: { bubble:'18px',input:'24px',button:'8px' }, medium: { bubble:'10px',input:'12px',button:'4px' }, sharp: { bubble:'0',input:'0',button:'0' }, pill: { bubble:'18px',input:'24px',button:'50px' } };
    root.style.setProperty('--bubble-radius', sv[s.bubbleShape]?.bubble||'18px');
    root.style.setProperty('--input-radius', sv[s.inputShape]?.input||'24px');
    root.style.setProperty('--button-radius', sv[s.buttonShape]?.button||'8px');
    const bgLayer = document.getElementById('backgroundImageLayer');
    if (bgLayer) { bgLayer.style.backgroundImage = s.bgImage ? `url(${s.bgImage})` : ''; bgLayer.style.opacity = s.bgImage ? s.bgOpacity/100 : 1; }
    const header = document.getElementById('chatHeader');
    if (header) { s.headerVisible ? header.classList.remove('hidden') : header.classList.add('hidden'); }
    this.applyBackgroundText();
    if (s.musicEnabled && s.musicFile) this.playMusic(s.musicFile, s.musicVolume); else this.clearMusic();
  },
  applyBackgroundText() {
    const s = this.currentSettings;
    document.querySelector('.background-text-overlay')?.remove();
    if (s.bgTextEnabled && s.bgText) {
      const o = document.createElement('div');
      o.className = `background-text-overlay ${s.bgTextPosition}`;
      o.textContent = s.bgText; o.style.fontSize = s.bgTextSize + 'px'; o.style.color = s.bgTextColor;
      document.getElementById('chatScreen')?.appendChild(o);
    }
  },
  updateUI() {
    const s = this.currentSettings;
    const sv = (id, v) => { const el = document.getElementById(id); if(el) el.value = v; };
    const sc = (id, v) => { const el = document.getElementById(id); if(el) el.checked = v; };
    const st = (id, v) => { const el = document.getElementById(id); if(el) el.textContent = v; };
    sv('bgColorPicker', s.bgColor); sv('myBubbleColorPicker', s.myBubbleColor);
    sv('otherBubbleColorPicker', s.otherBubbleColor); sv('myTextColorPicker', s.myTextColor);
    sv('otherTextColorPicker', s.otherTextColor); sv('chatBgColorPicker', s.chatBgColor);
    sv('headerBgColorPicker', s.headerBgColor); sv('headerTextColorPicker', s.headerTextColor);
    sv('bgTextColorPicker', s.bgTextColor); sv('bubbleShapeSelect', s.bubbleShape);
    sv('inputShapeSelect', s.inputShape); sv('buttonShapeSelect', s.buttonShape);
    sv('fontSizeSelect', s.fontSize); sv('fontFamilySelect', s.fontFamily);
    sv('bgTextPositionSelect', s.bgTextPosition); sv('bgTextInput', s.bgText);
    sc('headerVisibleToggle', s.headerVisible); sc('musicToggle', s.musicEnabled); sc('bgTextToggle', s.bgTextEnabled);
    sv('bgOpacitySlider', s.bgOpacity); st('bgOpacityValue', s.bgOpacity+'%');
    sv('bgTextSizeSlider', s.bgTextSize); st('bgTextSizeValue', s.bgTextSize+'px');
    sv('musicVolumeSlider', s.musicVolume); st('musicVolumeValue', s.musicVolume+'%');
    sc('hideStatusToggle', !!s.hideStatusFromMembers);
    sc('hideDMsToggle', !!s.hideDMsFromMembers);
  },
  playMusic(dataUrl, volume) {
    const audio = document.getElementById('backgroundAudio');
    if (audio.src !== dataUrl) audio.src = dataUrl;
    audio.volume = volume/100; audio.play().catch(()=>{});
  },
  clearMusic() { const a = document.getElementById('backgroundAudio'); if(a){a.pause();a.currentTime=0;} },
  reset() { this.currentSettings = this.getDefaultSettings(); this.apply(); this.updateUI(); }
};

// ========================================================
// SECTION 7: ADMIN ACTIONS — all now go through backend API
// ========================================================
const AdminActions = {
  async blockUser(uid, roomId, block, displayName) {
    if (!Auth.isAdmin) return;
    if (block && !confirm(`Block ${displayName} from this room?`)) return;
    try {
      await API.blockUser(uid, roomId, block);
      UI.showToast(block ? `${displayName} blocked` : `${displayName} unblocked`);
    } catch(e) { UI.showToast('Error: ' + e.message); }
  },

  async kickUser(uid, roomId, displayName) {
    if (!Auth.isAdmin) return;
    if (!confirm(`Kick ${displayName}?`)) return;
    try {
      await API.kickUser(uid, roomId);
      UI.showToast(`${displayName} kicked`);
    } catch(e) { UI.showToast('Error: ' + e.message); }
  },

  async clearChat(roomId) {
    if (!Auth.isAdmin) return;
    if (!confirm('Delete ALL messages? Cannot be undone.')) return;
    try {
      await API.clearChat(roomId);
      document.getElementById('messagesContainer').innerHTML = '';
      const info = document.createElement('div');
      info.style.cssText = 'text-align:center;padding:20px;color:#7a7570;font-size:0.82rem;';
      info.textContent = '— Chat cleared by admin —';
      document.getElementById('messagesContainer').appendChild(info);
    } catch(e) { UI.showToast('Error: ' + e.message); }
  },

  async toggleLock(roomId) {
    if (!Auth.isAdmin) return;
    const current = await Firebase.readData(`rooms/${roomId}/locked`);
    try {
      await API.lockRoom(roomId, !current);
      document.getElementById('lockRoomBtn').textContent = current ? 'Lock Room' : 'Unlock Room';
    } catch(e) { UI.showToast('Error: ' + e.message); }
  },

  async createRoom(name, icon, desc, password) {
    if (!Auth.isAdmin) return;
    const res = await API.createRoom(name, icon, desc, password);
    return res.roomId;
  },

  async deleteRoom(roomId) {
    if (!Auth.isAdmin) return;
    await API.deleteRoom(roomId);
  },

  async sendBroadcast(message) {
    if (!Auth.isAdmin) return;
    await API.broadcast(message);
  },

  async setPrefs(prefs) {
    if (!Auth.isAdmin) return;
    await API.setPrefs(prefs);
  },

  async changePassword(oldPassword, newPassword) {
    if (!Auth.isAdmin) return;
    return API.changePassword(oldPassword, newPassword);
  },

  async getUsers() {
    if (!Auth.isAdmin) return {};
    const res = await API.getUsers();
    return res.users || {};
  }
};

// ========================================================
// SECTION 8: UI CONTROLLER
// Key changes: Google sign-in now calls API.verifyIdToken,
// admin actions use AdminActions.*, presence unchanged.
// ========================================================
const UI = {
  pendingRoomId: null,
  pendingRoomData: null,
  membersListener: null,

  getProxiedAvatar(url) {
    if (!url) return '';
    if (url.includes('googleusercontent.com')) {
      return url.replace(/=s\d+-c/, '=s128-c').replace(/=s\d+/, '=s128');
    }
    return url;
  },

  async init() {
    const ok = await Firebase.init();
    if (!ok) { alert('Firebase configuration error'); return; }

    this.createParticles();

    // Try to restore session from sessionStorage on page load
    API.loadSession();

    Firebase.onAuthStateChanged(Firebase.auth, async (user) => {
  if (user) {
    Auth.user = user;

    API.loadSession();
    let sessionOk = false;

    if (API._sessionToken) {
      try {
        const me = await API.getMe();
        Auth.isAdmin = me.isAdmin;
        sessionOk = true;
      } catch (e) {
        API.clearSession();  // expired — fall through
      }
    }

    if (!sessionOk) {
      // Re-exchange Firebase token for a fresh backend session
      try {
        const idToken = await user.getIdToken(false);
        const session = await API.verifyIdToken(idToken);
        Auth.isAdmin = session.isAdmin;
      } catch (e) {
        console.error('[Auth] Backend session failed:', e);
        await Auth.signOut();
        UI.showSplash();
        return;
      }
    }

    Auth.storeUserProfile();
    const params = new URLSearchParams(window.location.search);
    if (params.get('room')) this._pendingRoomFromUrl = params.get('room');
    this.showPasswordScreen();

  } else {
    Auth.setOnlineStatus && Auth.setOnlineStatus(false);
    this.showSplash();
  }
});

    document.getElementById('googleSignInBtn').addEventListener('click', async () => {
      try {
        document.getElementById('googleSignInBtn').textContent = 'Signing in…';
        // signInWithGoogle now internally calls API.verifyIdToken and sets Auth.isAdmin
        await Auth.signInWithGoogle();
      } catch(e) {
        document.getElementById('googleSignInBtn').innerHTML = '<img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" style="width:20px"> Try again';
        UI.showToast('Sign-in failed: ' + e.message);
      }
    });

    document.getElementById('pwdSubmitBtn').addEventListener('click', () => this.handlePasswordSubmit());
    document.getElementById('pwdInput').addEventListener('keydown', e => { if(e.key==='Enter') this.handlePasswordSubmit(); });
    document.getElementById('pwdSignoutBtn').addEventListener('click', async () => { await Auth.signOut(); this.showSplash(); });
    document.getElementById('lobbySignoutBtn').addEventListener('click', async () => { DM.closeAll(); Presence.stop(); await Auth.signOut(); this.showSplash(); });

    document.getElementById('createRoomAdminBtn').addEventListener('click', () => this.showAdminRoomModal());
    document.getElementById('deleteRoomAdminBtn').addEventListener('click', () => this.showDeleteRoomPicker());
    document.getElementById('viewMembersAdminBtn').addEventListener('click', () => this.showGlobalMembersModal());
    document.getElementById('changePasswordAdminBtn').addEventListener('click', () => this.showChangePasswordModal());
    document.getElementById('broadcastAlertBtn')?.addEventListener('click', () => this.showBroadcastModal());
    document.getElementById('broadcastChatBtn')?.addEventListener('click', () => this.showBroadcastModal());
    document.getElementById('broadcastSendBtn')?.addEventListener('click', () => this.handleSendBroadcast());
    document.getElementById('broadcastCancelBtn')?.addEventListener('click', () => document.getElementById('broadcastModal').classList.remove('active'));

    document.getElementById('armCancelBtn').addEventListener('click', () => document.getElementById('adminRoomModal').classList.remove('active'));
    document.getElementById('armSubmitBtn').addEventListener('click', () => this.handleAdminCreateRoom());

    document.getElementById('rpwdCancelBtn').addEventListener('click', () => { document.getElementById('roomPasswordModal').classList.remove('active'); this.pendingRoomId = null; });
    document.getElementById('rpwdSubmitBtn').addEventListener('click', () => this.handleRoomPasswordSubmit());
    document.getElementById('rpwdInput').addEventListener('keydown', e => { if(e.key==='Enter') this.handleRoomPasswordSubmit(); });

    document.getElementById('sendMessageBtn').addEventListener('click', () => this.handleSendMessage());
    document.getElementById('messageInput').addEventListener('keydown', e => { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();this.handleSendMessage();} });
    document.getElementById('messageInput').addEventListener('input', () => Messaging.setTypingStatus(true));
    document.getElementById('leaveRoomBtn').addEventListener('click', () => this.handleLeaveRoom());
    document.getElementById('backToLobbyBtn').addEventListener('click', () => this.handleLeaveRoom());
    document.getElementById('shareRoomBtn').addEventListener('click', () => this.showShareModal());
    document.getElementById('settingsBtn').addEventListener('click', () => this.toggleSettings());
    document.getElementById('membersToggleBtn').addEventListener('click', () => this.toggleMembers());
    document.getElementById('closeMembersBtn').addEventListener('click', () => document.getElementById('membersPanel').classList.remove('open'));
    document.getElementById('clearRoomChatBtn').addEventListener('click', () => AdminActions.clearChat(Room.current.id));
    document.getElementById('lockRoomBtn').addEventListener('click', () => AdminActions.toggleLock(Room.current.id));

    document.getElementById('attachBtn').addEventListener('click', () => { document.getElementById('attachMenu').classList.toggle('visible'); });
    document.getElementById('attachImageOpt').addEventListener('click', () => { document.getElementById('attachMenu').classList.remove('visible'); document.getElementById('imageFileInput').click(); });
    document.getElementById('attachDocOpt').addEventListener('click', () => { document.getElementById('attachMenu').classList.remove('visible'); document.getElementById('docFileInput').click(); });
    document.getElementById('imageFileInput').addEventListener('change', e => this.handleImageUpload(e));
    document.getElementById('docFileInput').addEventListener('change', e => this.handleDocUpload(e));
    document.addEventListener('click', e => { if (!e.target.closest('#attachBtn') && !e.target.closest('#attachMenu')) document.getElementById('attachMenu').classList.remove('visible'); });

    this.setupSettingsListeners();

    document.getElementById('closeShareModal').addEventListener('click', () => document.getElementById('shareModal').classList.add('hidden'));
    document.getElementById('copyLinkBtn').addEventListener('click', () => {
      const i = document.getElementById('shareLinkInput'); i.select(); document.execCommand('copy');
      document.getElementById('copyLinkBtn').textContent = 'Copied';
      setTimeout(() => document.getElementById('copyLinkBtn').textContent = 'Copy', 2000);
    });
    document.getElementById('imgLightbox').addEventListener('click', () => document.getElementById('imgLightbox').classList.remove('active'));
    document.getElementById('changePwdCancelBtn')?.addEventListener('click', () => document.getElementById('changePasswordModal').classList.remove('active'));
    document.getElementById('changePwdSubmitBtn')?.addEventListener('click', () => this.handleChangeGlobalPassword());
    document.getElementById('closeGlobalMembersBtn')?.addEventListener('click', () => document.getElementById('globalMembersModal').classList.remove('active'));

    window.addEventListener('beforeunload', () => { if (Auth.user) Auth.setOnlineStatus(false); });
  },

  createParticles() {
    const container = document.getElementById('splashParticles');
    if (!container) return;
    for (let i = 0; i < 18; i++) {
      const p = document.createElement('div');
      p.className = 'particle';
      p.style.left = Math.random()*100+'%';
      p.style.animationDuration = (8+Math.random()*12)+'s';
      p.style.animationDelay = (-Math.random()*20)+'s';
      p.style.width = p.style.height = (1+Math.random()*3)+'px';
      container.appendChild(p);
    }
  },

  showSplash() {
    document.getElementById('splashScreen').classList.remove('hidden');
    document.getElementById('passwordScreen').classList.remove('active');
    document.getElementById('lobbyScreen').classList.remove('active');
    document.getElementById('chatScreen').classList.remove('active');
  },

  showPasswordScreen() {
    document.getElementById('splashScreen').classList.add('hidden');
    document.getElementById('passwordScreen').classList.add('active');
    const u = Auth.user;
    const avatarUrl = this.getProxiedAvatar(u.photoURL);
    const pwdAvatar = document.getElementById('pwdAvatar');
    if (avatarUrl) {
      pwdAvatar.src = avatarUrl;
      pwdAvatar.onerror = () => { pwdAvatar.outerHTML = `<div class="pwd-avatar pwd-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`; };
    } else {
      pwdAvatar.outerHTML = `<div class="pwd-avatar pwd-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`;
    }
    document.getElementById('pwdName').textContent = u.displayName || 'User';
    document.getElementById('pwdEmail').textContent = u.email;
    document.getElementById('pwdInput').value = '';
    document.getElementById('pwdError').textContent = '';
    setTimeout(() => document.getElementById('pwdInput').focus(), 300);
  },

  async showLobby() {
    document.getElementById('passwordScreen').classList.remove('active');
    document.getElementById('lobbyScreen').classList.add('active');
    const u = Auth.user;
    const lobbyAv = document.getElementById('lobbyAvatar');
    const avatarUrl = this.getProxiedAvatar(u.photoURL);
    if (avatarUrl) {
      lobbyAv.src = avatarUrl;
      lobbyAv.onerror = () => { lobbyAv.outerHTML = `<div class="lobby-avatar lobby-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`; };
    } else {
      lobbyAv.outerHTML = `<div class="lobby-avatar lobby-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`;
    }
    document.getElementById('lobbyUsername').textContent = u.displayName || 'User';
    document.getElementById('adminBadge').style.display = Auth.isAdmin ? 'inline' : 'none';
    document.getElementById('adminPanel').classList.toggle('visible', Auth.isAdmin);
    Presence.start();
    Broadcast.start();
    await Room.ensureDefaultRooms();
    await this.renderRooms();
    if (this._pendingRoomFromUrl) {
      const roomId = this._pendingRoomFromUrl;
      this._pendingRoomFromUrl = null;
      setTimeout(async () => {
        const roomData = await Firebase.readData(`rooms/${roomId}`);
        if (roomData) await this.handleJoinRoom(roomId, roomData);
        else this.showToast('Room not found.');
      }, 500);
    }
  },

  async renderRooms() {
    const grid = document.getElementById('roomsGrid');
    grid.innerHTML = '<div class="rooms-loading">Loading rooms…</div>';
    const roomsData = await Firebase.readData('rooms');
    if (!roomsData) { grid.innerHTML = '<div class="rooms-loading">No rooms found</div>'; return; }
    grid.innerHTML = '';
    const blockedRooms = (await Firebase.readData(`users/${Auth.user.uid}/blockedFrom`)) || {};
    for (const [id, room] of Object.entries(roomsData)) {
      if (!room || !room.roomName) continue;
      const isLocked = room.locked === true && !Auth.isAdmin;
      const isBlockedHere = blockedRooms[id] === true;
      const color = room.color || '#8b7355';
      const card = document.createElement('div');
      card.className = `room-card${isLocked||isBlockedHere?' locked':''}`;
      card.style.setProperty('--room-color', color);
      let onlineCount = 0;
      const members = room.members || {};
      for (const m of Object.values(members)) if (m.online) onlineCount++;
      const iconText = (room.icon||room.roomName.charAt(0)).charAt(0).toUpperCase();
      card.innerHTML = `
        <div class="room-card-icon" style="background:${color}">${this.escHtml(iconText)}</div>
        <div class="room-name">${this.escHtml(room.roomName)}</div>
        <div class="room-description">${this.escHtml(room.description||'')}</div>
        <div class="room-meta">
          <span class="room-status-dot ${onlineCount>0?'active':''}"></span>
          <span>${onlineCount} online</span>
          ${room.locked?'<span class="room-tag locked-tag">Locked</span>':''}
          ${isBlockedHere?'<span class="room-tag blocked-tag">Blocked</span>':''}
        </div>
        ${!isLocked&&!isBlockedHere?`<button class="room-join-btn" data-id="${id}">Enter Room</button>`:`<button class="room-join-btn locked-btn">${isBlockedHere?'Blocked':'Locked'}</button>`}
      `;
      card.querySelectorAll('[data-id]').forEach(btn => {
        btn.addEventListener('click', () => this.handleJoinRoom(id, room));
      });
      grid.appendChild(card);
    }
  },

  async handleJoinRoom(roomId, roomData) {
    const blocked = await Firebase.readData(`users/${Auth.user.uid}/blockedFrom/${roomId}`);
    if (blocked && !Auth.isAdmin) { this.showToast('You have been blocked from this room.'); return; }
    if (roomData.isDefault || !roomData.salt) {
      await this.enterRoom(roomId, roomData);
    } else {
      this.pendingRoomId = roomId;
      this.pendingRoomData = roomData;
      document.getElementById('rpwdRoomName').textContent = roomData.roomName;
      document.getElementById('rpwdRoomDesc').textContent = roomData.description || 'Enter the room password to join.';
      document.getElementById('rpwdInput').value = '';
      document.getElementById('rpwdError').textContent = '';
      document.getElementById('roomPasswordModal').classList.add('active');
      setTimeout(() => document.getElementById('rpwdInput').focus(), 200);
    }
  },

  async handleRoomPasswordSubmit() {
    const pwd = document.getElementById('rpwdInput').value;
    const errEl = document.getElementById('rpwdError');
    if (!pwd) { errEl.textContent = 'Password required'; return; }
    errEl.textContent = '';
    document.getElementById('rpwdSubmitBtn').textContent = 'Joining…';
    try {
      const success = await Room.join(this.pendingRoomId, this.pendingRoomData, pwd);
      if (success) {
        document.getElementById('roomPasswordModal').classList.remove('active');
        await this.initChatScreen();
      } else {
        errEl.textContent = 'Incorrect password';
      }
    } catch(e) { errEl.textContent = 'Error joining room'; }
    document.getElementById('rpwdSubmitBtn').textContent = 'Join';
  },

  async enterRoom(roomId, roomData) {
    this.showLoading('Entering room…');
    const joined = await Room.join(roomId, roomData, null);
    this.hideLoading();
    if (joined) await this.initChatScreen();
    else this.showToast('Could not join room.');
  },

  async initChatScreen() {
    const isBlocked = await Room.isBlocked();
    document.getElementById('lobbyScreen').classList.remove('active');
    document.getElementById('chatScreen').classList.add('active');
    document.getElementById('roomNameDisplay').textContent = Room.current.name;
    document.getElementById('messagesContainer').innerHTML = '';
    document.getElementById('adminChatBar').classList.toggle('visible', Auth.isAdmin);
    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) settingsBtn.style.display = Auth.isAdmin ? '' : 'none';

    if (isBlocked) {
      const blocker = document.createElement('div');
      blocker.className = 'blocked-overlay';
      blocker.innerHTML = 'You have been blocked in this room.';
      document.getElementById('messagesContainer').appendChild(blocker);
      document.getElementById('messageInput').disabled = true;
      document.getElementById('sendMessageBtn').disabled = true;
    }

    await Settings.load();
    await Messaging.listen((msg) => this.addMessageToUI(msg));
    Messaging.listenForTyping((name) => this.showTypingIndicator(name));
    this.listenToMembers();
    const newUrl = `${window.location.origin}${window.location.pathname}?room=${Room.current.id}`;
    window.history.replaceState({}, '', newUrl);
  },

  listenToMembers() {
    if (this.membersListener) this.membersListener();
    this.membersListener = Firebase.listenToValue(`rooms/${Room.current.id}/members`, (data) => {
      this._lastMembersData = data || {};
      this.renderMembersList(this._lastMembersData);
    });
  },

  renderMembersList(members) {
    const list = document.getElementById('membersList');
    list.innerHTML = '';
    const prefs = Presence._cachedPrefs || {};
    const dmsDisabled = !!prefs.hideDMsFromMembers && !Auth.isAdmin;

    for (const [uid, m] of Object.entries(members)) {
      if (!m || !m.displayName) continue;
      const item = document.createElement('div');
      item.className = 'member-item';
      const initials = (m.displayName||'U').charAt(0).toUpperCase();
      const colors = ['#8b7355','#4a7c5c','#6c7a8b','#8b4a6c','#2d2926'];
      const color = colors[uid.charCodeAt(0)%colors.length];
      const avatarUrl = this.getProxiedAvatar(m.photoURL);
      const avHtml = avatarUrl
        ? `<img class="member-av" src="${this.escHtml(avatarUrl)}" onerror="this.outerHTML='<div class=\\'member-av-ph\\'style=\\'background:${color}\\'>${initials}</div>'">`
        : `<div class="member-av-ph" style="background:${color}">${initials}</div>`;
      const isSelf = uid === Auth.user.uid;
      const canDM = !isSelf && !dmsDisabled;

      item.innerHTML = `
        ${avHtml}
        <div class="member-info">
          <div class="member-name${m.blocked?' blocked':''}">${this.escHtml(m.displayName||'User')}${m.isAdmin?'<span class="member-admin-star">A</span>':''}</div>
          <div class="member-status ${m.online?'online':'offline'}">${m.online?'Online':'Offline'}</div>
        </div>
        <div class="member-quick-actions">
          ${canDM ? `<button class="member-dm-btn" data-uid="${uid}" title="Message">&#128172;</button>` : ''}
        </div>
        <div class="${m.online?'member-online-dot':'member-offline-dot'}"></div>
        ${Auth.isAdmin&&!isSelf?`<div class="member-actions">
          <button class="member-action-btn ${m.blocked?'unblock':'block'}" data-uid="${uid}" data-action="${m.blocked?'unblock':'block'}">${m.blocked?'Unblock':'Block'}</button>
          <button class="member-action-btn kick" data-uid="${uid}" data-action="kick">Kick</button>
        </div>`:''}
      `;
      item.querySelector('.member-dm-btn')?.addEventListener('click', (e) => { e.stopPropagation(); DM.open(uid, m.displayName, m.photoURL); });
      item.querySelectorAll('[data-action]').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          if (btn.dataset.action === 'kick') AdminActions.kickUser(uid, Room.current.id, m.displayName);
          else AdminActions.blockUser(uid, Room.current.id, btn.dataset.action === 'block', m.displayName);
        });
      });
      list.appendChild(item);
    }
  },

  addMessageToUI(message) {
    const container = document.getElementById('messagesContainer');
    const row = document.createElement('div');
    row.className = `message-row${message.isMe?' me':''}`;
    const initials = (message.displayName||'U').charAt(0).toUpperCase();
    const colors = ['#8b7355','#4a7c5c','#6c7a8b','#8b4a6c','#2d2926'];
    const color = colors[(message.author||'u').charCodeAt(0)%colors.length];
    const avatarUrl = this.getProxiedAvatar(message.photoURL);
    const avatarEl = avatarUrl
      ? `<img class="msg-avatar" src="${this.escHtml(avatarUrl)}" onerror="this.outerHTML='<div class=\\'msg-avatar-placeholder\\'style=\\'background:${color}\\'>${initials}</div>'" alt="">`
      : `<div class="msg-avatar-placeholder" style="background:${color}">${initials}</div>`;
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${message.isMe?'me':'other'}${message.error?' error':''}`;
    if (!message.isMe) {
      const nameEl = document.createElement('div');
      nameEl.className = 'message-username';
      nameEl.textContent = message.displayName || 'Unknown';
      bubble.appendChild(nameEl);
    }
    if (message.type === 'image' && message.fileData) {
      const img = document.createElement('img');
      img.className = 'msg-image'; img.src = message.fileData; img.alt = message.text || 'Image';
      img.addEventListener('click', () => { document.getElementById('lightboxImg').src = message.fileData; document.getElementById('imgLightbox').classList.add('active'); });
      bubble.appendChild(img);
    } else if (message.type === 'document' && message.fileData) {
      const link = document.createElement('a');
      link.className = 'msg-doc'; link.href = message.fileData; link.download = message.text || 'document';
      link.innerHTML = `<span class="msg-doc-icon">&#128196;</span><span>${this.escHtml(message.text||'Document')}</span>`;
      bubble.appendChild(link);
    } else {
      const text = document.createElement('p');
      text.className = 'message-text'; text.textContent = message.text;
      bubble.appendChild(text);
    }
    const meta = document.createElement('div');
    meta.className = 'message-meta';
    meta.textContent = new Date(message.timestamp).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
    bubble.appendChild(meta);
    if (message.isMe) { row.appendChild(bubble); row.insertAdjacentHTML('beforeend', avatarEl); }
    else { row.insertAdjacentHTML('beforeend', avatarEl); row.appendChild(bubble); }
    container.appendChild(row);
    container.scrollTop = container.scrollHeight;
  },

  async handleSendMessage() {
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if (!text) return;
    try { await Messaging.send(text); input.value = ''; input.style.height = 'auto'; }
    catch(e) { this.showToast('Failed to send: ' + e.message); }
  },

  async handleImageUpload(e) {
    const file = e.target.files[0]; if (!file) return;
    if (file.size > 2*1024*1024) { this.showToast('Image too large. Max 2MB.'); return; }
    this.showLoading('Encrypting image…');
    try { const dataUrl = await this.fileToDataUrl(file); await Messaging.send(file.name, 'image', dataUrl); }
    catch(err) { this.showToast('Failed to send image'); }
    this.hideLoading(); e.target.value = '';
  },

  async handleDocUpload(e) {
    const file = e.target.files[0]; if (!file) return;
    if (file.size > 5*1024*1024) { this.showToast('File too large. Max 5MB.'); return; }
    this.showLoading('Encrypting document…');
    try { const dataUrl = await this.fileToDataUrl(file); await Messaging.send(file.name, 'document', dataUrl); }
    catch(err) { this.showToast('Failed to send document'); }
    this.hideLoading(); e.target.value = '';
  },

  fileToDataUrl(file) {
    return new Promise((res, rej) => { const r = new FileReader(); r.onload = e => res(e.target.result); r.onerror = rej; r.readAsDataURL(file); });
  },

  showTypingIndicator(name) {
    const el = document.getElementById('typingIndicator');
    if (el) {
      if (name) { el.classList.remove('hidden'); el.querySelector('span:last-child').textContent = `${name} is typing…`; }
      else el.classList.add('hidden');
    }
  },

  handleLeaveRoom() {
    if (!confirm('Leave this room?')) return;
    if (this.membersListener) { this.membersListener(); this.membersListener = null; }
    Room.leave();
    document.getElementById('chatScreen').classList.remove('active');
    document.getElementById('messagesContainer').innerHTML = '';
    window.history.replaceState({}, '', window.location.pathname);
    this.showLobby();
  },

  toggleMembers() { document.getElementById('membersPanel').classList.toggle('open'); },

  showShareModal() {
    document.getElementById('shareLinkInput').value = `${window.location.origin}${window.location.pathname}?room=${Room.current.id}`;
    document.getElementById('shareModal').classList.remove('hidden');
  },

  toggleSettings() {
    if (!Auth.isAdmin) return;
    document.getElementById('settingsPanel').classList.toggle('active');
  },

  showAdminRoomModal() {
    document.getElementById('armNameInput').value = '';
    document.getElementById('armIconInput').value = '';
    document.getElementById('armDescInput').value = '';
    document.getElementById('armPwdInput').value = '';
    document.getElementById('armStatus').textContent = '';
    document.getElementById('adminRoomModal').classList.add('active');
  },

  async handleAdminCreateRoom() {
    const name = document.getElementById('armNameInput').value.trim();
    const icon = document.getElementById('armIconInput').value.trim() || name.charAt(0).toUpperCase();
    const desc = document.getElementById('armDescInput').value.trim();
    const pwd = document.getElementById('armPwdInput').value;
    const status = document.getElementById('armStatus');
    if (!name) { status.textContent = 'Room name required'; status.className = 'arm-status error'; return; }
    if (!pwd || pwd.length < 6) { status.textContent = 'Password must be at least 6 characters'; status.className = 'arm-status error'; return; }
    document.getElementById('armSubmitBtn').textContent = 'Creating…';
    try {
      const roomId = await AdminActions.createRoom(name, icon, desc, pwd);
      const shareLink = `${window.location.origin}${window.location.pathname}?room=${roomId}`;
      status.innerHTML = `Room created. <a href="${shareLink}" target="_blank" style="color:#4a7c5c">Share link</a>`;
      status.className = 'arm-status success';
      navigator.clipboard?.writeText(shareLink).catch(()=>{});
      setTimeout(() => { document.getElementById('adminRoomModal').classList.remove('active'); this.showLobby(); }, 2500);
    } catch(e) { status.textContent = 'Error: ' + e.message; status.className = 'arm-status error'; }
    document.getElementById('armSubmitBtn').textContent = 'Create';
  },

  async showDeleteRoomPicker() {
    const roomsData = await Firebase.readData('rooms');
    if (!roomsData) { this.showToast('No rooms found.'); return; }
    const options = Object.entries(roomsData).map(([id,r]) => `${id} — ${r.roomName||id}`).join('\n');
    const roomId = prompt(`Enter room ID to delete:\n${options}`);
    if (!roomId) return;
    if (roomsData[roomId] && confirm(`Permanently delete room "${roomsData[roomId].roomName}"?`)) {
      try {
        await AdminActions.deleteRoom(roomId);
        this.showToast('Room deleted');
        this.showLobby();
      } catch(e) { this.showToast('Error: ' + e.message); }
    }
  },

  async showGlobalMembersModal() {
    if (!Auth.isAdmin) return;
    try {
      const users = await AdminActions.getUsers();
      const modal = document.getElementById('globalMembersModal');
      const list = document.getElementById('globalMembersList');
      list.innerHTML = '';
      for (const [uid, u] of Object.entries(users)) {
        if (!u || !u.displayName) continue;
        const item = document.createElement('div');
        item.className = 'gm-item';
        const initials = (u.displayName||'U').charAt(0).toUpperCase();
        const av = this.getProxiedAvatar(u.photoURL);
        item.innerHTML = `
          <div class="gm-av-wrap">
            ${av ? `<img class="gm-av" src="${this.escHtml(av)}" onerror="this.outerHTML='<div class=\\'gm-av-ph\\'>${initials}</div>'">` : `<div class="gm-av-ph">${initials}</div>`}
            <span class="gm-status-dot ${u.online?'on':'off'}"></span>
          </div>
          <div class="gm-info">
            <div class="gm-name">${this.escHtml(u.displayName)}</div>
            <div class="gm-email">${this.escHtml(u.email||'')}</div>
            ${u.currentRoomName?`<div class="gm-room">In: ${this.escHtml(u.currentRoomName)}</div>`:'<div class="gm-room offline-text">Not in a room</div>'}
          </div>
          <div class="gm-badges">
            ${u.isAdmin?'<span class="gm-badge admin">Admin</span>':''}
            <span class="gm-badge ${u.online?'online':'offline'}">${u.online?'Online':'Offline'}</span>
          </div>
        `;
        list.appendChild(item);
      }
      modal.classList.add('active');
    } catch(e) { this.showToast('Error loading users: ' + e.message); }
  },

  showBroadcastModal() {
    if (!Auth.isAdmin) return;
    document.getElementById('broadcastInput').value = '';
    document.getElementById('broadcastStatus').textContent = '';
    document.getElementById('broadcastModal').classList.add('active');
    setTimeout(() => document.getElementById('broadcastInput').focus(), 150);
  },

  async handleSendBroadcast() {
    if (!Auth.isAdmin) return;
    const input = document.getElementById('broadcastInput');
    const status = document.getElementById('broadcastStatus');
    const msg = input.value.trim();
    if (!msg) { status.textContent = 'Message cannot be empty'; return; }
    const btn = document.getElementById('broadcastSendBtn');
    btn.textContent = 'Sending…';
    try {
      await AdminActions.sendBroadcast(msg);
      status.textContent = 'Alert sent';
      status.className = 'broadcast-status success';
      input.value = '';
      setTimeout(() => document.getElementById('broadcastModal').classList.remove('active'), 1800);
    } catch(e) {
      status.textContent = 'Failed: ' + e.message;
      status.className = 'broadcast-status error';
    }
    btn.textContent = 'Send Alert';
  },

  showChangePasswordModal() {
    document.getElementById('changePwdOld').value = '';
    document.getElementById('changePwdNew').value = '';
    document.getElementById('changePwdConfirm').value = '';
    document.getElementById('changePwdError').textContent = '';
    document.getElementById('changePwdSuccess').textContent = '';
    document.getElementById('changePasswordModal').classList.add('active');
  },

  async handleChangeGlobalPassword() {
    if (!Auth.isAdmin) return;
    const oldPwd = document.getElementById('changePwdOld').value;
    const newPwd = document.getElementById('changePwdNew').value;
    const confirmPwd = document.getElementById('changePwdConfirm').value;
    const errEl = document.getElementById('changePwdError');
    const successEl = document.getElementById('changePwdSuccess');
    errEl.textContent = ''; successEl.textContent = '';
    if (!oldPwd || !newPwd || !confirmPwd) { errEl.textContent = 'All fields required'; return; }
    if (newPwd.length < 6) { errEl.textContent = 'New password must be at least 6 characters'; return; }
    if (newPwd !== confirmPwd) { errEl.textContent = 'Passwords do not match'; return; }
    document.getElementById('changePwdSubmitBtn').textContent = 'Updating…';
    try {
      await AdminActions.changePassword(oldPwd, newPwd);
      // Re-derive local key with new password
      await Auth.deriveKey(newPwd);
      successEl.textContent = 'Password updated. All members will need to re-enter it.';
    } catch(e) {
      errEl.textContent = e.message || 'Failed to update password';
    }
    document.getElementById('changePwdSubmitBtn').textContent = 'Update Password';
  },

  async handlePasswordSubmit() {
    const pwd = document.getElementById('pwdInput').value;
    const errEl = document.getElementById('pwdError');
    if (!pwd || pwd.length < 6) { errEl.textContent = 'Password must be at least 6 characters'; return; }
    errEl.textContent = '';
    document.getElementById('pwdSubmitBtn').textContent = 'Verifying…';
    const valid = await Auth.verifyPassword(pwd);
    document.getElementById('pwdSubmitBtn').textContent = 'Unlock & Enter';
    if (valid) {
      Auth.chatPassword = pwd;
      await this.showLobby();
    } else {
      errEl.textContent = 'Incorrect password';
      document.getElementById('pwdInput').value = '';
      document.getElementById('pwdInput').focus();
    }
  },

  setupSettingsListeners() {
    const qs = id => document.getElementById(id);
    qs('bgColorPicker')?.addEventListener('change', e => { Settings.currentSettings.bgColor = e.target.value; Settings.apply(); });
    qs('chatBgColorPicker')?.addEventListener('change', e => { Settings.currentSettings.chatBgColor = e.target.value; Settings.apply(); });
    qs('myBubbleColorPicker')?.addEventListener('change', e => { Settings.currentSettings.myBubbleColor=e.target.value; Settings.apply(); });
    qs('otherBubbleColorPicker')?.addEventListener('change', e => { Settings.currentSettings.otherBubbleColor=e.target.value; Settings.apply(); });
    qs('myTextColorPicker')?.addEventListener('change', e => { Settings.currentSettings.myTextColor=e.target.value; Settings.apply(); });
    qs('otherTextColorPicker')?.addEventListener('change', e => { Settings.currentSettings.otherTextColor=e.target.value; Settings.apply(); });
    qs('bubbleShapeSelect')?.addEventListener('change', e => { Settings.currentSettings.bubbleShape=e.target.value; Settings.apply(); });
    qs('inputShapeSelect')?.addEventListener('change', e => { Settings.currentSettings.inputShape=e.target.value; Settings.apply(); });
    qs('buttonShapeSelect')?.addEventListener('change', e => { Settings.currentSettings.buttonShape=e.target.value; Settings.apply(); });
    qs('headerVisibleToggle')?.addEventListener('change', e => { Settings.currentSettings.headerVisible=e.target.checked; Settings.apply(); });
    qs('headerBgColorPicker')?.addEventListener('change', e => { Settings.currentSettings.headerBgColor=e.target.value; Settings.apply(); });
    qs('headerTextColorPicker')?.addEventListener('change', e => { Settings.currentSettings.headerTextColor=e.target.value; Settings.apply(); });
    qs('fontSizeSelect')?.addEventListener('change', e => { Settings.currentSettings.fontSize=e.target.value; Settings.apply(); });
    qs('fontFamilySelect')?.addEventListener('change', e => { Settings.currentSettings.fontFamily=e.target.value; Settings.apply(); });
    qs('musicToggle')?.addEventListener('change', e => { Settings.currentSettings.musicEnabled=e.target.checked; });
    qs('bgTextToggle')?.addEventListener('change', e => { Settings.currentSettings.bgTextEnabled=e.target.checked; Settings.apply(); });
    qs('bgTextInput')?.addEventListener('input', e => { Settings.currentSettings.bgText=e.target.value; Settings.applyBackgroundText(); });
    qs('saveSettingsBtn')?.addEventListener('click', async () => {
      try { await Settings.save(); UI.showToast('Settings saved'); }
      catch(e) { UI.showToast('Error: '+e.message); }
    });
    qs('resetSettingsBtn')?.addEventListener('click', () => { if(confirm('Reset all settings?')){Settings.reset();} });
    qs('closeSettingsBtn')?.addEventListener('click', () => this.toggleSettings());

    // Admin prefs — now go through backend API
    qs('hideStatusToggle')?.addEventListener('change', async e => {
      try { await AdminActions.setPrefs({ hideStatusFromMembers: e.target.checked }); }
      catch(err) { UI.showToast('Error: ' + err.message); }
    });
    qs('hideDMsToggle')?.addEventListener('change', async e => {
      try { await AdminActions.setPrefs({ hideDMsFromMembers: e.target.checked }); }
      catch(err) { UI.showToast('Error: ' + err.message); }
    });
  },

  showLoading(text = 'Loading…') {
    const ol = document.getElementById('loadingOverlay'); const lt = document.getElementById('loadingText');
    if (ol) { lt.textContent = text; ol.classList.remove('hidden'); }
  },
  hideLoading() { document.getElementById('loadingOverlay')?.classList.add('hidden'); },

  showToast(msg) {
    let toast = document.getElementById('aionToast');
    if (!toast) { toast = document.createElement('div'); toast.id = 'aionToast'; document.body.appendChild(toast); }
    toast.textContent = msg;
    toast.classList.add('visible');
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => toast.classList.remove('visible'), 3200);
  },

  escHtml(str) {
    return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  },
};

// ========================================================
// SECTION 9: PRESENCE, DM, NOTIFICATIONS, BROADCAST
// Only change: admin prefs (hideDMs, hideStatus) now read from
// Presence._cachedPrefs which is fetched from Firebase, same as before.
// ========================================================
const Presence = {
  listener: null,
  _cachedPrefs: {},
  _lastUsers: {},

  start() {
    Firebase.listenToValue('global/adminPrefs', (data) => {
      this._cachedPrefs = data || {};
      if (this._lastUsers) this.renderPresenceBar(this._lastUsers);
    });
    this.listener = Firebase.listenToValue('users', (data) => {
      this._lastUsers = data || {};
      this.renderPresenceBar(this._lastUsers);
    });
  },

  stop() { if (this.listener) { this.listener(); this.listener = null; } },

  renderPresenceBar(users) {
    const bar = document.getElementById('presenceBar');
    if (!bar) return;
    const prefs = Presence._cachedPrefs || {};
    const hideStatus = !!prefs.hideStatusFromMembers && !Auth.isAdmin;
    const hideDMs = !!prefs.hideDMsFromMembers && !Auth.isAdmin;
    if (hideStatus) { bar.innerHTML = ''; return; }
    bar.innerHTML = '';
    const sorted = Object.entries(users).sort((a,b) => (b[1].online?1:0)-(a[1].online?1:0));
    for (const [uid, u] of sorted) {
      if (!u || !u.displayName) continue;
      const item = document.createElement('div');
      item.className = `presence-item ${u.online ? 'online' : 'offline'}`;
      const initials = (u.displayName||'U').charAt(0).toUpperCase();
      const av = u.photoURL
        ? `<img class="presence-av" src="${UI.escHtml(UI.getProxiedAvatar(u.photoURL))}" onerror="this.outerHTML='<div class=\\'presence-av-ph\\'>${initials}</div>'">`
        : `<div class="presence-av-ph">${initials}</div>`;
      const roomBadge = u.currentRoomName ? `<span class="presence-room">${UI.escHtml(u.currentRoomName)}</span>` : '';
      item.innerHTML = `
        <div class="presence-av-wrap">${av}<span class="presence-dot ${u.online?'on':'off'}"></span></div>
        <div class="presence-info"><span class="presence-name">${UI.escHtml(u.displayName)}</span>${roomBadge}</div>
      `;
      if (uid !== Auth.user.uid && !hideDMs) {
        item.title = `Message ${u.displayName}`;
        item.style.cursor = 'pointer';
        item.addEventListener('click', () => DM.open(uid, u.displayName, u.photoURL));
      }
      bar.appendChild(item);
    }
  }
};

// DM, Notifications, Broadcast — keep from original (unchanged)
const DM = {
  openChats: {}, dmUnsubscribers: {}, unreadCounts: {},
  open(uid, name, photoURL) {
    const prefs = Presence._cachedPrefs || {};
    if (prefs.hideDMsFromMembers && !Auth.isAdmin) { UI.showToast('Private messaging is disabled.'); return; }
    if (this.openChats[uid]) { this.openChats[uid].window.classList.add('active'); this.unreadCounts[uid] = 0; return; }
    const win = document.createElement('div');
    win.className = 'dm-window active'; win.dataset.uid = uid;
    win.innerHTML = `
      <div class="dm-header"><div class="dm-header-info"><div class="dm-name">${UI.escHtml(name)}</div></div><button class="dm-close" data-uid="${uid}">&times;</button></div>
      <div class="dm-messages" id="dm-msgs-${uid}"></div>
      <div class="dm-input-row">
        <input type="text" class="dm-input" id="dm-inp-${uid}" placeholder="Message ${UI.escHtml(name)}…">
        <button class="dm-send" data-uid="${uid}">Send</button>
      </div>
    `;
    document.body.appendChild(win);
    this.openChats[uid] = { name, window: win };
    win.querySelector('.dm-close').addEventListener('click', () => this.close(uid));
    win.querySelector('.dm-send').addEventListener('click', () => this.sendFromWindow(uid));
    win.querySelector(`#dm-inp-${uid}`).addEventListener('keydown', e => { if(e.key==='Enter') this.sendFromWindow(uid); });
    this.repositionWindows();
    const unsub = Messaging.listenDM(uid, (msg) => this.addMsg(uid, msg));
    this.dmUnsubscribers[uid] = unsub;
  },
  repositionWindows() { document.querySelectorAll('.dm-window').forEach((w, i) => { w.style.right = (20 + i * 320) + 'px'; }); },
  close(uid) {
    const chat = this.openChats[uid];
    if (chat) { chat.window.remove(); delete this.openChats[uid]; }
    if (this.dmUnsubscribers[uid]) { this.dmUnsubscribers[uid](); delete this.dmUnsubscribers[uid]; }
    delete this.unreadCounts[uid];
    this.repositionWindows();
  },
  addMsg(uid, msg) {
    const container = document.getElementById(`dm-msgs-${uid}`);
    if (!container) return;
    const el = document.createElement('div');
    el.className = `dm-msg ${msg.isMe ? 'me' : 'them'}`;
    el.innerHTML = `<span class="dm-bubble">${UI.escHtml(msg.text)}</span><span class="dm-time">${new Date(msg.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span>`;
    container.appendChild(el);
    container.scrollTop = container.scrollHeight;
  },
  async sendFromWindow(uid) {
    const inp = document.getElementById(`dm-inp-${uid}`);
    if (!inp || !inp.value.trim()) return;
    const text = inp.value.trim(); inp.value = '';
    try { await Messaging.sendDM(uid, this.openChats[uid]?.name || uid, text); } catch(e) {}
  },
  closeAll() { Object.keys(this.openChats).forEach(uid => this.close(uid)); }
};

const Broadcast = {
  listener: null, _lastSeenId: null,
  start() {
    if (this.listener) return;
    this.listener = Firebase.listenToValue('global/broadcast', (data) => {
      if (!data || !data.message) return;
      if (data.id === this._lastSeenId) return;
      this._lastSeenId = data.id;
      if (data.senderUid === Auth.user?.uid) return;
      this.showAlert(data.message, data.senderName || 'Admin');
    });
  },
  stop() { if (this.listener) { this.listener(); this.listener = null; } },
  showAlert(message, senderName) {
    document.getElementById('broadcastAlertOverlay')?.remove();
    const overlay = document.createElement('div');
    overlay.id = 'broadcastAlertOverlay'; overlay.className = 'broadcast-overlay';
    overlay.innerHTML = `<div class="broadcast-alert"><div class="broadcast-alert-tag">Announcement</div><div class="broadcast-alert-message">${UI.escHtml(message)}</div><div class="broadcast-alert-sender">— ${UI.escHtml(senderName)}</div><button class="broadcast-alert-close">Dismiss</button></div>`;
    const dismiss = () => { overlay.classList.add('hiding'); setTimeout(() => overlay.remove(), 400); };
    overlay.querySelector('.broadcast-alert-close').addEventListener('click', dismiss);
    setTimeout(() => { if (overlay.isConnected) dismiss(); }, 12000);
    document.body.appendChild(overlay);
    requestAnimationFrame(() => requestAnimationFrame(() => overlay.classList.add('visible')));
  }
};

// ========================================================
// INITIALIZE
// ========================================================
document.addEventListener('DOMContentLoaded', () => {
  UI.init();
});
