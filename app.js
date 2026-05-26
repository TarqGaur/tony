/**
 * ========================================================
 * AION ENCRYPTED GROUP CHAT — v2 ENHANCED
 * All changes applied:
 * - Member presence shown to everyone (online/offline + which room)
 * - Admin can hide member status & hide DMs from others
 * - Google avatar fixed (proxy fallback)
 * - Admin has full settings access; settings btn hidden from non-admins
 * - Contrasting chat colors
 * - Room URL sharing (direct room join after auth)
 * - Admin can create custom rooms joinable via link
 * - Admin can change global entry password
 * - Improved admin panel UI
 * - No emojis in UI chrome; professional aesthetic
 * ========================================================
 */

// ========================================================
// SECTION 1: CRYPTO UTILITIES
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
    // Single consistent key derivation — always PBKDF2 via WebCrypto (built into every browser,
    // no external dependency, deterministic across all devices). Argon2 was removed because the
    // CDN script loaded inconsistently, causing different devices to derive different keys from
    // the same password and silently locking everyone out.
    async deriveKeyArgon2(password, salt) {
        return this.deriveKeyPBKDF2(password, salt);
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
    async createRoomCheck(key) { return await this.aesGcmEncrypt(key, 'ROOM_OK'); },
    async verifyRoomPassword(key, roomCheck) {
        try { return (await this.aesGcmDecrypt(key, roomCheck.ciphertext, roomCheck.iv)) === 'ROOM_OK'; } catch(e) { return false; }
    }
};

// ========================================================
// SECTION 2: FIREBASE + AUTH CONFIGURATION
// ========================================================
const ADMIN_EMAILS = ['tarqgaur7@gmail.com'];

const DEFAULT_ROOMS = [
    { id: 'general',   name: 'General',    icon: 'G', description: 'Open discussion — say anything', color: '#8b7355' },
    { id: 'creative',  name: 'Creative',   icon: 'C', description: 'Art, music, design and ideas',   color: '#6c7a8b' },
    { id: 'tech',      name: 'Tech',       icon: 'T', description: 'Code, gadgets and digital life',  color: '#4a7c5c' },
    { id: 'random',    name: 'Random',     icon: 'R', description: 'Fun, memes and everything else',  color: '#8b4a6c' },
    { id: 'private',   name: 'Private',    icon: 'P', description: 'Invitation-only secure lounge',   color: '#2d2926' },
];

const Firebase = {
    app: null, db: null, auth: null,
    ref: null, set: null, get: null, push: null,
    onChildAdded: null, onValue: null, update: null, off: null,
    remove: null, serverTimestamp: null,
    signInWithPopup: null, GoogleAuthProvider: null, onAuthStateChanged: null, signOut: null,

    async init() {
        const firebaseConfig = {
            apiKey: "AIzaSyAS_HheqFK98UIvjtiBxtHSOkOfuaOkkug",
            authDomain: "kwit-5dde3.firebaseapp.com",
            databaseURL: "https://kwit-5dde3-default-rtdb.firebaseio.com",
            projectId: "kwit-5dde3",
            storageBucket: "kwit-5dde3.firebasestorage.app",
            messagingSenderId: "692601571855",
            appId: "1:692601571855:web:03e8538f22f47202a5f17a"
        };
        try {
            const { initializeApp } = await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js');
            const { getDatabase, ref, set, get, push, onChildAdded, onValue, update, off, remove, serverTimestamp } =
                await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-database.js');
            const { getAuth, signInWithPopup, GoogleAuthProvider, onAuthStateChanged, signOut } =
                await import('https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js');

            this.app = initializeApp(firebaseConfig);
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
    async deleteData(path) { await this.remove(this.ref(this.db, path)); },
    getServerTimestamp() { return { '.sv': 'timestamp' }; }
};

// ========================================================
// SECTION 3: AUTH STATE
// ========================================================
const Auth = {
    user: null,
    isAdmin: false,
    chatPassword: null,
    masterKey: null,

    async signInWithGoogle() {
        const provider = new Firebase.GoogleAuthProvider();
        return await Firebase.signInWithPopup(Firebase.auth, provider);
    },

    async signOut() {
        this.user = null; this.isAdmin = false; this.chatPassword = null; this.masterKey = null;
        await Firebase.signOut(Firebase.auth);
    },

    async deriveKey(password) {
        const salt = await this.getGlobalSalt();
        this.masterKey = await Crypto.deriveKeyArgon2(password, salt);
        return this.masterKey;
    },

    async getGlobalSalt() {
        let saltB64 = await Firebase.readData('global/salt');
        if (!saltB64) {
            const salt = Crypto.generateRandomBytes(16);
            saltB64 = Crypto.arrayBufferToBase64(salt);
            await Firebase.writeData('global/salt', saltB64);
        }
        return Crypto.base64ToArrayBuffer(saltB64);
    },

    async verifyPassword(password) {
        try {
            UI.showLoading('Verifying password…');
            const key = await this.deriveKey(password);
            const check = await Firebase.readData('global/passwordCheck');
            if (!check) {
                // No password has been set yet — only admin is allowed to initialise it.
                // Regular users should not be able to accidentally set the global password
                // just by being the first one to open the page.
                if (ADMIN_EMAILS.includes(Auth.user?.email)) {
                    // Admin is setting the password for the first time — create the check token.
                    const token = await Crypto.createRoomCheck(key);
                    await Firebase.writeData('global/passwordCheck', token);
                    UI.hideLoading();
                    return true;
                } else {
                    // Non-admin on first load: password not configured yet, reject.
                    UI.hideLoading();
                    return false;
                }
            }
            const valid = await Crypto.verifyRoomPassword(key, check);
            UI.hideLoading();
            return valid;
        } catch(e) { UI.hideLoading(); return false; }
    },

    // Admin: change global entry password
    async changeGlobalPassword(oldPassword, newPassword) {
        const valid = await this.verifyPassword(oldPassword);
        if (!valid) return { success: false, error: 'Current password is incorrect' };
        try {
            const newSalt = Crypto.generateRandomBytes(16);
            const newSaltB64 = Crypto.arrayBufferToBase64(newSalt);
            const newKey = await Crypto.deriveKeyArgon2(newPassword, newSalt);
            const newCheck = await Crypto.createRoomCheck(newKey);
            await Firebase.writeData('global/salt', newSaltB64);
            await Firebase.writeData('global/passwordCheck', newCheck);
            this.masterKey = newKey;
            this.chatPassword = newPassword;
            return { success: true };
        } catch(e) { return { success: false, error: e.message }; }
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
// ========================================================
const Room = {
    current: { id: null, name: null, masterKey: null, userId: null, username: null },

    generateRoomId() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const bytes = new Uint8Array(12); crypto.getRandomValues(bytes);
        return Array.from(bytes, b => chars[b % chars.length]).join('');
    },

    async ensureDefaultRooms() {
        for (const room of DEFAULT_ROOMS) {
            const existing = await Firebase.readData(`rooms/${room.id}`);
            if (!existing) {
                await Firebase.writeData(`rooms/${room.id}`, {
                    roomName: room.name, icon: room.icon, description: room.description,
                    color: room.color, isDefault: true,
                    createdAt: Firebase.getServerTimestamp()
                });
            }
        }
    },

    async createRoom(name, icon, description, password) {
        const roomId = this.generateRoomId();
        const salt = Crypto.generateRandomBytes(16);
        const saltB64 = Crypto.arrayBufferToBase64(salt);
        const key = await Crypto.deriveKeyArgon2(password, salt);
        const roomCheck = await Crypto.createRoomCheck(key);
        await Firebase.writeData(`rooms/${roomId}`, {
            roomName: name,
            icon: icon || name.charAt(0).toUpperCase(),
            description: description || '',
            color: '#8b7355',
            salt: saltB64, roomCheck,
            isDefault: false,
            createdAt: Firebase.getServerTimestamp()
        });
        return roomId;
    },

    async deleteRoom(roomId) {
        await Firebase.deleteData(`rooms/${roomId}`);
        await Firebase.deleteData(`messages/${roomId}`);
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
        const salt = Crypto.base64ToArrayBuffer(roomData.salt);
        const key = await Crypto.deriveKeyArgon2(password, salt);
        const valid = await Crypto.verifyRoomPassword(key, roomData.roomCheck);
        if (!valid) return false;
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
        // Also update global user presence
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
// SECTION 5: MESSAGING
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
// SECTION 6: SETTINGS
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
            // Admin-only toggles
            hideStatusFromMembers: false,
            hideDMsFromMembers: false
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
        if (s.robotProvider && window.ROBOT_PROVIDER !== undefined) {
            window.ROBOT_PROVIDER = s.robotProvider;
            document.querySelectorAll('.provider-btn').forEach(b => b.classList.toggle('active', b.dataset.provider === s.robotProvider));
        }
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
        if (s.musicFile) { document.getElementById('musicControls')?.classList.remove('hidden'); st('musicFileName','Music loaded'); }
        // Admin toggle UI
        sc('hideStatusToggle', !!s.hideStatusFromMembers);
        sc('hideDMsToggle', !!s.hideDMsFromMembers);
        if (s.robotProvider) {
            document.querySelectorAll('.provider-btn').forEach(b => b.classList.toggle('active', b.dataset.provider === s.robotProvider));
            const labels = { cerebras:'Cerebras — Fastest',groq:'Groq — Fast',openrouter:'OpenRouter — Wide selection',nvidia:'NVIDIA — High quality',inception:'Mercury 2 — Diffusion LLM' };
            st('providerStatus', labels[s.robotProvider] || s.robotProvider);
        }
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
// SECTION 7: DM WINDOW
// ========================================================
const DM = {
    openChats: {},  // uid -> { name, window, msgs }
    dmUnsubscribers: {},

    unreadCounts: {}, // uid -> unread count

    open(uid, name, photoURL) {
        // Check if admin has disabled DMs
        const dmPrefs = Presence._cachedPrefs || Settings.currentSettings || {};
        if (dmPrefs.hideDMsFromMembers && !Auth.isAdmin) {
            UI.showToast('Private messaging is currently disabled by admin.');
            return;
        }
        if (this.openChats[uid]) {
            this.openChats[uid].window.classList.add('active');
            // Mark as read
            this.unreadCounts[uid] = 0;
            Notifications.updateDMBadge();
            return;
        }
        const win = document.createElement('div');
        win.className = 'dm-window active';
        win.dataset.uid = uid;
        win.innerHTML = `
            <div class="dm-header">
                <div class="dm-header-info">
                    <div class="dm-av">${this.avatarEl(uid, name, photoURL)}</div>
                    <div class="dm-name">${UI.escHtml(name)}</div>
                </div>
                <button class="dm-close" data-uid="${uid}">&times;</button>
            </div>
            <div class="dm-messages" id="dm-msgs-${uid}"></div>
            <div class="dm-input-row">
                <button class="dm-attach-btn" data-uid="${uid}" title="Attach">+</button>
                <div class="dm-attach-menu" id="dm-attach-menu-${uid}">
                    <div class="dm-attach-opt" data-type="image" data-uid="${uid}">&#128247; Image</div>
                    <div class="dm-attach-opt" data-type="doc" data-uid="${uid}">&#128196; Document</div>
                </div>
                <input type="file" accept="image/*" id="dm-img-inp-${uid}" hidden>
                <input type="file" id="dm-doc-inp-${uid}" hidden>
                <input type="text" class="dm-input" id="dm-inp-${uid}" placeholder="Message ${UI.escHtml(name)}…">
                <button class="dm-send" data-uid="${uid}">Send</button>
            </div>
        `;
        document.body.appendChild(win);
        this.openChats[uid] = { name, window: win, count: Object.keys(this.openChats).length };

        win.querySelector('.dm-close').addEventListener('click', () => this.close(uid));
        win.querySelector('.dm-send').addEventListener('click', () => this.sendFromWindow(uid));
        win.querySelector(`#dm-inp-${uid}`).addEventListener('keydown', e => { if(e.key==='Enter') this.sendFromWindow(uid); });
        // Clear unread when window is focused
        win.addEventListener('click', () => {
            this.unreadCounts[uid] = 0;
            Notifications.updateDMBadge();
        });

        // Attach button toggle
        win.querySelector('.dm-attach-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            const menu = win.querySelector(`#dm-attach-menu-${uid}`);
            menu.classList.toggle('visible');
        });
        // Attach options
        win.querySelectorAll('.dm-attach-opt').forEach(opt => {
            opt.addEventListener('click', () => {
                win.querySelector(`#dm-attach-menu-${uid}`).classList.remove('visible');
                if (opt.dataset.type === 'image') win.querySelector(`#dm-img-inp-${uid}`).click();
                else win.querySelector(`#dm-doc-inp-${uid}`).click();
            });
        });
        win.querySelector(`#dm-img-inp-${uid}`).addEventListener('change', e => this.handleImageUpload(uid, e));
        win.querySelector(`#dm-doc-inp-${uid}`).addEventListener('change', e => this.handleDocUpload(uid, e));
        // Close attach menu on outside click
        document.addEventListener('click', () => {
            win.querySelector(`#dm-attach-menu-${uid}`)?.classList.remove('visible');
        });

        // Position windows
        this.repositionWindows();

        // Listen
        const unsub = Messaging.listenDM(uid, (msg) => this.addMsg(uid, msg));
        this.dmUnsubscribers[uid] = unsub;
    },

    avatarEl(uid, name, photoURL) {
        if (photoURL) return `<img src="${UI.escHtml(UI.getProxiedAvatar(photoURL))}" style="width:28px;height:28px;border-radius:50%;object-fit:cover;" onerror="this.parentNode.innerHTML='<div class=\\'dm-av-ph\\'>${(name||'U').charAt(0).toUpperCase()}</div>'">`;
        return `<div class="dm-av-ph">${(name||'U').charAt(0).toUpperCase()}</div>`;
    },

    repositionWindows() {
        const wins = document.querySelectorAll('.dm-window');
        wins.forEach((w, i) => { w.style.right = (20 + i * 320) + 'px'; });
    },

    close(uid) {
        const chat = this.openChats[uid];
        if (chat) { chat.window.remove(); delete this.openChats[uid]; }
        if (this.dmUnsubscribers[uid]) { this.dmUnsubscribers[uid](); delete this.dmUnsubscribers[uid]; }
        delete this.unreadCounts[uid];
        Notifications.updateDMBadge();
        this.repositionWindows();
    },

    addMsg(uid, msg) {
        const container = document.getElementById(`dm-msgs-${uid}`);
        if (!container) return;

        // Track unread if window not focused
        if (!msg.isMe) {
            const win = this.openChats[uid]?.window;
            // Only notify when the DM window is NOT open/active
            const isOpen = win && win.classList.contains('active');
            if (!isOpen) {
                this.unreadCounts[uid] = (this.unreadCounts[uid] || 0) + 1;
                Notifications.updateDMBadge();
                Notifications.showDMToast(uid, msg.displayName, msg.text, this.openChats[uid]?.window?.querySelector('.dm-av')?.cloneNode(true));
            }
        }
        const el = document.createElement('div');
        el.className = `dm-msg ${msg.isMe ? 'me' : 'them'}`;

        let bubbleContent = '';
        if (msg.type === 'image' && msg.fileData) {
            bubbleContent = `<span class="dm-bubble dm-bubble-media"><img class="dm-img-preview" src="${UI.escHtml(msg.fileData)}" alt="${UI.escHtml(msg.text||'Image')}" style="max-width:200px;max-height:180px;border-radius:8px;display:block;cursor:zoom-in;"></span>`;
        } else if (msg.type === 'document' && msg.fileData) {
            bubbleContent = `<span class="dm-bubble dm-bubble-doc"><a href="${UI.escHtml(msg.fileData)}" download="${UI.escHtml(msg.text||'document')}" style="display:flex;align-items:center;gap:8px;color:inherit;text-decoration:none;"><span style="font-size:1.2rem;">&#128196;</span><span style="font-size:0.78rem;word-break:break-all;">${UI.escHtml(msg.text||'Document')}</span></a></span>`;
        } else {
            bubbleContent = `<span class="dm-bubble">${UI.escHtml(msg.text)}</span>`;
        }

        el.innerHTML = `${bubbleContent}<span class="dm-time">${new Date(msg.timestamp).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span>`;

        // Image click → lightbox
        const imgEl = el.querySelector('.dm-img-preview');
        if (imgEl) {
            imgEl.addEventListener('click', () => {
                document.getElementById('lightboxImg').src = msg.fileData;
                document.getElementById('imgLightbox').classList.add('active');
            });
        }

        container.appendChild(el);
        container.scrollTop = container.scrollHeight;
    },

    async sendFromWindow(uid) {
        const inp = document.getElementById(`dm-inp-${uid}`);
        if (!inp || !inp.value.trim()) return;
        const text = inp.value.trim();
        inp.value = '';
        try {
            await Messaging.sendDM(uid, this.openChats[uid]?.name || uid, text, 'text', null);
        } catch(e) { console.error('DM send failed', e); }
    },

    async handleImageUpload(uid, e) {
        const file = e.target.files[0]; if (!file) return;
        if (file.size > 2*1024*1024) { UI.showToast('Image too large. Max 2MB.'); return; }
        UI.showLoading('Encrypting image…');
        try {
            const dataUrl = await UI.fileToDataUrl(file);
            await Messaging.sendDM(uid, this.openChats[uid]?.name || uid, file.name, 'image', dataUrl);
        } catch(err) { UI.showToast('Failed to send image'); }
        UI.hideLoading(); e.target.value = '';
    },

    async handleDocUpload(uid, e) {
        const file = e.target.files[0]; if (!file) return;
        if (file.size > 5*1024*1024) { UI.showToast('File too large. Max 5MB.'); return; }
        UI.showLoading('Encrypting document…');
        try {
            const dataUrl = await UI.fileToDataUrl(file);
            await Messaging.sendDM(uid, this.openChats[uid]?.name || uid, file.name, 'document', dataUrl);
        } catch(err) { UI.showToast('Failed to send document'); }
        UI.hideLoading(); e.target.value = '';
    },

    closeAll() {
        Object.keys(this.openChats).forEach(uid => this.close(uid));
    }
};

// ========================================================
// SECTION 8: PRESENCE PANEL (all users visible to all)
// ========================================================
const Presence = {
    listener: null,
    panelVisible: false,

    start() {
        this._cachedPrefs = {};
        // Load + live-listen to admin prefs so hide-status/hide-DMs work from the lobby
        Firebase.listenToValue('global/adminPrefs', (data) => {
            this._cachedPrefs = data || {};
            // Re-render presence with latest prefs
            if (this._lastUsers) this.renderPresenceBar(this._lastUsers);
            // Also sync lobby checkboxes for admin
            if (Auth.isAdmin) {
                const hst = document.getElementById('hideStatusToggle');
                const hdt = document.getElementById('hideDMsToggle');
                const dct = document.getElementById('disableCallsToggle');
                const lvt = document.getElementById('lockVoiceRoomToggle');
                if (hst) hst.checked = !!this._cachedPrefs.hideStatusFromMembers;
                if (hdt) hdt.checked = !!this._cachedPrefs.hideDMsFromMembers;
                if (dct) dct.checked = !!this._cachedPrefs.disableCalls;
                if (lvt) lvt.checked = !!this._cachedPrefs.lockVoiceRoom;
                // Update chat bar button labels
                const dbtn = document.getElementById('adminDisableCallsBtn');
                const lbtn = document.getElementById('adminLockVoiceBtn');
                if (dbtn) dbtn.textContent = this._cachedPrefs.disableCalls ? 'Enable Calls' : 'Disable Calls';
                if (lbtn) lbtn.textContent = this._cachedPrefs.lockVoiceRoom ? 'Unlock Voice Room' : 'Lock Voice Room';
            }
            // Re-render member list in chat (reflects call/DM permission changes live)
            if (UI.membersListener && UI._lastMembersData) {
                UI.renderMembersList(UI._lastMembersData);
            }
        });
        this.listener = Firebase.listenToValue('users', (data) => {
            this._lastUsers = data || {};
            this.renderPresenceBar(this._lastUsers);
        });
    },

    stop() {
        if (this.listener) { this.listener(); this.listener = null; }
    },

    renderPresenceBar(users) {
        const bar = document.getElementById('presenceBar');
        if (!bar) return;
        // Merge room settings (if in room) with cached global prefs (for lobby)
        const prefs = Settings.currentSettings || Presence._cachedPrefs || {};
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
                <div class="presence-info">
                    <span class="presence-name">${UI.escHtml(u.displayName)}</span>
                    ${roomBadge}
                </div>
            `;
            // Click to DM (if not self, and DMs not disabled by admin)
            if (uid !== Auth.user.uid && !hideDMs) {
                item.title = `Message ${u.displayName}`;
                item.style.cursor = 'pointer';
                item.addEventListener('click', () => DM.open(uid, u.displayName, u.photoURL));
            }
            bar.appendChild(item);
        }
    }
};

// ========================================================
// SECTION 8.5: NOTIFICATIONS
// ========================================================
const Notifications = {
    _dmToastQueue: [],
    _dmToastVisible: false,

    updateDMBadge() {
        const total = Object.values(DM.unreadCounts).reduce((a, b) => a + b, 0);
        const badge = document.getElementById('dmNotifBadge');
        const bell = document.getElementById('dmNotifBell');
        if (!badge || !bell) return;
        if (total > 0) {
            badge.textContent = total > 99 ? '99+' : total;
            badge.classList.add('visible');
            bell.classList.add('has-unread');
        } else {
            badge.classList.remove('visible');
            bell.classList.remove('has-unread');
        }
    },

    showDMToast(uid, senderName, text, _avatarEl) {
        const existing = document.getElementById(`dm-notif-toast-${uid}`);
        if (existing) {
            // Update existing toast
            const msgEl = existing.querySelector('.dm-notif-text');
            if (msgEl) msgEl.textContent = text.length > 60 ? text.slice(0, 60) + '…' : text;
            existing.classList.add('bump');
            setTimeout(() => existing.classList.remove('bump'), 300);
            clearTimeout(existing._dismissTimer);
            existing._dismissTimer = setTimeout(() => this._dismissDMToast(uid), 5000);
            return;
        }

        const toast = document.createElement('div');
        toast.className = 'dm-notif-toast';
        toast.id = `dm-notif-toast-${uid}`;
        const initials = (senderName || 'U').charAt(0).toUpperCase();
        const preview = text ? (text.length > 60 ? text.slice(0, 60) + '…' : text) : 'Sent an attachment';
        toast.innerHTML = `
            <div class="dm-notif-av">${initials}</div>
            <div class="dm-notif-body">
                <div class="dm-notif-name">${UI.escHtml(senderName)}</div>
                <div class="dm-notif-text">${UI.escHtml(preview)}</div>
            </div>
            <button class="dm-notif-open" data-uid="${uid}">Open</button>
            <button class="dm-notif-dismiss" data-uid="${uid}">&times;</button>
        `;
        toast.querySelector('.dm-notif-open').addEventListener('click', () => {
            this._dismissDMToast(uid);
            const chat = DM.openChats[uid];
            if (chat) { chat.window.classList.add('active'); DM.unreadCounts[uid] = 0; this.updateDMBadge(); }
        });
        toast.querySelector('.dm-notif-dismiss').addEventListener('click', () => this._dismissDMToast(uid));

        const container = document.getElementById('dmToastContainer');
        if (container) container.appendChild(toast);
        // Animate in
        requestAnimationFrame(() => { requestAnimationFrame(() => toast.classList.add('visible')); });

        toast._dismissTimer = setTimeout(() => this._dismissDMToast(uid), 5000);
    },

    _dismissDMToast(uid) {
        const toast = document.getElementById(`dm-notif-toast-${uid}`);
        if (!toast) return;
        toast.classList.remove('visible');
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 350);
    },

    dismissAll() {
        document.querySelectorAll('.dm-notif-toast').forEach(t => t.remove());
    }
};

// ========================================================
// SECTION 8.6: BROADCAST ALERTS (Admin → Everyone)
// ========================================================
const Broadcast = {
    listener: null,
    _lastSeenId: null,

    _getDismissed() {
        try { return JSON.parse(sessionStorage.getItem('aion_dismissed_broadcasts') || '[]'); } catch(e) { return []; }
    },
    _markDismissed(id) {
        try {
            const list = this._getDismissed();
            if (!list.includes(id)) { list.push(id); sessionStorage.setItem('aion_dismissed_broadcasts', JSON.stringify(list.slice(-20))); }
        } catch(e) {}
    },

    start() {
        if (this.listener) return;
        this.listener = Firebase.listenToValue('global/broadcast', (data) => {
            if (!data || !data.message) return;
            if (data.id === this._lastSeenId) return;
            this._lastSeenId = data.id;
            // Don't show to admin who sent it
            if (data.senderUid === Auth.user?.uid) return;
            // Don't re-show alerts already dismissed this session
            if (this._getDismissed().includes(data.id)) return;
            this.showAlert(data.message, data.senderName || 'Admin', data.id);
        });
    },

    stop() {
        if (this.listener) { this.listener(); this.listener = null; }
    },

    async send(message) {
        if (!Auth.isAdmin || !message.trim()) return;
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2);
        const payload = {
            id,
            message: message.trim(),
            senderUid: Auth.user.uid,
            senderName: Auth.user.displayName || 'Admin',
            sentAt: Firebase.getServerTimestamp()
        };
        // Write both to active broadcast and to history list
        await Firebase.writeData('global/broadcast', payload);
        await Firebase.writeData(`global/broadcastHistory/${id}`, payload);
    },

    async deleteAlert(id) {
        // Clear active broadcast if it's this one
        const active = await Firebase.readData('global/broadcast');
        if (active && active.id === id) await Firebase.deleteData('global/broadcast');
        await Firebase.deleteData(`global/broadcastHistory/${id}`);
    },

    async clearAll() {
        await Firebase.deleteData('global/broadcast');
        await Firebase.deleteData('global/broadcastHistory');
    },

    showAlert(message, senderName, id) {
        // Remove any existing
        document.getElementById('broadcastAlertOverlay')?.remove();

        const overlay = document.createElement('div');
        overlay.id = 'broadcastAlertOverlay';
        overlay.className = 'broadcast-overlay';
        overlay.innerHTML = `
            <div class="broadcast-alert">
                <div class="broadcast-alert-tag">Announcement</div>
                <div class="broadcast-alert-icon">&#9741;</div>
                <div class="broadcast-alert-message">${UI.escHtml(message)}</div>
                <div class="broadcast-alert-sender">— ${UI.escHtml(senderName)}</div>
                <button class="broadcast-alert-close">Dismiss</button>
            </div>
        `;
        const dismiss = () => {
            if (id) this._markDismissed(id);
            overlay.classList.add('hiding');
            setTimeout(() => overlay.remove(), 400);
        };
        overlay.querySelector('.broadcast-alert-close').addEventListener('click', dismiss);
        // Auto-dismiss after 12s
        setTimeout(() => { if (overlay.isConnected) dismiss(); }, 12000);

        document.body.appendChild(overlay);
        requestAnimationFrame(() => { requestAnimationFrame(() => overlay.classList.add('visible')); });
    }
};

// ========================================================
// SECTION 9: UI CONTROLLER
// ========================================================
const UI = {
    pendingRoomId: null,
    pendingRoomData: null,
    membersListener: null,

    // Fix Google avatar: use proxy to avoid CORS/CSP issues
    getProxiedAvatar(url) {
        if (!url) return '';
        // Remove size restrictions from Google photo URLs and ensure HTTPS
        if (url.includes('googleusercontent.com')) {
            // Remove =s96-c or similar size params and replace with larger
            return url.replace(/=s\d+-c/, '=s128-c').replace(/=s\d+/, '=s128');
        }
        return url;
    },

    async init() {
        const ok = await Firebase.init();
        if (!ok) { alert('Firebase configuration error'); return; }

        this.createParticles();

        Firebase.onAuthStateChanged(Firebase.auth, async (user) => {
            if (user) {
                Auth.user = user;
                Auth.isAdmin = ADMIN_EMAILS.includes(user.email);
                Auth.storeUserProfile();

                // Check for room URL param
                const params = new URLSearchParams(window.location.search);
                const roomParam = params.get('room');
                if (roomParam) {
                    this._pendingRoomFromUrl = roomParam;
                }
                this.showPasswordScreen();
            } else {
                Auth.setOnlineStatus && Auth.setOnlineStatus(false);
                this.showSplash();
            }
        });

        document.getElementById('googleSignInBtn').addEventListener('click', async () => {
            try {
                document.getElementById('googleSignInBtn').textContent = 'Signing in…';
                await Auth.signInWithGoogle();
            } catch(e) {
                document.getElementById('googleSignInBtn').innerHTML = '<img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" style="width:20px"> Try again';
            }
        });

        document.getElementById('pwdSubmitBtn').addEventListener('click', () => this.handlePasswordSubmit());
        document.getElementById('pwdInput').addEventListener('keydown', e => { if(e.key==='Enter') this.handlePasswordSubmit(); });
        document.getElementById('pwdSignoutBtn').addEventListener('click', async () => { await Auth.signOut(); this.showSplash(); });
        document.getElementById('lobbySignoutBtn').addEventListener('click', async () => { DM.closeAll(); Presence.stop(); await Auth.signOut(); this.showSplash(); });

        // Admin lobby buttons
        document.getElementById('createRoomAdminBtn').addEventListener('click', () => this.showAdminRoomModal('create'));
        document.getElementById('deleteRoomAdminBtn').addEventListener('click', () => this.showDeleteRoomPicker());
        document.getElementById('viewMembersAdminBtn').addEventListener('click', () => this.showGlobalMembersModal());
        document.getElementById('manageBannedBtn').addEventListener('click', () => this.showBannedList());
        document.getElementById('changePasswordAdminBtn').addEventListener('click', () => this.showChangePasswordModal());

        // Broadcast alert buttons (lobby + chat)
        document.getElementById('broadcastAlertBtn')?.addEventListener('click', () => this.showBroadcastModal());
        document.getElementById('broadcastChatBtn')?.addEventListener('click', () => this.showBroadcastModal());
        document.getElementById('broadcastSendBtn')?.addEventListener('click', () => this.handleSendBroadcast());
        document.getElementById('broadcastCancelBtn')?.addEventListener('click', () => document.getElementById('broadcastModal').classList.remove('active'));
        document.getElementById('broadcastInput')?.addEventListener('keydown', e => { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();this.handleSendBroadcast();} });
        document.getElementById('manageAlertsBtn')?.addEventListener('click', () => this.showManageAlertsModal());
        document.getElementById('manageAlertsCancelBtn')?.addEventListener('click', () => document.getElementById('manageAlertsModal').classList.remove('active'));
        document.getElementById('clearAllAlertsBtn')?.addEventListener('click', () => this.handleClearAllAlerts());

        // DM notification bell
        document.getElementById('dmNotifBell')?.addEventListener('click', () => {
            // Open first unread DM or just clear
            const uid = Object.keys(DM.unreadCounts).find(u => DM.unreadCounts[u] > 0);
            if (uid && DM.openChats[uid]) {
                DM.openChats[uid].window.classList.add('active');
                DM.unreadCounts[uid] = 0;
                Notifications.updateDMBadge();
            }
        });

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

        document.getElementById('toggleMembersBtn').addEventListener('click', () => this.toggleMembers());
        document.getElementById('clearRoomChatBtn').addEventListener('click', () => this.adminClearChat());
        document.getElementById('lockRoomBtn').addEventListener('click', () => this.adminToggleLock());

        document.getElementById('attachBtn').addEventListener('click', () => {
            document.getElementById('attachMenu').classList.toggle('visible');
        });
        document.getElementById('attachImageOpt').addEventListener('click', () => {
            document.getElementById('attachMenu').classList.remove('visible');
            document.getElementById('imageFileInput').click();
        });
        document.getElementById('attachDocOpt').addEventListener('click', () => {
            document.getElementById('attachMenu').classList.remove('visible');
            document.getElementById('docFileInput').click();
        });
        document.getElementById('imageFileInput').addEventListener('change', e => this.handleImageUpload(e));
        document.getElementById('docFileInput').addEventListener('change', e => this.handleDocUpload(e));
        document.addEventListener('click', e => {
            if (!e.target.closest('#attachBtn') && !e.target.closest('#attachMenu'))
                document.getElementById('attachMenu').classList.remove('visible');
        });

        this.setupSettingsListeners();

        document.getElementById('closeShareModal').addEventListener('click', () => document.getElementById('shareModal').classList.add('hidden'));
        document.getElementById('copyLinkBtn').addEventListener('click', () => {
            const i = document.getElementById('shareLinkInput'); i.select(); document.execCommand('copy');
            document.getElementById('copyLinkBtn').textContent = 'Copied';
            setTimeout(() => document.getElementById('copyLinkBtn').textContent = 'Copy', 2000);
        });

        document.getElementById('imgLightbox').addEventListener('click', () => document.getElementById('imgLightbox').classList.remove('active'));

        // Change password modal
        document.getElementById('changePwdCancelBtn')?.addEventListener('click', () => document.getElementById('changePasswordModal').classList.remove('active'));
        document.getElementById('changePwdSubmitBtn')?.addEventListener('click', () => this.handleChangeGlobalPassword());

        // Global members modal close
        document.getElementById('closeGlobalMembersBtn')?.addEventListener('click', () => document.getElementById('globalMembersModal').classList.remove('active'));

        // Window unload
        window.addEventListener('beforeunload', () => {
            if (Auth.user) Auth.setOnlineStatus(false);
        });
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
            pwdAvatar.onerror = () => {
                pwdAvatar.outerHTML = `<div class="pwd-avatar pwd-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`;
            };
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
            lobbyAv.onerror = () => {
                lobbyAv.outerHTML = `<div class="lobby-avatar lobby-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`;
            };
        } else {
            lobbyAv.outerHTML = `<div class="lobby-avatar lobby-avatar-fallback">${(u.displayName||'U').charAt(0).toUpperCase()}</div>`;
        }

        document.getElementById('lobbyUsername').textContent = u.displayName || 'User';
        document.getElementById('adminBadge').style.display = Auth.isAdmin ? 'inline' : 'none';
        document.getElementById('adminPanel').classList.toggle('visible', Auth.isAdmin);

        // Start global presence
        Presence.start();
        // Start broadcast listener
        Broadcast.start();

        await Room.ensureDefaultRooms();
        await this.renderRooms();

        // If redirected from room URL
        if (this._pendingRoomFromUrl) {
            const roomId = this._pendingRoomFromUrl;
            this._pendingRoomFromUrl = null;
            setTimeout(async () => {
                const roomData = await Firebase.readData(`rooms/${roomId}`);
                if (roomData) await this.handleJoinRoom(roomId, roomData);
                else this.showToast('Room not found or expired.');
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
                ${Auth.isAdmin&&room.locked?`<button class="room-join-btn admin-override-btn" data-id="${id}" data-admin="1">Admin Access</button>`:''}
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

        // Init PeerJS and register presence for calls
        await VoiceCall.init();
        setTimeout(() => VoiceCall.registerPeer(), 1500);

        // Load admin prefs for call UI
        Firebase.readData('global/adminPrefs').then(prefs => {
            if (!prefs) return;
            const dbtn = document.getElementById('adminDisableCallsBtn');
            const lbtn = document.getElementById('adminLockVoiceBtn');
            if (dbtn) dbtn.textContent = prefs.disableCalls ? 'Enable Calls' : 'Disable Calls';
            if (lbtn) lbtn.textContent = prefs.lockVoiceRoom ? 'Unlock Voice Room' : 'Lock Voice Room';
        });

        // Admin bar
        document.getElementById('adminChatBar').classList.toggle('visible', Auth.isAdmin);

        // Settings button: only for admin
        const settingsBtn = document.getElementById('settingsBtn');
        if (settingsBtn) settingsBtn.style.display = Auth.isAdmin ? '' : 'none';

        if (isBlocked) {
            const blocker = document.createElement('div');
            blocker.className = 'blocked-overlay';
            blocker.innerHTML = 'You have been blocked in this room. You can view messages but cannot send.';
            document.getElementById('messagesContainer').appendChild(blocker);
            document.getElementById('messageInput').disabled = true;
            document.getElementById('sendMessageBtn').disabled = true;
            document.getElementById('attachBtn').disabled = true;
        } else {
            document.getElementById('messageInput').disabled = false;
            document.getElementById('sendMessageBtn').disabled = false;
            document.getElementById('attachBtn').disabled = false;
        }

        await Settings.load();

        if (window.RobotSystem) {
            window.RobotSystem.initSync(Firebase, Room.current.id, Room.current.userId);
            window.RobotSystem.setLabels(Room.current.username, '…');
        }

        await Messaging.listen((msg) => this.addMessageToUI(msg));
        Messaging.listenForTyping((name) => this.showTypingIndicator(name));
        this.listenToMembers();

        // Update URL without reload
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
        // Always read prefs fresh from live cache
        const prefs = Presence._cachedPrefs || Settings.currentSettings || {};
        const dmsDisabledGlobal = !!prefs.hideDMsFromMembers && !Auth.isAdmin;
        const callsDisabledGlobal = !!prefs.disableCalls && !Auth.isAdmin;

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
            // Show call button: non-self, member is online, calls not disabled
            const canCall = !isSelf && m.online && (!callsDisabledGlobal);
            // Show DM button: non-self, DMs not disabled
            const canDM = !isSelf && !dmsDisabledGlobal;

            item.innerHTML = `
                ${avHtml}
                <div class="member-info">
                    <div class="member-name${m.blocked?' blocked':''}">${this.escHtml(m.displayName||'User')}${m.isAdmin?'<span class="member-admin-star">A</span>':''}</div>
                    <div class="member-status ${m.online?'online':'offline'}">${m.online?'Online':'Offline'}</div>
                </div>
                <div class="member-quick-actions">
                    ${canCall ? `<button class="member-call-btn" data-uid="${uid}" data-name="${this.escHtml(m.displayName)}" data-photo="${this.escHtml(m.photoURL||'')}" title="Call ${this.escHtml(m.displayName)}">&#128222;</button>` : ''}
                    ${canDM ? `<button class="member-dm-btn" data-uid="${uid}" title="Message ${this.escHtml(m.displayName)}">&#128172;</button>` : ''}
                </div>
                <div class="${m.online?'member-online-dot':'member-offline-dot'}"></div>
                ${Auth.isAdmin&&!isSelf?`<div class="member-actions">
                    <button class="member-action-btn ${m.blocked?'unblock':'block'}" data-uid="${uid}" data-action="${m.blocked?'unblock':'block'}">${m.blocked?'Unblock':'Block'}</button>
                    <button class="member-action-btn kick" data-uid="${uid}" data-action="kick">Kick</button>
                </div>`:''}
            `;

            // Call button
            item.querySelector('.member-call-btn')?.addEventListener('click', (e) => {
                e.stopPropagation();
                const btn = e.currentTarget;
                VoiceCall.callUser(btn.dataset.uid, btn.dataset.name, btn.dataset.photo, false);
            });

            // DM button or item click
            item.querySelector('.member-dm-btn')?.addEventListener('click', (e) => {
                e.stopPropagation();
                DM.open(uid, m.displayName, m.photoURL);
            });

            item.querySelectorAll('[data-action]').forEach(btn => {
                btn.addEventListener('click', (e) => { e.stopPropagation(); this.handleMemberAction(btn.dataset.uid, btn.dataset.action, m.displayName); });
            });
            list.appendChild(item);
        }
    },

    async handleMemberAction(uid, action, displayName) {
        if (!Auth.isAdmin) return;
        const roomId = Room.current.id;
        if (action === 'block') {
            if (!confirm(`Block ${displayName} from this room?`)) return;
            await Firebase.updateData(`rooms/${roomId}/members/${uid}`, { blocked: true });
            await Firebase.updateData(`users/${uid}/blockedFrom`, { [roomId]: true });
        } else if (action === 'unblock') {
            await Firebase.updateData(`rooms/${roomId}/members/${uid}`, { blocked: false });
            await Firebase.updateData(`users/${uid}/blockedFrom`, { [roomId]: false });
        } else if (action === 'kick') {
            if (!confirm(`Kick ${displayName}?`)) return;
            await Firebase.updateData(`rooms/${roomId}/members/${uid}`, { online: false });
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
            img.className = 'msg-image';
            img.src = message.fileData;
            img.alt = message.text || 'Image';
            img.addEventListener('click', () => {
                document.getElementById('lightboxImg').src = message.fileData;
                document.getElementById('imgLightbox').classList.add('active');
            });
            bubble.appendChild(img);
            if (message.text) {
                const cap = document.createElement('p'); cap.className = 'message-text';
                cap.textContent = message.text; bubble.appendChild(cap);
            }
        } else if (message.type === 'document' && message.fileData) {
            const link = document.createElement('a');
            link.className = 'msg-doc'; link.href = message.fileData;
            link.download = message.text || 'document';
            link.innerHTML = `<span class="msg-doc-icon">&#128196;</span><span>${this.escHtml(message.text||'Document')}</span>`;
            bubble.appendChild(link);
        } else {
            const text = document.createElement('p');
            text.className = 'message-text';
            text.textContent = message.text;
            bubble.appendChild(text);
        }

        const meta = document.createElement('div');
        meta.className = 'message-meta';
        meta.textContent = new Date(message.timestamp).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
        bubble.appendChild(meta);

        if (message.isMe) {
            row.appendChild(bubble);
            row.insertAdjacentHTML('beforeend', avatarEl);
        } else {
            row.insertAdjacentHTML('beforeend', avatarEl);
            row.appendChild(bubble);
        }

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
        try {
            const dataUrl = await this.fileToDataUrl(file);
            await Messaging.send(file.name, 'image', dataUrl);
        } catch(err) { this.showToast('Failed to send image'); }
        this.hideLoading(); e.target.value = '';
    },

    async handleDocUpload(e) {
        const file = e.target.files[0]; if (!file) return;
        if (file.size > 5*1024*1024) { this.showToast('File too large. Max 5MB.'); return; }
        this.showLoading('Encrypting document…');
        try {
            const dataUrl = await this.fileToDataUrl(file);
            await Messaging.send(file.name, 'document', dataUrl);
        } catch(err) { this.showToast('Failed to send document'); }
        this.hideLoading(); e.target.value = '';
    },

    fileToDataUrl(file) {
        return new Promise((res, rej) => {
            const reader = new FileReader();
            reader.onload = e => res(e.target.result);
            reader.onerror = rej;
            reader.readAsDataURL(file);
        });
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
        VoiceRoom.cleanup();
        VoiceCall.hangupAll();
        VoiceCall.unregisterPeer();
        if (this.membersListener) { this.membersListener(); this.membersListener = null; }
        Room.leave();
        document.getElementById('chatScreen').classList.remove('active');
        document.getElementById('messagesContainer').innerHTML = '';
        // Reset URL
        window.history.replaceState({}, '', window.location.pathname);
        this.showLobby();
    },

    toggleMembers() { document.getElementById('membersPanel').classList.toggle('open'); },

    showShareModal() {
        const modal = document.getElementById('shareModal');
        document.getElementById('shareLinkInput').value = `${window.location.origin}${window.location.pathname}?room=${Room.current.id}`;
        modal.classList.remove('hidden');
    },

    toggleSettings() {
        if (!Auth.isAdmin) return;
        document.getElementById('settingsPanel').classList.toggle('active');
    },

    // Admin room creation
    showAdminRoomModal(mode) {
        document.getElementById('armTitle').textContent = mode === 'create' ? 'Create Room' : 'Delete Room';
        document.getElementById('armNameInput').value = '';
        document.getElementById('armIconInput').value = '';
        document.getElementById('armDescInput').value = '';
        document.getElementById('armPwdInput').value = '';
        document.getElementById('armStatus').textContent = '';
        document.getElementById('armStatus').className = 'arm-status';
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
            const roomId = await Room.createRoom(name, icon, desc, pwd);
            const shareLink = `${window.location.origin}${window.location.pathname}?room=${roomId}`;
            status.innerHTML = `Room created. <a href="${shareLink}" target="_blank" style="color:#4a7c5c">Copy link</a>`;
            status.className = 'arm-status success';
            // Copy to clipboard automatically
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
            await Room.deleteRoom(roomId);
            document.getElementById('adminStatus').textContent = 'Room deleted.';
            this.showLobby();
        }
    },

    async showGlobalMembersModal() {
        const users = await Firebase.readData('users');
        if (!users) { this.showToast('No users found.'); return; }
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
    },

    async showBannedList() {
        this.showToast('Manage bans: open a room, open Members panel, use Block/Unblock.');
    },

    async showManageAlertsModal() {
        if (!Auth.isAdmin) return;
        const modal = document.getElementById('manageAlertsModal');
        const list = document.getElementById('manageAlertsList');
        list.innerHTML = '<div style="color:#7a7570;font-size:0.8rem;font-family:\'DM Sans\',sans-serif;padding:12px 0;">Loading…</div>';
        modal.classList.add('active');

        const history = await Firebase.readData('global/broadcastHistory') || {};
        const entries = Object.entries(history).sort((a, b) => (b[1].sentAt || 0) - (a[1].sentAt || 0));

        list.innerHTML = '';
        if (!entries.length) {
            list.innerHTML = '<div style="color:#7a7570;font-size:0.8rem;font-family:\'DM Sans\',sans-serif;padding:12px 0;text-align:center;">No alerts sent yet.</div>';
            return;
        }
        for (const [id, item] of entries) {
            const el = document.createElement('div');
            el.className = 'manage-alert-item';
            const ts = item.sentAt ? new Date(item.sentAt).toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }) : '';
            el.innerHTML = `
                <div class="manage-alert-body">
                    <div class="manage-alert-msg">${this.escHtml(item.message)}</div>
                    <div class="manage-alert-meta">${ts}</div>
                </div>
                <button class="manage-alert-del" data-id="${id}" title="Delete">&#128465;</button>
            `;
            el.querySelector('.manage-alert-del').addEventListener('click', async (e) => {
                const btn = e.currentTarget;
                btn.textContent = '…';
                await Broadcast.deleteAlert(id);
                el.classList.add('removing');
                setTimeout(() => { el.remove(); if (!list.children.length) list.innerHTML = '<div style="color:#7a7570;font-size:0.8rem;font-family:\'DM Sans\',sans-serif;padding:12px 0;text-align:center;">No alerts.</div>'; }, 300);
            });
            list.appendChild(el);
        }
    },

    async handleClearAllAlerts() {
        if (!Auth.isAdmin) return;
        if (!confirm('Delete all broadcast alerts? Members will no longer see them.')) return;
        await Broadcast.clearAll();
        document.getElementById('manageAlertsModal').classList.remove('active');
        this.showToast('All alerts cleared.');
    },

    showBroadcastModal() {
        if (!Auth.isAdmin) return;
        const modal = document.getElementById('broadcastModal');
        document.getElementById('broadcastInput').value = '';
        document.getElementById('broadcastStatus').textContent = '';
        modal.classList.add('active');
        setTimeout(() => document.getElementById('broadcastInput').focus(), 150);
    },

    async handleSendBroadcast() {
        if (!Auth.isAdmin) return;
        const input = document.getElementById('broadcastInput');
        const status = document.getElementById('broadcastStatus');
        const msg = input.value.trim();
        if (!msg) { status.textContent = 'Message cannot be empty'; status.className = 'broadcast-status error'; return; }
        const btn = document.getElementById('broadcastSendBtn');
        btn.textContent = 'Sending…';
        try {
            await Broadcast.send(msg);
            status.textContent = 'Alert sent to all online members';
            status.className = 'broadcast-status success';
            input.value = '';
            setTimeout(() => document.getElementById('broadcastModal').classList.remove('active'), 1800);
        } catch(e) {
            status.textContent = 'Failed to send: ' + e.message;
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
        if (newPwd !== confirmPwd) { errEl.textContent = 'New passwords do not match'; return; }
        document.getElementById('changePwdSubmitBtn').textContent = 'Updating…';
        const result = await Auth.changeGlobalPassword(oldPwd, newPwd);
        document.getElementById('changePwdSubmitBtn').textContent = 'Update Password';
        if (result.success) {
            successEl.textContent = 'Password updated. All members will need to use the new password.';
        } else {
            errEl.textContent = result.error || 'Failed to update password';
        }
    },

    async adminClearChat() {
        if (!Auth.isAdmin) return;
        if (!confirm('Delete ALL messages in this room? This cannot be undone.')) return;
        await Firebase.deleteData(`messages/${Room.current.id}`);
        document.getElementById('messagesContainer').innerHTML = '';
        const info = document.createElement('div');
        info.style.cssText = 'text-align:center;padding:20px;color:#7a7570;font-size:0.82rem;font-family:\'DM Sans\',sans-serif;';
        info.textContent = '— Chat cleared by admin —';
        document.getElementById('messagesContainer').appendChild(info);
    },

    async adminToggleLock() {
        if (!Auth.isAdmin) return;
        const current = await Firebase.readData(`rooms/${Room.current.id}/locked`);
        await Firebase.updateData(`rooms/${Room.current.id}`, { locked: !current });
        document.getElementById('lockRoomBtn').textContent = current ? 'Lock Room' : 'Unlock Room';
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
            errEl.textContent = 'Incorrect password. Make sure you are using the exact password set by the admin — it is case-sensitive.';
            document.getElementById('pwdInput').value = '';
            document.getElementById('pwdInput').focus();
        }
    },

    showLoading(text = 'Loading…') {
        const ol = document.getElementById('loadingOverlay'); const lt = document.getElementById('loadingText');
        if (ol) { lt.textContent = text; ol.classList.remove('hidden'); }
    },
    hideLoading() { document.getElementById('loadingOverlay')?.classList.add('hidden'); },

    showToast(msg) {
        let toast = document.getElementById('aionToast');
        if (!toast) {
            toast = document.createElement('div');
            toast.id = 'aionToast';
            document.body.appendChild(toast);
        }
        toast.textContent = msg;
        toast.classList.add('visible');
        clearTimeout(this._toastTimer);
        this._toastTimer = setTimeout(() => toast.classList.remove('visible'), 3200);
    },

    escHtml(str) {
        return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    },

    setupSettingsListeners() {
        const qs = id => document.getElementById(id);
        qs('bgColorPicker')?.addEventListener('change', e => { Settings.currentSettings.bgColor = e.target.value; document.documentElement.style.setProperty('--chat-bg',e.target.value); });
        qs('chatBgColorPicker')?.addEventListener('change', e => { Settings.currentSettings.chatBgColor = e.target.value; document.documentElement.style.setProperty('--chat-bg',e.target.value); });
        qs('uploadBgImageBtn')?.addEventListener('click', () => qs('bgImageInput').click());
        qs('bgImageInput')?.addEventListener('change', e => { const f=e.target.files[0]; if(f){const r=new FileReader();r.onload=ev=>{Settings.currentSettings.bgImage=ev.target.result;Settings.apply();};r.readAsDataURL(f);} });
        qs('removeBgImageBtn')?.addEventListener('click', () => { Settings.currentSettings.bgImage=null; Settings.apply(); });
        qs('bgOpacitySlider')?.addEventListener('input', e => { Settings.currentSettings.bgOpacity=parseInt(e.target.value); qs('bgOpacityValue').textContent=e.target.value+'%'; Settings.apply(); });
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
        qs('musicToggle')?.addEventListener('change', e => { Settings.currentSettings.musicEnabled=e.target.checked; e.target.checked&&Settings.currentSettings.musicFile?Settings.playMusic(Settings.currentSettings.musicFile,Settings.currentSettings.musicVolume):Settings.clearMusic(); });
        qs('uploadMusicBtn')?.addEventListener('click', () => qs('musicFileInput').click());
        qs('musicFileInput')?.addEventListener('change', e => { const f=e.target.files[0]; if(f){const r=new FileReader();r.onload=ev=>{Settings.currentSettings.musicFile=ev.target.result;qs('musicControls').classList.remove('hidden');qs('musicFileName').textContent=f.name;};r.readAsDataURL(f);} });
        qs('playMusicBtn')?.addEventListener('click', () => qs('backgroundAudio').play());
        qs('pauseMusicBtn')?.addEventListener('click', () => qs('backgroundAudio').pause());
        qs('stopMusicBtn')?.addEventListener('click', () => { const a=qs('backgroundAudio'); a.pause(); a.currentTime=0; });
        qs('musicVolumeSlider')?.addEventListener('input', e => { Settings.currentSettings.musicVolume=parseInt(e.target.value); qs('musicVolumeValue').textContent=e.target.value+'%'; qs('backgroundAudio').volume=e.target.value/100; });
        qs('bgTextToggle')?.addEventListener('change', e => { Settings.currentSettings.bgTextEnabled=e.target.checked; Settings.apply(); });
        qs('bgTextInput')?.addEventListener('input', e => { Settings.currentSettings.bgText=e.target.value; Settings.applyBackgroundText(); });
        qs('bgTextSizeSlider')?.addEventListener('input', e => { Settings.currentSettings.bgTextSize=parseInt(e.target.value); qs('bgTextSizeValue').textContent=e.target.value+'px'; Settings.applyBackgroundText(); });
        qs('bgTextColorPicker')?.addEventListener('change', e => { Settings.currentSettings.bgTextColor=e.target.value; Settings.applyBackgroundText(); });
        qs('bgTextPositionSelect')?.addEventListener('change', e => { Settings.currentSettings.bgTextPosition=e.target.value; Settings.applyBackgroundText(); });
        qs('saveSettingsBtn')?.addEventListener('click', async () => {
            try {
                if(window.ROBOT_PROVIDER) Settings.currentSettings.robotProvider=window.ROBOT_PROVIDER;
                await Settings.save();
                UI.showToast('Settings saved');
            } catch(e) { UI.showToast('Error: '+e.message); }
        });
        qs('resetSettingsBtn')?.addEventListener('click', () => { if(confirm('Reset all settings?')){Settings.reset();} });
        qs('closeSettingsBtn')?.addEventListener('click', () => this.toggleSettings());
        document.querySelectorAll('.provider-btn').forEach(btn => btn.addEventListener('click', () => { Settings.currentSettings.robotProvider = btn.dataset.provider; }));
        // Admin-only setting toggles — persist to Firebase global prefs (work from lobby before entering a room)
        qs('hideStatusToggle')?.addEventListener('change', async e => {
            const val = e.target.checked;
            if (Settings.currentSettings) Settings.currentSettings.hideStatusFromMembers = val;
            await Firebase.updateData('global/adminPrefs', { hideStatusFromMembers: val });
            Presence._cachedPrefs = { ...Presence._cachedPrefs, hideStatusFromMembers: val };
            if (Presence._lastUsers) Presence.renderPresenceBar(Presence._lastUsers);
        });
        qs('hideDMsToggle')?.addEventListener('change', async e => {
            const val = e.target.checked;
            if (Settings.currentSettings) Settings.currentSettings.hideDMsFromMembers = val;
            await Firebase.updateData('global/adminPrefs', { hideDMsFromMembers: val });
            Presence._cachedPrefs = { ...Presence._cachedPrefs, hideDMsFromMembers: val };
            if (Presence._lastUsers) Presence.renderPresenceBar(Presence._lastUsers);
        });
    }
};

// ========================================================
// INITIALIZE
// ========================================================
document.addEventListener('DOMContentLoaded', () => {
    UI.init();
    wireCallListeners();
});
// ========================================================
// SECTION 10: VOICE CALL SYSTEM (PeerJS)
// ========================================================
const VoiceCall = {
    peer: null,
    peerId: null,
    activeCall: null,
    activeCalls: {}, // peerId -> MediaConnection (for group)
    localStream: null,
    isInCall: false,
    isMicOn: true,
    callTimerInterval: null,
    callSeconds: 0,
    isGroupCall: false,

    // Firebase path for signaling
    _sigPath(roomId) { return `voiceSignal/${roomId}`; },
    _presPath() { return `voiceCallPresence/${Room.current?.id || 'global'}`; },

    async init() {
        if (this.peer) return;
        try {
            // Use a unique peerId tied to user uid
            const uid = Auth.user?.uid;
            if (!uid) return;
            this.peerId = 'aion_' + uid + '_' + Date.now();
            this.peer = new Peer(this.peerId);
            this.peer.on('open', (id) => {
                console.log('[VoiceCall] PeerJS open, id:', id);
                this.peerId = id;
                // Store our peerId in Firebase so others can call us
                if (Room.current?.id) {
                    Firebase.updateData(`voicePeers/${Room.current.id}/${uid}`, {
                        peerId: id,
                        displayName: Auth.user.displayName,
                        photoURL: Auth.user.photoURL || '',
                        online: true,
                        timestamp: Firebase.getServerTimestamp()
                    });
                }
            });
            this.peer.on('call', (call) => this._handleIncomingCall(call));
            this.peer.on('error', (err) => { console.error('[VoiceCall] Peer error:', err); });
        } catch(e) { console.error('[VoiceCall] init error:', e); }
    },

    async registerPeer() {
        if (!this.peer || !Room.current?.id || !Auth.user) return;
        await Firebase.updateData(`voicePeers/${Room.current.id}/${Auth.user.uid}`, {
            peerId: this.peerId,
            displayName: Auth.user.displayName,
            photoURL: Auth.user.photoURL || '',
            online: true,
            timestamp: Firebase.getServerTimestamp()
        });
    },

    async unregisterPeer() {
        if (!Room.current?.id || !Auth.user) return;
        await Firebase.updateData(`voicePeers/${Room.current.id}/${Auth.user.uid}`, { online: false });
    },

    async _handleIncomingCall(call) {
        // Check if calls disabled
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        if (prefs.disableCalls && !Auth.isAdmin) {
            call.close();
            UI.showToast('Calling is disabled by admin.');
            return;
        }
        // Show incoming call UI
        const callerMeta = call.metadata || {};
        UI.showIncomingCall(callerMeta, call);
    },

    async callUser(targetUid, targetName, targetPhotoURL, isGroup = false) {
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        if (prefs.disableCalls && !Auth.isAdmin) { UI.showToast('Calling is disabled by admin.'); return; }

        const peerData = await Firebase.readData(`voicePeers/${Room.current?.id}/${targetUid}`);
        if (!peerData || !peerData.peerId || !peerData.online) {
            UI.showToast(`${targetName} is not available for calls.`); return;
        }
        try {
            const stream = await this._getLocalStream();
            const call = this.peer.call(peerData.peerId, stream, {
                metadata: {
                    callerUid: Auth.user.uid,
                    callerName: Auth.user.displayName,
                    callerPhoto: Auth.user.photoURL || '',
                    isGroup
                }
            });
            this.activeCalls[peerData.peerId] = call;
            call.on('stream', (remoteStream) => {
                this._attachRemoteAudio(remoteStream, targetUid);
                CallUI.addParticipant(targetUid, targetName, targetPhotoURL);
            });
            call.on('close', () => { this._handleCallEnded(peerData.peerId, targetUid); });
            call.on('error', () => { this._handleCallEnded(peerData.peerId, targetUid); });

            if (!this.isInCall) {
                this.isInCall = true;
                this.isGroupCall = isGroup;
                CallUI.show();
                CallUI.startTimer();
                CallUI.addParticipant(Auth.user.uid, Auth.user.displayName, Auth.user.photoURL, true);
            }
        } catch(e) { UI.showToast('Could not start call: ' + e.message); }
    },

    async acceptCall(call) {
        try {
            const stream = await this._getLocalStream();
            call.answer(stream);
            const callerMeta = call.metadata || {};
            this.activeCalls[call.peer] = call;
            call.on('stream', (remoteStream) => {
                this._attachRemoteAudio(remoteStream, callerMeta.callerUid);
                CallUI.addParticipant(callerMeta.callerUid, callerMeta.callerName, callerMeta.callerPhoto);
            });
            call.on('close', () => { this._handleCallEnded(call.peer, callerMeta.callerUid); });
            this.isInCall = true;
            CallUI.show();
            CallUI.startTimer();
            CallUI.addParticipant(Auth.user.uid, Auth.user.displayName, Auth.user.photoURL, true);
        } catch(e) { UI.showToast('Could not accept call: ' + e.message); }
    },

    hangupAll() {
        Object.values(this.activeCalls).forEach(c => { try { c.close(); } catch(e){} });
        this.activeCalls = {};
        if (this.activeCall) { try { this.activeCall.close(); } catch(e){} this.activeCall = null; }
        if (this.localStream) { this.localStream.getTracks().forEach(t => t.stop()); this.localStream = null; }
        this.isInCall = false;
        CallUI.hide();
        // Remove remote audio tags
        document.querySelectorAll('.remote-audio-el').forEach(el => el.remove());
    },

    _handleCallEnded(peerId, uid) {
        delete this.activeCalls[peerId];
        CallUI.removeParticipant(uid);
        if (Object.keys(this.activeCalls).length === 0) {
            this.hangupAll();
        }
    },

    toggleMic() {
        this.isMicOn = !this.isMicOn;
        if (this.localStream) {
            this.localStream.getAudioTracks().forEach(t => { t.enabled = this.isMicOn; });
        }
        const btn = document.getElementById('callMicBtn');
        if (btn) btn.textContent = this.isMicOn ? '🎤 Mic On' : '🔇 Muted';
        if (btn) btn.classList.toggle('muted', !this.isMicOn);
        return this.isMicOn;
    },

    async _getLocalStream() {
        if (this.localStream) return this.localStream;
        this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        return this.localStream;
    },

    _attachRemoteAudio(stream, uid) {
        const existing = document.getElementById('remote-audio-' + uid);
        if (existing) { existing.srcObject = stream; return; }
        const audio = document.createElement('audio');
        audio.id = 'remote-audio-' + uid;
        audio.className = 'remote-audio-el';
        audio.srcObject = stream;
        audio.autoplay = true;
        document.body.appendChild(audio);
    },

    async startGroupCall() {
        if (!Auth.isAdmin) { UI.showToast('Only admin can start group calls.'); return; }
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        if (prefs.disableCalls) { UI.showToast('Enable calls first in admin settings.'); return; }
        const peers = await Firebase.readData(`voicePeers/${Room.current?.id}`) || {};
        let called = 0;
        for (const [uid, data] of Object.entries(peers)) {
            if (uid === Auth.user.uid || !data.online || !data.peerId) continue;
            await this.callUser(uid, data.displayName, data.photoURL, true);
            called++;
        }
        if (called === 0) UI.showToast('No other members online to call.');
        else UI.showToast(`Group call started — calling ${called} member(s)`);
    }
};

// ========================================================
// SECTION 11: CALL UI CONTROLLER
// ========================================================
const CallUI = {
    participants: {}, // uid -> {name, photo}

    show() {
        const box = document.getElementById('callFloatBox');
        if (box) box.classList.remove('hidden');
    },

    hide() {
        const box = document.getElementById('callFloatBox');
        if (box) box.classList.add('hidden');
        this.participants = {};
        this.renderParticipants();
        this.stopTimer();
        // collapse back to mini
        box?.setAttribute('data-state', 'minimized');
    },

    addParticipant(uid, name, photoURL, isMe = false) {
        this.participants[uid] = { name, photoURL, isMe };
        this.renderParticipants();
    },

    removeParticipant(uid) {
        delete this.participants[uid];
        this.renderParticipants();
    },

    renderParticipants() {
        const el = document.getElementById('callParticipants');
        if (!el) return;
        el.innerHTML = '';
        for (const [uid, p] of Object.entries(this.participants)) {
            const chip = document.createElement('div');
            chip.className = 'call-participant-chip';
            const av = p.photoURL
                ? `<img src="${UI.escHtml(UI.getProxiedAvatar(p.photoURL))}" onerror="this.outerHTML='<div class=\\'cp-av\\'>${(p.name||'U').charAt(0)}</div>'">`
                : `<div class="cp-av">${(p.name||'U').charAt(0).toUpperCase()}</div>`;
            chip.innerHTML = av + `<span>${UI.escHtml(p.name||'User')}${p.isMe?' (you)':''}</span>`;
            el.appendChild(chip);
        }
    },

    startTimer() {
        VoiceCall.callSeconds = 0;
        this.stopTimer();
        VoiceCall.callTimerInterval = setInterval(() => {
            VoiceCall.callSeconds++;
            const m = String(Math.floor(VoiceCall.callSeconds/60)).padStart(2,'0');
            const s = String(VoiceCall.callSeconds%60).padStart(2,'0');
            const el = document.getElementById('callTimer');
            if (el) el.textContent = m + ':' + s;
        }, 1000);
    },

    stopTimer() {
        if (VoiceCall.callTimerInterval) { clearInterval(VoiceCall.callTimerInterval); VoiceCall.callTimerInterval = null; }
    }
};

// ========================================================
// SECTION 12: VOICE ROOM (Discord-style auto-VC)
// ========================================================
const VoiceRoom = {
    isJoined: false,
    isMicOn: true,
    localStream: null,
    peers: {}, // uid -> peerId
    activeCalls: {}, // peerId -> call
    membersListener: null,

    async join() {
        // Check lock
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        if (prefs.lockVoiceRoom && !Auth.isAdmin) {
            document.getElementById('voiceRoomLockedNotice')?.classList.remove('hidden');
            UI.showToast('Voice room is locked by admin.');
            return;
        }
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
        } catch(e) {
            UI.showToast('Microphone access denied.'); return;
        }

        // Make sure PeerJS is ready
        if (!VoiceCall.peer || !VoiceCall.peerId) {
            await VoiceCall.init();
            await new Promise(res => setTimeout(res, 1200)); // wait for peer open
        }

        // Register in voice room
        await Firebase.updateData(`voiceRoom/${Room.current?.id}/${Auth.user.uid}`, {
            peerId: VoiceCall.peerId,
            displayName: Auth.user.displayName,
            photoURL: Auth.user.photoURL || '',
            micOn: true,
            joinedAt: Firebase.getServerTimestamp()
        });

        this.isJoined = true;
        this.isMicOn = true;
        this._updateUI();

        // Connect to all existing members
        const existing = await Firebase.readData(`voiceRoom/${Room.current?.id}`) || {};
        for (const [uid, data] of Object.entries(existing)) {
            if (uid === Auth.user.uid || !data.peerId) continue;
            this._connectTo(uid, data.peerId, data.displayName, data.photoURL);
        }

        // Listen for new joiners
        this.membersListener = Firebase.listenToValue(`voiceRoom/${Room.current?.id}`, (data) => {
            this._handleMembersUpdate(data || {});
        });

        // Handle incoming calls from voice room
        if (VoiceCall.peer) {
            VoiceCall.peer.on('call', (call) => {
                if (!this.isJoined) return;
                call.answer(this.localStream);
                call.on('stream', (remoteStream) => {
                    const uid = call.metadata?.callerUid || call.peer;
                    this._attachAudio(remoteStream, uid);
                    this.renderMembers(Firebase._lastVoiceRoomData || {});
                });
                call.on('close', () => {
                    const uid = call.metadata?.callerUid || call.peer;
                    this._detachAudio(uid);
                });
                this.activeCalls[call.peer] = call;
            });
        }

        document.getElementById('voiceRoomStatus').textContent = 'Connected';
    },

    _connectTo(uid, peerId, name, photoURL) {
        if (this.activeCalls[peerId] || !this.localStream || !VoiceCall.peer) return;
        const call = VoiceCall.peer.call(peerId, this.localStream, {
            metadata: { callerUid: Auth.user.uid, callerName: Auth.user.displayName, isVoiceRoom: true }
        });
        this.activeCalls[peerId] = call;
        call.on('stream', (remoteStream) => { this._attachAudio(remoteStream, uid); });
        call.on('close', () => { delete this.activeCalls[peerId]; this._detachAudio(uid); });
    },

    _handleMembersUpdate(data) {
        Firebase._lastVoiceRoomData = data;
        // Connect to any new members we haven't connected to
        for (const [uid, d] of Object.entries(data)) {
            if (uid === Auth.user.uid || !d.peerId) continue;
            if (!this.activeCalls[d.peerId] && this.isJoined) {
                this._connectTo(uid, d.peerId, d.displayName, d.photoURL);
            }
        }
        this.renderMembers(data);
    },

    renderMembers(data) {
        const container = document.getElementById('voiceRoomMembers');
        if (!container) return;
        container.innerHTML = '';
        const entries = Object.entries(data);
        if (!entries.length) {
            container.innerHTML = '<div style="color:#6a6560;font-size:0.78rem;padding:12px;text-align:center;">No one in voice room</div>';
            return;
        }
        for (const [uid, d] of entries) {
            const item = document.createElement('div');
            item.className = 'voice-member-item';
            const av = d.photoURL
                ? `<img src="${UI.escHtml(UI.getProxiedAvatar(d.photoURL))}">`
                : `<div>${(d.displayName||'U').charAt(0).toUpperCase()}</div>`;
            item.innerHTML = `
                <div class="voice-member-av">${av}</div>
                <div class="voice-member-name">${UI.escHtml(d.displayName||'User')}${uid===Auth.user.uid?' (you)':''}</div>
                <span class="voice-member-mic ${d.micOn===false?'muted':''}">${d.micOn===false?'🔇':'🎤'}</span>
            `;
            container.appendChild(item);
        }
        document.getElementById('voiceRoomSubtitle').textContent = `${entries.length} member${entries.length!==1?'s':''} connected`;
    },

    async leave() {
        if (!this.isJoined) return;
        this.isJoined = false;
        // Remove from Firebase
        await Firebase.deleteData(`voiceRoom/${Room.current?.id}/${Auth.user.uid}`);
        // Close all calls
        Object.values(this.activeCalls).forEach(c => { try { c.close(); } catch(e){} });
        this.activeCalls = {};
        // Stop local stream
        if (this.localStream) { this.localStream.getTracks().forEach(t => t.stop()); this.localStream = null; }
        // Remove audio tags
        document.querySelectorAll('.voice-room-audio').forEach(el => el.remove());
        if (this.membersListener) { this.membersListener(); this.membersListener = null; }
        this._updateUI();
        document.getElementById('voiceRoomMembers').innerHTML = '<div style="color:#6a6560;font-size:0.78rem;padding:12px;text-align:center;">No one in voice room</div>';
        document.getElementById('voiceRoomSubtitle').textContent = 'Join to start talking';
        document.getElementById('voiceRoomStatus').textContent = '';
    },

    toggleMic() {
        this.isMicOn = !this.isMicOn;
        if (this.localStream) this.localStream.getAudioTracks().forEach(t => { t.enabled = this.isMicOn; });
        // Update Firebase
        if (Room.current?.id && Auth.user) {
            Firebase.updateData(`voiceRoom/${Room.current.id}/${Auth.user.uid}`, { micOn: this.isMicOn });
        }
        const btn = document.getElementById('voiceMicBtn');
        if (btn) { btn.textContent = this.isMicOn ? '🎤 Mic On' : '🔇 Muted'; btn.classList.toggle('muted', !this.isMicOn); }
    },

    _attachAudio(stream, uid) {
        const id = 'vr-audio-' + uid;
        if (document.getElementById(id)) return;
        const audio = document.createElement('audio');
        audio.id = id; audio.className = 'voice-room-audio';
        audio.srcObject = stream; audio.autoplay = true;
        document.body.appendChild(audio);
    },

    _detachAudio(uid) {
        document.getElementById('vr-audio-' + uid)?.remove();
    },

    _updateUI() {
        const joinBtn = document.getElementById('voiceJoinBtn');
        const micBtn = document.getElementById('voiceMicBtn');
        const leaveBtn = document.getElementById('voiceLeaveBtn');
        if (joinBtn) joinBtn.classList.toggle('hidden', this.isJoined);
        if (micBtn) micBtn.classList.toggle('hidden', !this.isJoined);
        if (leaveBtn) leaveBtn.classList.toggle('hidden', !this.isJoined);
    },

    // Called when room changes
    cleanup() {
        if (this.isJoined) this.leave();
    }
};

// ========================================================
// SECTION 13: CALL-RELATED UI ADDITIONS (patched into UI)
// ========================================================

// Show incoming call modal
UI.showIncomingCall = function(meta, call) {
    const modal = document.getElementById('incomingCallModal');
    const avEl = document.getElementById('incomingCallAvatar');
    const nameEl = document.getElementById('incomingCallName');
    const typeEl = document.getElementById('incomingCallType');
    if (!modal) return;

    nameEl.textContent = meta.callerName || 'Someone';
    typeEl.textContent = meta.isGroup ? 'is inviting you to a group call...' : 'is calling you...';
    if (meta.callerPhoto) {
        avEl.innerHTML = `<img src="${UI.escHtml(UI.getProxiedAvatar(meta.callerPhoto))}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
    } else {
        avEl.innerHTML = `<span style="font-size:1.4rem;">${(meta.callerName||'U').charAt(0).toUpperCase()}</span>`;
    }
    modal.classList.remove('hidden');

    // Auto-reject after 30s
    const autoReject = setTimeout(() => {
        modal.classList.add('hidden');
        try { call.close(); } catch(e){}
    }, 30000);

    document.getElementById('acceptCallBtn').onclick = () => {
        clearTimeout(autoReject);
        modal.classList.add('hidden');
        VoiceCall.acceptCall(call);
    };
    document.getElementById('rejectCallBtn').onclick = () => {
        clearTimeout(autoReject);
        modal.classList.add('hidden');
        try { call.close(); } catch(e){}
    };
};


// Wire call listeners after DOM ready — called from main DOMContentLoaded
function wireCallListeners() {
    // Float box: mini click to expand
    document.getElementById('callFloatMini')?.addEventListener('click', () => {
        document.getElementById('callFloatBox')?.setAttribute('data-state','expanded');
    });
    document.getElementById('callFloatCollapse')?.addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('callFloatBox')?.setAttribute('data-state','minimized');
    });

    // Mic toggle in call
    document.getElementById('callMicBtn')?.addEventListener('click', () => {
        VoiceCall.toggleMic();
    });

    // Hangup
    document.getElementById('callHangupBtn')?.addEventListener('click', () => {
        VoiceCall.hangupAll();
    });

    // Voice room button (header)
    document.getElementById('voiceRoomBtn')?.addEventListener('click', () => {
        const panel = document.getElementById('voiceRoomPanel');
        if (panel) panel.classList.toggle('hidden');
        if (!panel.classList.contains('hidden')) {
            // Load current members
            if (Room.current?.id) {
                Firebase.readData(`voiceRoom/${Room.current.id}`).then(data => {
                    VoiceRoom.renderMembers(data || {});
                });
            }
            // Check lock status
            Firebase.readData('global/adminPrefs').then(prefs => {
                const locked = prefs?.lockVoiceRoom;
                document.getElementById('voiceRoomLockedNotice')?.classList.toggle('hidden', !locked || Auth.isAdmin);
                const joinBtn = document.getElementById('voiceJoinBtn');
                if (joinBtn && locked && !Auth.isAdmin) joinBtn.disabled = true;
            });
        }
    });
    document.getElementById('voiceRoomClose')?.addEventListener('click', () => {
        document.getElementById('voiceRoomPanel')?.classList.add('hidden');
    });
    document.getElementById('voiceJoinBtn')?.addEventListener('click', () => VoiceRoom.join());
    document.getElementById('voiceLeaveBtn')?.addEventListener('click', () => VoiceRoom.leave());
    document.getElementById('voiceMicBtn')?.addEventListener('click', () => VoiceRoom.toggleMic());

    // Start call button (header) — opens member picker
    document.getElementById('startCallBtn')?.addEventListener('click', () => {
        UI.showCallMemberPicker();
    });

    // Admin chat bar: group call
    document.getElementById('adminGroupCallBtn')?.addEventListener('click', () => {
        VoiceCall.startGroupCall();
    });

    // Admin chat bar: disable calls toggle
    document.getElementById('adminDisableCallsBtn')?.addEventListener('click', async () => {
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        const newVal = !prefs.disableCalls;
        await Firebase.updateData('global/adminPrefs', { disableCalls: newVal });
        UI.showToast(newVal ? 'Calling disabled for members' : 'Calling enabled for members');
        document.getElementById('adminDisableCallsBtn').textContent = newVal ? 'Enable Calls' : 'Disable Calls';
    });

    // Admin chat bar: lock voice room
    document.getElementById('adminLockVoiceBtn')?.addEventListener('click', async () => {
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        const newVal = !prefs.lockVoiceRoom;
        await Firebase.updateData('global/adminPrefs', { lockVoiceRoom: newVal });
        UI.showToast(newVal ? 'Voice room locked' : 'Voice room unlocked');
        document.getElementById('adminLockVoiceBtn').textContent = newVal ? 'Unlock Voice Room' : 'Lock Voice Room';
        document.getElementById('voiceRoomLockedNotice')?.classList.toggle('hidden', !newVal);
    });

    // Lobby admin toggles for calls/voice
    document.getElementById('disableCallsToggle')?.addEventListener('change', async (e) => {
        await Firebase.updateData('global/adminPrefs', { disableCalls: e.target.checked });
        UI.showToast(e.target.checked ? 'Calling disabled' : 'Calling enabled');
    });
    document.getElementById('lockVoiceRoomToggle')?.addEventListener('change', async (e) => {
        await Firebase.updateData('global/adminPrefs', { lockVoiceRoom: e.target.checked });
        UI.showToast(e.target.checked ? 'Voice room locked' : 'Voice room unlocked');
    });
    document.getElementById('lobbyDisableCallsBtn')?.addEventListener('click', async () => {
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        const newVal = !prefs.disableCalls;
        await Firebase.updateData('global/adminPrefs', { disableCalls: newVal });
        const toggle = document.getElementById('disableCallsToggle');
        if (toggle) toggle.checked = newVal;
        UI.showToast(newVal ? 'Calling disabled' : 'Calling enabled');
    });
    document.getElementById('lobbyLockVoiceBtn')?.addEventListener('click', async () => {
        const prefs = await Firebase.readData('global/adminPrefs') || {};
        const newVal = !prefs.lockVoiceRoom;
        await Firebase.updateData('global/adminPrefs', { lockVoiceRoom: newVal });
        const toggle = document.getElementById('lockVoiceRoomToggle');
        if (toggle) toggle.checked = newVal;
        UI.showToast(newVal ? 'Voice room locked' : 'Voice room unlocked');
    });
}

// Member picker for 1:1 calls from the header call button
UI.showCallMemberPicker = async function() {
    if (!Room.current?.id) return;
    // Check if calls are disabled for non-admins
    const prefs = await Firebase.readData('global/adminPrefs') || {};
    if (prefs.disableCalls && !Auth.isAdmin) {
        UI.showToast('Calling is currently disabled by admin.');
        return;
    }

    const peers = await Firebase.readData(`voicePeers/${Room.current.id}`);
    // Build a quick modal
    const existing = document.getElementById('callPickerModal');
    if (existing) existing.remove();
    const modal = document.createElement('div');
    modal.id = 'callPickerModal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:9000;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px);';

    let memberRows = '';
    let count = 0;
    if (peers) {
        for (const [uid, data] of Object.entries(peers)) {
            if (uid === Auth.user.uid || !data.online) continue;
            const initials = (data.displayName||'U').charAt(0).toUpperCase();
            const av = data.photoURL
                ? `<img src="${UI.escHtml(UI.getProxiedAvatar(data.photoURL))}" style="width:38px;height:38px;border-radius:50%;object-fit:cover;flex-shrink:0;">`
                : `<div style="width:38px;height:38px;border-radius:50%;background:linear-gradient(135deg,#4a7c5c,#2d5c42);display:flex;align-items:center;justify-content:center;font-size:0.9rem;color:#fff;font-weight:600;flex-shrink:0;">${initials}</div>`;
            memberRows += `<div class="call-picker-row" data-uid="${uid}" data-name="${UI.escHtml(data.displayName)}" data-photo="${UI.escHtml(data.photoURL||'')}">
                <div class="call-picker-av">${av}</div>
                <div class="call-picker-name">${UI.escHtml(data.displayName||'User')}</div>
                <div class="call-picker-status-dot"></div>
                <button class="call-picker-call-btn">&#128222; Call</button>
            </div>`;
            count++;
        }
    }

    if (count === 0) {
        memberRows = `<div style="text-align:center;padding:24px 0;color:#6a6560;font-size:0.85rem;">No online members available to call</div>`;
    }

    // Admin-only group call option
    const groupRow = Auth.isAdmin ? `<div style="border-top:1px solid #2d2926;margin-top:12px;padding-top:12px;">
        <button id="callPickerGroupBtn" style="width:100%;background:linear-gradient(135deg,#1a4a2e,#2d7a4a);color:#6fcf97;border:1px solid #2d7a4a;border-radius:10px;padding:10px 16px;font-size:0.83rem;cursor:pointer;font-family:'DM Sans',sans-serif;letter-spacing:0.04em;transition:all 0.2s;">
            &#127908; Start Group Call (all online members)
        </button>
    </div>` : '';

    modal.innerHTML = `<div class="call-picker-card">
        <div class="call-picker-header">
            <span class="call-picker-title">Start a Call</span>
            <button id="callPickerClose" class="call-picker-close-btn">&#10005;</button>
        </div>
        <div class="call-picker-list">${memberRows}</div>
        ${groupRow}
    </div>`;

    document.body.appendChild(modal);

    modal.querySelectorAll('.call-picker-row').forEach(row => {
        row.querySelector('.call-picker-call-btn').addEventListener('click', () => {
            modal.remove();
            VoiceCall.callUser(row.dataset.uid, row.dataset.name, row.dataset.photo, false);
        });
    });

    document.getElementById('callPickerClose')?.addEventListener('click', () => modal.remove());
    document.getElementById('callPickerGroupBtn')?.addEventListener('click', () => {
        modal.remove();
        VoiceCall.startGroupCall();
    });
    modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
};

// wireCallListeners is called from UI.init() below