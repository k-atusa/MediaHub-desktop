// Core utility functions, encrypted session storage, and UI dialogs

// Convert Uint8Array buffer to lowercase hexadecimal string
export const ToHex = (buf) => {
    if (!buf) return '';
    return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
};

// Convert hexadecimal string to Uint8Array buffer
export const FromHex = (hex) => {
    if (!hex || hex.length % 2 !== 0) return new Uint8Array(0);
    const matches = hex.match(/.{1,2}/g);
    if (!matches) return new Uint8Array(0);
    return new Uint8Array(matches.map(b => parseInt(b, 16)));
};

// Format byte count to human-readable size string
export const FormatBytes = (bytes) => {
    if (bytes === undefined || bytes === null || isNaN(bytes)) return '-';
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const val = parseFloat((bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1));
    return `${val} ${sizes[i]}`;
};

// Escape HTML special characters
export const EscapeHtml = (str) => {
    return (str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

// Extract 24-byte object PID from key slice
export const GetObjPid = (key) => {
    if (!key || key.length < 44) return '';
    return ToHex(key.slice(32, 44));
};

const videoExts = ['mp4', 'webm', 'mov', 'mkv', 'avi', 'ts', 'm4v', '3gp', 'flv'];
const audioExts = ['mp3', 'ogg', 'wav', 'm4a', 'aac', 'flac', 'opus', 'wma'];
const imageExts = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'heic', 'avif'];
const pdfExts = ['pdf'];
const textExts = [
    'txt', 'log', 'md', 'json', 'csv', 'xml', 'html', 'css', 'js', 'ts', 'jsx', 'tsx',
    'yaml', 'yml', 'sh', 'py', 'sql', 'ini', 'conf', 'c', 'cpp', 'h', 'hpp', 'go', 'rs',
    'java', 'kt', 'kts', 'swift', 'rb', 'php', 'cs', 'scala', 'dart', 'lua', 'r',
    'bat', 'cmd', 'ps1', 'zsh', 'bash', 'toml', 'env', 'properties', 'graphql', 'gql',
    'proto', 'diff', 'patch', 'vue', 'svelte', 'lock', 'json5',
    'readme', 'license', 'makefile', 'dockerfile'
];

// Determine media category by file name extension
export const GetKind = (name) => {
    const ext = ((name || '').split('.').pop() || '').toLowerCase();
    if (videoExts.includes(ext)) return 'video';
    if (audioExts.includes(ext)) return 'audio';
    if (imageExts.includes(ext)) return 'image';
    if (pdfExts.includes(ext)) return 'pdf';
    if (textExts.includes(ext)) return 'text';
    return 'unsupported';
};

// Get MIME type by file name extension
export const GetMime = (name) => {
    const ext = ((name || '').split('.').pop() || '').toLowerCase();
    const map = {
        pdf: 'application/pdf',
        txt: 'text/plain;charset=utf-8',
        log: 'text/plain;charset=utf-8',
        md: 'text/markdown;charset=utf-8',
        json: 'application/json',
        csv: 'text/csv;charset=utf-8',
        xml: 'application/xml',
        html: 'text/html;charset=utf-8',
        css: 'text/css;charset=utf-8',
        js: 'text/javascript;charset=utf-8',
        jpg: 'image/jpeg',
        jpeg: 'image/jpeg',
        png: 'image/png',
        gif: 'image/gif',
        webp: 'image/webp',
        svg: 'image/svg+xml',
        bmp: 'image/bmp',
        ico: 'image/x-icon',
        mp4: 'video/mp4',
        webm: 'video/webm',
        mov: 'video/quicktime',
        mkv: 'video/x-matroska',
        mp3: 'audio/mpeg',
        ogg: 'audio/ogg',
        wav: 'audio/wav',
        m4a: 'audio/mp4',
        aac: 'audio/aac',
        flac: 'audio/flac',
        opus: 'audio/opus'
    };
    return map[ext] || 'application/octet-stream';
};

// Get file type icon and theme color
export const GetGoogleFileIcon = (filename) => {
    const ext = (filename.split('.').pop() || '').toLowerCase();
    if (['mp4', 'mkv', 'avi', 'mov', 'webm', 'ts', 'm4v', '3gp', 'flv'].includes(ext)) {
        return { icon: 'movie', color: '#e06d53' };
    }
    if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'heic', 'avif'].includes(ext)) {
        return { icon: 'image', color: '#ea4335' };
    }
    if (['mp3', 'wav', 'flac', 'm4a', 'aac', 'ogg', 'wma'].includes(ext)) {
        return { icon: 'audiotrack', color: '#f29900' };
    }
    if (['pdf'].includes(ext)) {
        return { icon: 'picture_as_pdf', color: '#ea4335' };
    }
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) {
        return { icon: 'folder_zip', color: '#5f6368' };
    }
    return { icon: 'description', color: '#4285f4' };
};

const storageKey = '__mh_enc_session__';
const kekHexRegex = /^[0-9a-fA-F]{64}$/;

// Get or generate ephemeral window key encryption key
const getOrGenerateKek = () => {
    let hex = window.name;
    if (typeof hex === 'string' && kekHexRegex.test(hex)) {
        return hex;
    }
    const rand = new Uint8Array(32);
    crypto.getRandomValues(rand);
    hex = ToHex(rand);
    rand.fill(0);
    window.name = hex;
    return hex;
};

// Import raw key for AES-GCM subtle crypto
const importKek = async (hexKey) => {
    const raw = FromHex(hexKey);
    const key = await crypto.subtle.importKey(
        'raw',
        raw,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
    raw.fill(0);
    return key;
};

// Encrypt plain session data with AES-GCM
const encryptSession = async (data, hexKey) => {
    const key = await importKek(hexKey);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);

    const plain = new TextEncoder().encode(JSON.stringify(data));
    const cipherBuf = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plain
    );

    const cipherBytes = new Uint8Array(cipherBuf);
    const res = ToHex(iv) + ToHex(cipherBytes);
    iv.fill(0);
    return res;
};

// Decrypt encrypted session payload
const decryptSession = async (payload, hexKey) => {
    if (!payload || payload.length < 24) return null;
    const iv = FromHex(payload.slice(0, 24));
    const cipher = FromHex(payload.slice(24));
    const key = await importKek(hexKey);

    const buf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        cipher
    );

    iv.fill(0);
    return JSON.parse(new TextDecoder().decode(buf));
};

// In-memory encrypted session storage manager
export class SafeSessionManager {
    constructor() {
        this.ram = {};
        this.initPromise = null;
        this.isInitialized = false;
        this.saveTimer = null;
    }

    // Initialize and decrypt session from storage
    async Init() {
        if (this.initPromise) return this.initPromise;

        this.initPromise = (async () => {
            const kek = getOrGenerateKek();
            const payload = sessionStorage.getItem(storageKey);
            if (payload) {
                try {
                    const decrypted = await decryptSession(payload, kek);
                    if (decrypted && typeof decrypted === 'object') {
                        this.ram = decrypted;
                    }
                } catch (err) {
                    console.warn('[SafeSession] Decryption failed:', err);
                    this.ram = {};
                }
            }
            this.isInitialized = true;
            return this.ram;
        })();

        return this.initPromise;
    }

    // Read item from RAM cache
    GetItem(key) {
        if (!this.ram) return null;
        const val = this.ram[key];
        return val !== undefined ? val : null;
    }

    // Store item in RAM cache and schedule disk save
    SetItem(key, value) {
        if (!this.ram) this.ram = {};
        this.ram[key] = String(value);
        this.scheduleSave();
    }

    // Delete item from RAM cache and schedule disk save
    RemoveItem(key) {
        if (this.ram && key in this.ram) {
            delete this.ram[key];
            this.scheduleSave();
        }
    }

    // Wipe session from RAM and storage
    Clear() {
        this.ram = {};
        try {
            sessionStorage.clear();
            window.name = '';
        } catch { }
    }

    // Schedule debounced disk flush
    scheduleSave() {
        if (this.saveTimer) clearTimeout(this.saveTimer);
        this.saveTimer = setTimeout(() => {
            this.Save().catch(err => console.error('[SafeSession] Save error:', err));
        }, 50);
    }

    // Encrypt and persist RAM state to storage
    async Save() {
        if (this.saveTimer) {
            clearTimeout(this.saveTimer);
            this.saveTimer = null;
        }
        try {
            const kek = getOrGenerateKek();
            const payload = await encryptSession(this.ram, kek);
            sessionStorage.setItem(storageKey, payload);
        } catch (err) {
            console.error('[SafeSession] Persist failed:', err);
        }
    }
}

// Global SafeSession instance
export const SafeSession = new SafeSessionManager();

// Show alert notice dialog modal
export const ShowNotice = (msg, title = 'Notice', icon = 'campaign') => {
    const modal = document.getElementById('noticeModal');
    if (!modal) {
        alert(msg);
        return Promise.resolve();
    }
    const textEl = document.getElementById('noticeText');
    const titleEl = document.getElementById('noticeTitle');
    const iconEl = document.getElementById('noticeIcon');
    const btn = document.getElementById('btnConfirmNotice');

    if (textEl) textEl.textContent = msg;
    if (titleEl) titleEl.textContent = title;
    if (iconEl) {
        iconEl.textContent = icon;
        if (icon === 'error' || icon === 'delete') {
            iconEl.style.color = 'var(--g-danger, #b3261e)';
        } else if (icon === 'warning') {
            iconEl.style.color = '#ea8600';
        } else if (icon === 'check_circle' || icon === 'check') {
            iconEl.style.color = '#137333';
        } else {
            iconEl.style.color = 'var(--g-primary-blue, #0b57d0)';
        }
    }

    modal.showModal();
    return new Promise(resolve => {
        const handler = () => {
            btn.removeEventListener('click', handler);
            modal.close();
            resolve();
        };
        btn.addEventListener('click', handler);
        modal.addEventListener('close', () => {
            btn.removeEventListener('click', handler);
            resolve();
        }, { once: true });
    });
};

// Show notice dialog with dynamic severity icon
export const ShowAlert = (msg) => {
    let title = 'Notice';
    let icon = 'campaign';
    if (typeof msg === 'string') {
        const lower = msg.toLowerCase();
        if (msg.includes('❌') || lower.includes('fail') || lower.includes('error') || lower.includes('invalid')) {
            title = 'Error';
            icon = 'error';
        } else if (msg.includes('⚠️') || lower.includes('warning') || lower.includes('fill')) {
            title = 'Notice';
            icon = 'warning';
        } else if (msg.includes('✅') || lower.includes('success')) {
            title = 'Success';
            icon = 'check_circle';
        }
    }
    return ShowNotice(msg, title, icon);
};

// Show confirmation modal dialog
export const ShowConfirmModal = (msg, title = 'Confirm', icon = 'help', confirmText = 'Confirm', isDanger = false) => {
    return new Promise((resolve) => {
        const modal = document.getElementById('confirmModal');
        if (!modal) {
            return resolve(confirm(msg));
        }
        const textEl = document.getElementById('confirmModalText');
        const titleEl = document.getElementById('confirmModalTitle');
        const iconEl = document.getElementById('confirmModalIcon');
        const btnCancel = document.getElementById('btnCancelConfirmModal');
        const btnConfirm = document.getElementById('btnActionConfirmModal');

        if (textEl) textEl.innerHTML = msg;
        if (titleEl) titleEl.textContent = title;
        if (iconEl) {
            iconEl.textContent = icon;
            iconEl.style.color = isDanger ? 'var(--g-danger, #b3261e)' : 'var(--g-primary-blue, #0b57d0)';
        }
        if (btnConfirm) {
            btnConfirm.textContent = confirmText;
            btnConfirm.className = isDanger ? 'btn-dialog-danger' : 'btn-dialog-primary';
        }

        modal.showModal();

        const cleanup = () => {
            btnConfirm.removeEventListener('click', onConfirm);
            btnCancel.removeEventListener('click', onCancel);
        };

        const onCancel = () => {
            cleanup();
            modal.close();
            resolve(false);
        };

        const onConfirm = () => {
            cleanup();
            modal.close();
            resolve(true);
        };

        modal.addEventListener('close', () => { cleanup(); resolve(false); }, { once: true });
        btnConfirm.addEventListener('click', onConfirm);
        btnCancel.addEventListener('click', onCancel);
    });
};

// Disable browser autocomplete on text input elements
export const DisableAllAutocomplete = () => {
    document.querySelectorAll('input:not([type="checkbox"]):not([type="file"]):not([type="radio"])').forEach(input => {
        if (!input.hasAttribute('autocomplete') || input.getAttribute('autocomplete') !== 'new-password') {
            input.setAttribute('autocomplete', 'off');
        }
        input.setAttribute('autocorrect', 'off');
        input.setAttribute('autocapitalize', 'off');
        input.setAttribute('spellcheck', 'false');
        input.setAttribute('data-lpignore', 'true');
    });
};
