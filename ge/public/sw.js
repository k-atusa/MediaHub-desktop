// Service worker for range-based on-the-fly AES-GCM streaming decryption
const plainChunkSize = 1048576;
const cipherChunkSize = plainChunkSize + 16;
const maxResponseSize = 2 * 1048576;
const maxCacheEntries = 24;

const registryMap = new Map();
const chunkCache = new Map();

// Get cached chunk promise from memory map
const getChunkCache = (filePid, idx) => {
    const key = `${filePid}_${idx}`;
    const entry = chunkCache.get(key);
    if (entry) {
        entry.ts = Date.now();
        return entry.dataPromise;
    }
    return null;
};

// Store chunk promise in LRU cache
const setChunkCache = (filePid, idx, dataPromise) => {
    const key = `${filePid}_${idx}`;
    chunkCache.set(key, { dataPromise, ts: Date.now() });
    if (chunkCache.size > maxCacheEntries) {
        let oldest = null;
        let oldestKey = null;
        for (const [k, val] of chunkCache) {
            if (!oldest || val.ts < oldest) {
                oldest = val.ts;
                oldestKey = k;
            }
        }
        if (oldestKey) chunkCache.delete(oldestKey);
    }
};

// Purge all cached chunks for a specific file
const purgeChunkCache = (filePid) => {
    for (const key of [...chunkCache.keys()]) {
        if (key.startsWith(filePid + '_')) chunkCache.delete(key);
    }
};

// Convert hex string to Uint8Array buffer
const hexToBytes = (hex) => {
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < arr.length; i++) {
        arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return arr;
};

// Derive chunk-specific IV by XORing counter into base IV
const deriveChunkIv = (globalIv, count) => {
    const iv = new Uint8Array(globalIv);
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, BigInt(count), true);
    const counterBytes = new Uint8Array(buf);
    for (let i = 0; i < 8; i++) iv[4 + i] ^= counterBytes[i];
    return iv;
};

// Map media extension to standard MIME type
const getVideoMime = (name) => {
    const ext = (name || '').split('.').pop().toLowerCase();
    const map = {
        mp4: 'video/mp4',
        webm: 'video/webm',
        mov: 'video/mp4',
        mkv: 'video/x-matroska',
        mp3: 'audio/mpeg',
        ogg: 'audio/ogg',
        wav: 'audio/wav',
        m4a: 'audio/mp4',
        aac: 'audio/aac',
        flac: 'audio/flac',
        opus: 'audio/opus'
    };
    return map[ext] || 'video/mp4';
};

// Handle client registration and cache purge messages
self.addEventListener('message', async (e) => {
    const data = e.data;
    if (data.action === 'REGISTER') {
        const raw = hexToBytes(data.fileKey);
        const aesKey = raw.slice(0, 32);
        const cryptoKey = await crypto.subtle.importKey('raw', aesKey, 'AES-GCM', false, ['decrypt']);
        aesKey.fill(0);
        raw.fill(0);
        registryMap.set(data.filePid, {
            folderId: data.folderId,
            globalIv: null,
            globalIvPromise: null,
            cryptoKey,
            origSize: data.originalSize,
            mime: getVideoMime(data.fileName)
        });

        if (e.source) e.source.postMessage({ action: 'REGISTERED', filePid: data.filePid });
    } else if (data.action === 'UNREGISTER') {
        const info = registryMap.get(data.filePid);
        if (info?.globalIv) info.globalIv.fill(0);
        registryMap.delete(data.filePid);
        purgeChunkCache(data.filePid);
    } else if (data.action === 'CLEAR_CACHE') {
        for (const [, info] of registryMap) {
            if (info?.globalIv) info.globalIv.fill(0);
        }
        registryMap.clear();
        chunkCache.clear();
    }
});

// Retrieve registered decryption credentials or query window clients
const getFileInfo = async (filePid) => {
    if (registryMap.has(filePid)) return registryMap.get(filePid);

    const windowClients = await clients.matchAll({ type: 'window' });
    if (windowClients.length === 0) return null;

    windowClients.forEach(c => c.postMessage({ action: 'REQUEST_KEY', filePid }));

    for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 100));
        if (registryMap.has(filePid)) return registryMap.get(filePid);
    }
    return null;
};

// Intercept streaming URL requests
self.addEventListener('fetch', (e) => {
    let url;
    try {
        url = new URL(e.request.url);
    } catch {
        return;
    }
    const match = url.pathname.match(/^\/sw-stream\/([^/]+)\/([^/]+)$/);
    if (!match) return;

    e.respondWith(
        handleStream(e.request, match[1], match[2]).catch(err => {
            console.warn('SW stream response error:', err);
            return new Response(new Uint8Array(0), {
                status: 416,
                headers: { 'Content-Range': 'bytes */0', 'Accept-Ranges': 'bytes' }
            });
        })
    );
});

// Handle range request and stream decrypted chunk payload
const handleStream = async (req, folderId, filePid) => {
    const rangeHeader = req.headers.get('Range');
    let origSize = 0;
    try {
        const info = await getFileInfo(filePid);
        if (!info) return new Response('Not registered', { status: 404 });

        origSize = info.origSize;
        const { mime } = info;

        if (req.signal && req.signal.aborted) {
            return new Response(new Uint8Array(0), {
                status: 416,
                headers: { 'Content-Range': `bytes */${origSize}`, 'Accept-Ranges': 'bytes' }
            });
        }

        let rangeStart = 0;
        let rangeEnd = origSize - 1;
        if (rangeHeader) {
            const suffixMatch = rangeHeader.match(/bytes=-(\d+)/);
            if (suffixMatch) {
                const sLen = parseInt(suffixMatch[1], 10);
                rangeStart = Math.max(0, origSize - sLen);
                rangeEnd = origSize - 1;
            } else {
                const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
                if (match) {
                    rangeStart = parseInt(match[1], 10);
                    if (match[2]) {
                        rangeEnd = parseInt(match[2], 10);
                    }
                }
            }
        }

        if (rangeEnd - rangeStart + 1 > maxResponseSize) {
            rangeEnd = rangeStart + maxResponseSize - 1;
        }
        rangeEnd = Math.min(rangeEnd, origSize - 1);

        if (rangeStart > rangeEnd || rangeStart >= origSize) {
            return new Response(new Uint8Array(0), {
                status: 416,
                headers: {
                    'Content-Range': `bytes */${origSize}`,
                    'Content-Type': mime,
                    'Accept-Ranges': 'bytes'
                }
            });
        }

        const firstIdx = Math.floor(rangeStart / plainChunkSize);
        const lastIdx = Math.floor(rangeEnd / plainChunkSize);
        const len = rangeEnd - rangeStart + 1;

        const chunkPromises = [];
        for (let idx = firstIdx; idx <= lastIdx; idx++) {
            let chunkProm = getChunkCache(filePid, idx);
            if (!chunkProm) {
                chunkProm = fetchDecryptedChunk(info, folderId, filePid, idx).catch(err => {
                    chunkCache.delete(`${filePid}_${idx}`);
                    throw err;
                });
                setChunkCache(filePid, idx, chunkProm);
            }
            chunkPromises.push(chunkProm);
        }

        const chunks = await Promise.all(chunkPromises);

        if (req.signal && req.signal.aborted) {
            return new Response(new Uint8Array(0), {
                status: 416,
                headers: { 'Content-Range': `bytes */${origSize}`, 'Accept-Ranges': 'bytes' }
            });
        }

        const resultBuf = new Uint8Array(len);
        let offset = 0;
        for (let i = 0; i < chunks.length; i++) {
            const chunkBase = (firstIdx + i) * plainChunkSize;
            const plain = chunks[i];
            const from = Math.max(rangeStart, chunkBase) - chunkBase;
            const to = Math.min(rangeEnd, chunkBase + plain.length - 1) - chunkBase;
            if (from <= to) {
                const slice = plain.subarray(from, to + 1);
                resultBuf.set(slice, offset);
                offset += slice.length;
            }
        }

        return new Response(resultBuf, {
            status: 206,
            headers: {
                'Content-Type': mime,
                'Content-Length': len.toString(),
                'Content-Range': `bytes ${rangeStart}-${rangeEnd}/${origSize}`,
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'no-cache'
            }
        });
    } catch (err) {
        console.warn(`Stream seek range error (${rangeHeader}):`, err);
        return new Response(new Uint8Array(0), {
            status: 416,
            headers: {
                'Content-Range': `bytes */${origSize || 0}`,
                'Accept-Ranges': 'bytes'
            }
        });
    }
};

// Fetch global IV from the first 12 bytes of file
const ensureGlobalIv = async (info, folderId, filePid) => {
    if (info.globalIv) return info.globalIv;
    if (!info.globalIvPromise) {
        info.globalIvPromise = (async () => {
            const res = await fetch(`/api/media/${folderId}/${filePid}/dat`, {
                headers: { 'Range': 'bytes=0-11' }
            });
            info.globalIv = new Uint8Array(await res.arrayBuffer());
            return info.globalIv;
        })();
    }
    return info.globalIvPromise;
};

// Download and decrypt specific chunk slice
const fetchDecryptedChunk = async (info, folderId, filePid, chunkIdx) => {
    const { origSize, cryptoKey } = info;
    const globalIv = await ensureGlobalIv(info, folderId, filePid);

    const plainLen = Math.min(plainChunkSize, origSize - chunkIdx * plainChunkSize);
    if (plainLen <= 0) return new Uint8Array(0);
    const cipherLen = plainLen + 16;

    const cStart = 12 + chunkIdx * cipherChunkSize;
    const cEnd = cStart + cipherLen - 1;

    let lastErr;
    for (let attempt = 1; attempt <= 3; attempt++) {
        try {
            const res = await fetch(`/api/media/${folderId}/${filePid}/dat`, {
                headers: { 'Range': `bytes=${cStart}-${cEnd}` }
            });
            if (!res.ok && res.status !== 206 && res.status !== 200) {
                throw new Error(`HTTP ${res.status}`);
            }
            const cipherBuf = await res.arrayBuffer();
            if (cipherBuf.byteLength !== cipherLen) {
                throw new Error(`Length mismatch: got ${cipherBuf.byteLength}, expected ${cipherLen}`);
            }

            const iv = deriveChunkIv(globalIv, chunkIdx);
            const plain = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                cryptoKey,
                cipherBuf
            );
            return new Uint8Array(plain);
        } catch (err) {
            lastErr = err;
            console.warn(`Chunk ${chunkIdx} fetch attempt ${attempt} failed:`, err);
            if (attempt < 3) await new Promise(r => setTimeout(r, 300 * attempt));
        }
    }
    throw lastErr;
};

// Service Worker lifecycle activation
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
