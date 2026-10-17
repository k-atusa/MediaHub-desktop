// Backend network communication and client-side encryption adapter
import { SHA3256, SymMaster, Random, Masker, HashMaster } from '../engine/Bencrypt.js';
import { EncodeCfg, DecodeCfg, EncodeInt, DecodeInt, PadLen, Opsec } from '../engine/Opsec.js';
import { NormPW, Encode64, Decode64 } from '../engine/Bencode.js';
import { ToHex, FromHex, GetObjPid } from './utils.js';

// Derive 16-byte user public identifier from store key
const getUserPid = (key) => {
    if (!key) return '';
    return ToHex(SHA3256(key).slice(0, 16));
};

const mask = new Masker();
const secretPepper = "_PROJECT_WHY_MEDIAHUB_PEPPER_2026_!@#$";

// Web platform backend adapter service
export class AdapterService {
    // Initialize adapter with window origin
    constructor() {
        this.serverUrl = window.location.origin;
    }

    // Derive deterministic authentication user hash and masked master key
    async DeriveKeys(username, password) {
        const pwBytes = NormPW(password);
        const saltBytes = SHA3256(new TextEncoder().encode(username + secretPepper));
        const hm = new HashMaster("arg2st");
        const [storeKey, userKey] = await hm.KDF(pwBytes, saltBytes);
        const userHash = getUserPid(storeKey);
        const maskedKey = mask.XOR(userKey);
        userKey.fill(0);
        return { userHash, maskedKey };
    }

    // Check if user account exists on server
    async CheckUserExists(userHash) {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`);
        return res.status !== 404;
    }

    // Register user account on server with optional invite code
    async RegisterUser(userHash, inviteCode = "") {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`, {
            method: "POST",
            headers: inviteCode ? { "X-Invite-Code": inviteCode } : {},
            body: new Uint8Array(0)
        });
        if (!res.ok) {
            if (res.status === 403) throw new Error("Invalid invite code");
            throw new Error(`Registration failed (HTTP ${res.status})`);
        }
    }

    // Fetch server notification banner text
    async FetchNotice() {
        try {
            const res = await fetch(`${this.serverUrl}/api/notice`);
            if (!res.ok) return "";
            const data = await res.json();
            return data.notice || "";
        } catch {
            return "";
        }
    }

    // Fetch and decrypt user folder map from server
    async LoadUserData(userHash, maskedUserKey) {
        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`);
        if (res.status === 404) return {};
        if (!res.ok) throw new Error(`Failed to load userdata (HTTP ${res.status})`);

        const rawUk = mask.XOR(maskedUserKey);
        const sm = new SymMaster("gcm1", rawUk);
        rawUk.fill(0);

        const enc = new Uint8Array(await res.arrayBuffer());
        if (enc.length === 0) return {};

        const dec = await sm.DeBin(enc);
        const map = DecodeCfg(dec);
        dec.fill(0);
        return map;
    }

    // Encrypt and persist user folder map to server
    async SaveUserData(userHash, rawFolderMap, maskedUserKey, oldHash = "") {
        const rawUk = mask.XOR(maskedUserKey);
        const sm = new SymMaster("gcm1", rawUk);
        rawUk.fill(0);

        const bin = EncodeCfg(rawFolderMap);
        const enc = await sm.EnBin(bin);
        bin.fill(0);

        const headers = { "X-User-Hash": oldHash || userHash };
        if (oldHash) headers["X-Old-Hash"] = oldHash;

        const res = await fetch(`${this.serverUrl}/api/userdata/${userHash}`, {
            method: "POST",
            headers,
            body: enc
        });
        enc.fill(0);

        if (!res.ok) throw new Error(`Failed to save userdata (HTTP ${res.status})`);
    }

    // Fetch and decrypt folder file map from server
    async LoadFolderMeta(folderId, maskedFolderKey) {
        const res = await fetch(`${this.serverUrl}/api/storage/${folderId}/names`);
        if (res.status === 404) return {};
        if (!res.ok) throw new Error(`Failed to load folder map (HTTP ${res.status})`);

        const rawFk = mask.XOR(maskedFolderKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const enc = new Uint8Array(await res.arrayBuffer());
        if (enc.length === 0) return {};

        const dec = await sm.DeBin(enc);
        const map = DecodeCfg(dec);
        dec.fill(0);
        return map;
    }

    // Encrypt and persist folder file map to server
    async SaveFolderMeta(folderId, rawFilesMap, maskedFolderKey, userHash = "") {
        const rawFk = mask.XOR(maskedFolderKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const bin = EncodeCfg(rawFilesMap);
        const enc = await sm.EnBin(bin);
        bin.fill(0);

        const headers = {};
        if (userHash) headers["X-User-Hash"] = userHash;

        const res = await fetch(`${this.serverUrl}/api/storage/${folderId}/names`, {
            method: "POST",
            headers,
            body: enc
        });
        enc.fill(0);

        if (!res.ok) throw new Error(`Failed to save folder map (HTTP ${res.status})`);
    }

    // Delete folder catalog entry on server
    async DeleteFolderMeta(folderId, userHash = "") {
        const headers = {};
        if (userHash) headers["X-User-Hash"] = userHash;

        const res = await fetch(`${this.serverUrl}/api/storage/${folderId}/names`, {
            method: "DELETE",
            headers
        });
        if (!res.ok && res.status !== 404) {
            throw new Error(`Failed to delete folder meta (HTTP ${res.status})`);
        }
    }

    // Trim orphan files from folder storage
    async TrimFolder(folderId, activePids, userHash = "") {
        const headers = { "Content-Type": "application/json" };
        if (userHash) headers["X-User-Hash"] = userHash;

        const res = await fetch(`${this.serverUrl}/api/trim/${folderId}`, {
            method: "POST",
            headers,
            body: JSON.stringify(activePids)
        });
        if (!res.ok) throw new Error(`Trim failed (HTTP ${res.status})`);
        return await res.text();
    }

    // Load and decrypt thumbnail blob URL
    async LoadThumbnailUrl(folderId, filePid, maskedFileKey) {
        const res = await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/thumb`);
        if (!res.ok) return null;

        const rawFk = mask.XOR(maskedFileKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const enc = new Uint8Array(await res.arrayBuffer());
        const dec = await sm.DeBin(enc);
        const blob = new Blob([dec], { type: "image/webp" });
        dec.fill(0);
        return URL.createObjectURL(blob);
    }

    // Download and decrypt media payload to blob URL
    async LoadMediaBlob(folderId, filePid, maskedFileKey, origSize = 0, mimeType = "application/octet-stream") {
        const downloadChunkSize = 16 * 1024 * 1024;
        const url = `${this.serverUrl}/api/media/${folderId}/${filePid}/dat`;

        // Fetch first chunk to determine total file size from Content-Range
        const firstRes = await fetch(url, {
            headers: { 'Range': `bytes=0-${downloadChunkSize - 1}` }
        });
        if (!firstRes.ok && firstRes.status !== 206) {
            throw new Error(`Failed to download media (HTTP ${firstRes.status})`);
        }

        const firstChunk = new Uint8Array(await firstRes.arrayBuffer());

        // Parse total size from Content-Range header or use first chunk length
        let totalSize = firstChunk.length;
        const contentRange = firstRes.headers.get('Content-Range');
        if (contentRange) {
            const sizeMatch = contentRange.match(/\/(\d+)/);
            if (sizeMatch) totalSize = parseInt(sizeMatch[1], 10);
        }

        // Assemble full ciphertext buffer from range chunks
        const enc = new Uint8Array(totalSize);
        enc.set(firstChunk, 0);
        let downloaded = firstChunk.length;

        while (downloaded < totalSize) {
            const rangeEnd = Math.min(downloaded + downloadChunkSize, totalSize) - 1;
            const chunkRes = await fetch(url, {
                headers: { 'Range': `bytes=${downloaded}-${rangeEnd}` }
            });
            if (!chunkRes.ok && chunkRes.status !== 206) {
                throw new Error(`Failed to download media chunk (HTTP ${chunkRes.status})`);
            }
            const chunk = new Uint8Array(await chunkRes.arrayBuffer());
            enc.set(chunk, downloaded);
            downloaded += chunk.length;
        }

        // Decrypt assembled ciphertext
        const rawFk = mask.XOR(maskedFileKey);
        const sm = new SymMaster("gcm1", rawFk.slice(0, 32));
        rawFk.fill(0);

        const dec = await sm.DeBin(enc);
        const unpadded = (origSize > 0 && dec.length >= origSize) ? dec.slice(0, origSize) : dec;
        const blob = new Blob([unpadded], { type: mimeType });
        dec.fill(0);
        return URL.createObjectURL(blob);
    }

    // Delete media binary and thumbnail from server
    async DeleteMedia(folderId, filePid, userHash = "") {
        const headers = {};
        if (userHash) headers["X-User-Hash"] = userHash;

        await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/dat`, {
            method: "DELETE",
            headers
        });
        await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/thumb`, {
            method: "DELETE",
            headers
        });
    }

    // Register video streaming credentials with Service Worker
    async RegisterStreaming(folderId, filePid, maskedFileKey, origSize, fileName) {
        if (!navigator.serviceWorker || !navigator.serviceWorker.controller) {
            return false;
        }

        const rawFk = mask.XOR(maskedFileKey);
        const hexKey = ToHex(rawFk);
        rawFk.fill(0);

        return new Promise((resolve) => {
            const channel = new MessageChannel();
            channel.port1.onmessage = (e) => {
                if (e.data?.action === 'REGISTERED') resolve(true);
            };
            navigator.serviceWorker.controller.postMessage({
                action: 'REGISTER',
                filePid,
                folderId,
                fileKey: hexKey,
                originalSize: origSize,
                fileName
            }, [channel.port2]);

            setTimeout(() => resolve(true), 500);
        });
    }

    // Register streaming credentials and return SW stream endpoint URL
    async GetStreamUrl(folderId, filePid, maskedFileKey, origSize, fileName) {
        await this.RegisterStreaming(folderId, filePid, maskedFileKey, origSize, fileName);
        return `/sw-stream/${folderId}/${filePid}`;
    }

    // Retrieve saved user credentials
    async GetSavedCredentials() {
        return null;
    }

    // Persist user credentials
    async SaveCredentials(username, password) { }

    // Export password-encrypted folder share token
    async ExportShareToken(folderName, maskedKey, password) {
        if (!password) return null;
        const rawKey = mask.XOR(maskedKey);
        const op = new Opsec();
        op.Smsg = folderName;
        op.SmsgInfo = rawKey;
        const head = await op.Encpw('arg2st', NormPW(password));
        rawKey.fill(0);
        return Encode64(head, '#');
    }

    // Import and decrypt password-protected folder share token
    async ImportShareToken(tokenText, password) {
        try {
            if (!password || !tokenText) return null;
            const raw = Decode64(tokenText.trim(), '#');
            const op = new Opsec();
            op.View(raw);
            await op.Decpw(NormPW(password));
            if (!op.Smsg || op.SmsgInfo.length === 0) return null;
            const maskedKey = mask.XOR(op.SmsgInfo);
            op.SmsgInfo.fill(0);
            return { name: op.Smsg, key: maskedKey };
        } catch {
            return null;
        }
    }

    // Generate JPEG thumbnail blob from image File
    async MakeImageThumb(file) {
        try {
            const bmp = await createImageBitmap(file);
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const ratio = bmp.width / bmp.height;
            if (ratio >= 0.6666 && ratio <= 1.5) {
                if (bmp.width >= bmp.height) {
                    canvas.width = 256;
                    canvas.height = Math.round(256 / ratio);
                } else {
                    canvas.height = 256;
                    canvas.width = Math.round(256 * ratio);
                }
                ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
            } else {
                const size = Math.min(bmp.width, bmp.height);
                canvas.width = 256;
                canvas.height = 256;
                ctx.drawImage(bmp, 0, 0, size, size, 0, 0, 256, 256);
            }
            bmp.close();
            return new Promise(r => canvas.toBlob(r, 'image/jpeg', 0.7));
        } catch {
            return null;
        }
    }

    // Generate JPEG thumbnail blob from video File
    MakeVideoThumb(file) {
        return new Promise((resolve) => {
            const video = document.createElement('video');
            video.preload = 'metadata';
            video.muted = true;
            video.playsInline = true;
            video.src = URL.createObjectURL(file);
            video.onloadeddata = () => video.currentTime = 1;
            video.onseeked = () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                const ratio = video.videoWidth / video.videoHeight;
                if (video.videoWidth >= video.videoHeight) {
                    canvas.width = 256;
                    canvas.height = Math.round(256 / ratio);
                } else {
                    canvas.height = 256;
                    canvas.width = Math.round(256 * ratio);
                }
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                canvas.toBlob((b) => {
                    URL.revokeObjectURL(video.src);
                    resolve(b);
                }, 'image/jpeg', 0.7);
            };
            video.onerror = () => {
                URL.revokeObjectURL(video.src);
                resolve(null);
            };
        });
    }
}

// Global adapter singleton instance
export const Adapter = new AdapterService();
