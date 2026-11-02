// Desktop Wails network and crypto adapter
import { ToHex, FromHex, ShowNotice, DownloadProgressController } from './utils.js';

// Desktop Wails Adapter: All crypto and session management delegated to Go backend
export class AdapterService {
    // Initialize adapter properties
    constructor() {
        this.serverUrl = "";
        this.RequiresServiceWorker = false;
        this._streamEpoch = 0;
        this._streamPids = new Set();
        this._lastAuthCreds = null;
    }

    // Retrieve saved user credentials
    async GetSavedCredentials() {
        return null;
    }

    // Persist user credentials in memory for registration flow
    async SaveCredentials(username, password) {
        this._lastAuthCreds = { username, password };
    }

    // Fetch notice message from server
    async FetchNotice() {
        try {
            // Call Go backend to fetch notice
            if (window.go?.main?.App?.FetchNotice) {
                return await window.go.main.App.FetchNotice();
            }
            // Fallback fetch request
            const res = await fetch(`${window.location.origin}/api/notice`);
            if (!res.ok) return "";
            const data = await res.json();
            return data.notice || "";
        } catch {
            return "";
        }
    }

    // Display application info dialog
    async ShowAppInfo() {
        // Delegate to backend native dialog
        if (window.go?.main?.App?.ShowAppInfo) {
            await window.go.main.App.ShowAppInfo();
        } else {
            await ShowNotice("MediaHub Desktop GE (Go + Wails) v1.6.0", "About MediaHub", "info");
        }
    }

    // Authenticate user and derive keys via Argon2id in backend
    async DeriveKeys(username, password) {
        this._lastAuthCreds = { username, password };
        if (window.go?.main?.App?.Login) {
            try {
                // Attempt login and key derivation in Go backend
                const res = await window.go.main.App.Login(username, password);
                return {
                    userHash: res.userHash,
                    maskedKey: FromHex(res.userKey)
                };
            } catch (err) {
                // Check if account does not exist to support registration flow
                if (window.go?.main?.App?.CheckUserExists) {
                    try {
                        const exists = await window.go.main.App.CheckUserExists(username, password);
                        if (!exists) {
                            return { userHash: "PENDING_REGISTRATION", maskedKey: new Uint8Array(32) };
                        }
                    } catch { }
                }
                throw err;
            }
        }
        throw new Error("Wails backend is not available");
    }

    // Check if user account exists on server
    async CheckUserExists(userHash) {
        if (userHash === "PENDING_REGISTRATION") return false;
        return true;
    }

    // Register user account on server with invite code
    async RegisterUser(userHash, inviteCode = "") {
        if (!this._lastAuthCreds) {
            throw new Error("Missing registration credentials");
        }
        const { username, password } = this._lastAuthCreds;
        // Call backend registration endpoint
        if (window.go?.main?.App?.Register) {
            return await window.go.main.App.Register(username, password, inviteCode);
        }
        throw new Error("Wails backend is not available");
    }

    // Delete user account data on server
    async DeleteUserData(userHash) {
        // Delegate account deletion to backend
        if (window.go?.main?.App?.DeleteAccount) {
            await window.go.main.App.DeleteAccount();
        }
    }

    // Load folder map from backend
    async LoadUserData(userHash, maskedUserKey) {
        // Retrieve decrypted folder keys from backend
        if (window.go?.main?.App?.GetFolders) {
            const fldMap = await window.go.main.App.GetFolders();
            const out = {};
            for (const [name, meta] of Object.entries(fldMap || {})) {
                out[name] = FromHex(meta.folderKey);
            }
            return out;
        }
        return {};
    }

    // Persist folder map to server
    async SaveUserData(userHash, rawFolderMap, maskedUserKey, oldHash = "") {
        // Backend handles persistence automatically on folder operations
    }

    // Load folder files metadata
    async LoadFolderMeta(folderId, maskedFolderKey) {
        return {};
    }

    // Save folder files metadata
    async SaveFolderMeta(folderId, rawFilesMap, maskedFolderKey, userHash = "") {
        // Backend handles persistence automatically on file operations
    }

    // Delete folder metadata from server
    async DeleteFolderMeta(folderId, userHash = "") {
        // Backend handles deletion automatically
    }

    // Trim orphan files in folder
    async TrimFolder(folderId, activePids, userHash = "") {
        return "OK";
    }

    // Return media stream URL for video or audio playback
    async LoadMediaBlob(folderId, filePid, maskedFileKey, origSize = 0, mimeType = "application/octet-stream", onProgress = null) {
        // Return local proxy URL directly as media source
        return this.GetStreamUrl(folderId, filePid, maskedFileKey, origSize, "");
    }

    // Download and decrypt file directly via native dialog
    async DownloadFile(folderId, filePid, maskedFileKey, fileName, origSize = 0) {
        const toast = new DownloadProgressController(fileName);
        try {
            if (window.go?.main?.App?.DownloadFile) {
                // Subscribe to download progress events from Wails
                const unoff = window.runtime?.EventsOn?.("download_progress", (data) => {
                    if (data.fileName === fileName) {
                        toast.update({
                            phase: 'downloading',
                            loaded: data.loaded,
                            total: data.total,
                            percent: data.percent
                        });
                    }
                });

                // Trigger backend streaming download
                try {
                    await window.go.main.App.DownloadFile(folderId, fileName);
                    toast.update({ phase: 'complete', percent: 100 });
                } finally {
                    if (typeof unoff === 'function') unoff();
                }
                return;
            }
            throw new Error("Wails backend download is not available");
        } catch (err) {
            toast.fail(err);
            throw err;
        }
    }

    // Delete media binary and thumbnail
    async DeleteMedia(folderId, filePid, userHash = "") {
        // Backend deletes both binary and thumbnail simultaneously
    }

    // Load and return decrypted thumbnail URL from proxy
    async LoadThumbnailUrl(folderId, filePid, maskedFileKey) {
        // Register key with proxy if provided
        if (maskedFileKey && window.go?.main?.App?.RegisterFileStreaming) {
            const hexKey = (maskedFileKey instanceof Uint8Array) ? ToHex(maskedFileKey) : String(maskedFileKey);
            window.go.main.App.RegisterFileStreaming(filePid, hexKey);
        }
        // Retrieve local thumbnail endpoint URL
        if (window.go?.main?.App?.GetThumbUrl) {
            return await window.go.main.App.GetThumbUrl(folderId, filePid);
        }
        return `http://127.0.0.1:18080/thumb/${folderId}/${filePid}`;
    }

    // Generate JPEG thumbnail from image file in webview
    async MakeImageThumb(file) {
        try {
            // Render bitmap onto scaled HTML5 canvas
            const bmp = await createImageBitmap(file);
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const ratio = bmp.width / bmp.height;

            // Maintain aspect ratio within 256px
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

            // Export canvas as JPEG blob
            return new Promise(r => canvas.toBlob(r, 'image/jpeg', 0.7));
        } catch {
            return null;
        }
    }

    // Generate JPEG thumbnail from video file in webview
    MakeVideoThumb(file) {
        return new Promise((resolve) => {
            // Create hidden video element to capture first frame
            const video = document.createElement('video');
            video.preload = 'metadata';
            video.muted = true;
            video.playsInline = true;
            video.src = URL.createObjectURL(file);

            // Seek to 1 second timestamp
            video.onloadeddata = () => { video.currentTime = 1; };

            // Draw captured frame onto canvas
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

                // Export canvas to JPEG blob
                canvas.toBlob((b) => {
                    URL.revokeObjectURL(video.src);
                    resolve(b);
                }, 'image/jpeg', 0.7);
            };

            // Handle video loading failure
            video.onerror = () => {
                URL.revokeObjectURL(video.src);
                resolve(null);
            };
        });
    }

    // Get local proxy stream URL for video or audio playback
    async GetStreamUrl(folderId, filePid, maskedFileKey, origSize, fileName) {
        // Register key with proxy if provided
        if (maskedFileKey && window.go?.main?.App?.RegisterFileStreaming) {
            const hexKey = (maskedFileKey instanceof Uint8Array) ? ToHex(maskedFileKey) : String(maskedFileKey);
            window.go.main.App.RegisterFileStreaming(filePid, hexKey);
        }
        // Retrieve local stream proxy URL
        if (window.go?.main?.App?.GetStreamUrl) {
            return await window.go.main.App.GetStreamUrl(folderId, fileName || filePid);
        }
        return `http://127.0.0.1:18080/stream/${folderId}/${encodeURIComponent(fileName || filePid)}`;
    }

    // Register file streaming credentials
    async RegisterStreaming(folderId, filePid, maskedFileKey, origSize, fileName) {
        if (maskedFileKey && window.go?.main?.App?.RegisterFileStreaming) {
            const hexKey = (maskedFileKey instanceof Uint8Array) ? ToHex(maskedFileKey) : String(maskedFileKey);
            await window.go.main.App.RegisterFileStreaming(filePid, hexKey);
        }
        return true;
    }

    // Release active streaming registrations
    ReleaseStreaming() {
        // No service worker unregistration required in desktop
    }

    // Generate viewer file share URL
    async CreateShareLink(folderId, filePid, maskedFileKey = null, fileName = null, origSize = 0) {
        return `${window.location.origin}/viewer?f=${encodeURIComponent(folderId)}&p=${encodeURIComponent(filePid)}`;
    }

    // Check if current route is publicly accessible
    async IsPublicRoute(path, query) {
        return Boolean(query?.s);
    }

    // Export password-encrypted folder share token
    async ExportShareToken(folderName, maskedKey, password) {
        if (window.go?.main?.App?.ExportShareToken) {
            return await window.go.main.App.ExportShareToken(folderName, password);
        }
        return null;
    }

    // Import password-protected folder share token
    async ImportShareToken(tokenText, password) {
        if (window.go?.main?.App?.ImportShareToken) {
            const res = await window.go.main.App.ImportShareToken(tokenText, password);
            if (!res || !res.name) return null;
            return {
                name: res.name,
                key: FromHex(res.folderKey)
            };
        }
        return null;
    }

    // Save session bytes to desktop temp vault
    async SaveSessionBytes(plainBytes) {
        if (!plainBytes || plainBytes.length === 0) {
            await this.ClearSessionBytes();
            return;
        }
        const hex = ToHex(plainBytes);
        if (window.go?.main?.App?.SaveSessionBytes) {
            await window.go.main.App.SaveSessionBytes(hex);
        }
    }

    // Load session bytes from desktop temp vault
    async LoadSessionBytes() {
        if (window.go?.main?.App?.LoadSessionBytes) {
            const hex = await window.go.main.App.LoadSessionBytes();
            if (hex && hex.length > 0) {
                return FromHex(hex);
            }
        }
        return null;
    }

    // Clear session bytes from desktop temp vault
    async ClearSessionBytes() {
        if (window.go?.main?.App?.ClearSessionBytes) {
            await window.go.main.App.ClearSessionBytes();
        }
    }
}

// Global adapter instance
export const Adapter = new AdapterService();
