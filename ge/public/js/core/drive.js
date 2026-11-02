// Desktop drive service state management
import { SafeSession, ToHex, FromHex } from './utils.js';
import { Adapter } from './adapter.js';

// Regex patterns for keyword extraction
const bracketPattern = /[\[\(]([^\]\)]+)[\]\)]/g;
const splitPattern = /[._\-\s]+/;

// Generate SVG fallback thumbnail for non-media or missing files
function makeFallbackSvg(ext) {
    const label = (ext || "FILE").toUpperCase().slice(0, 5);
    return `data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='%23333'><rect width='24' height='24' rx='2'/><text x='50%' y='60%' font-family='sans-serif' font-size='5' font-weight='bold' fill='%23aaa' text-anchor='middle'>${label}</text></svg>`;
}

// Convert ArrayBuffer slice to Base64 string
function arrayBufferToBase64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i += 32768) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + 32768, len)));
    }
    return btoa(binary);
}

// Convert Blob to Base64 string
async function blobToBase64(blob) {
    if (!blob) return "";
    const buf = await blob.arrayBuffer();
    return arrayBufferToBase64(buf);
}

// Drive service state management for desktop
export class DriveService {
    // Initialize drive service properties
    constructor() {
        this.serverUrl = "";
        this.usrHsh = null;
        this.usrKey = null;

        this.fldMap = {};
        this.currentFolderName = "";
        this.currentFolderKey = null;
        this.currentFolderId = "";
        this.flsMap = {};

        this.sortMode = localStorage.getItem("mediahub_sort") || "name-asc";
        this.fileSizeCache = {};
        this.allFoldersFilesCache = null;
        this.allFoldersFilesCacheTime = 0;

        this.keywordsBuilt = false;
        this.availKeywords = [];
        this.keywordCounts = {};
        this.selectKeywords = new Set();
        this.tokenCache = new Map();

        this.isUploadCancelled = false;
        this.activeUploadFileIdx = -1;
        this.isUploading = false;
    }

    // Return unmasked or cloned raw key buffer
    MaskKey(rawKey) {
        if (!rawKey) return null;
        return (rawKey instanceof Uint8Array) ? new Uint8Array(rawKey) : rawKey;
    }

    // Return unmasked key buffer
    UnmaskKey(maskedKey) {
        if (!maskedKey) return null;
        return (maskedKey instanceof Uint8Array) ? new Uint8Array(maskedKey) : maskedKey;
    }

    // Decode file size from entry key byte slice
    GetEntrySize(flKey, isRaw = false) {
        if (!flKey || flKey.length < 52) return 0;
        try {
            const view = new DataView(flKey.buffer, flKey.byteOffset, flKey.byteLength);
            return Number(view.getBigUint64(44, true));
        } catch {
            return 0;
        }
    }

    // Decode file PID hex from entry key byte slice
    GetEntryPid(flKey, isRaw = false) {
        if (!flKey || flKey.length < 44) return "";
        try {
            return ToHex(flKey.slice(32, 44));
        } catch {
            return "";
        }
    }

    // Initialize session state from desktop vault
    async InitSession() {
        await SafeSession.Init();
        this.usrHsh = SafeSession.GetItem("userHash");
        const rawUkHex = SafeSession.GetItem("userKey");
        const username = SafeSession.GetItem("username") || "";

        // Restore authentication state in backend
        if (rawUkHex) {
            this.usrKey = FromHex(rawUkHex);
            if (this.usrHsh && window.go?.main?.App?.RestoreAuth) {
                await window.go.main.App.RestoreAuth(this.usrHsh, rawUkHex, username);
            }
        } else {
            this.usrKey = null;
        }
        return Boolean(this.usrHsh && this.usrKey);
    }

    // Clear active session and reset local state
    ClearSession() {
        this.usrKey = null;
        this.usrHsh = null;
        this.fldMap = {};
        this.flsMap = {};
        this.currentFolderName = "";
        this.currentFolderKey = null;
        this.currentFolderId = "";
        this.fileSizeCache = {};
        this.allFoldersFilesCache = null;

        // Clear session storage and notify backend
        SafeSession.Clear();
        if (window.go?.main?.App?.Logout) {
            window.go.main.App.Logout();
        }
    }

    // Fetch and populate folder list from backend
    async LoadUser() {
        if (window.go?.main?.App?.GetFolders) {
            try {
                // Fetch decrypted folders from backend
                const folders = await window.go.main.App.GetFolders();
                this.fldMap = {};
                for (const [name, meta] of Object.entries(folders || {})) {
                    this.fldMap[name] = FromHex(meta.folderKey);
                }
                return true;
            } catch (err) {
                console.warn("Failed to load folders:", err);
                return false;
            }
        }
        return false;
    }

    // Persist folder map to server
    async SaveUser() {
        return true;
    }

    // Change account password and clear active session
    async ChangePassword(newPw) {
        if (!newPw) throw new Error("Enter new password");
        if (window.go?.main?.App?.ChangePassword) {
            await window.go.main.App.ChangePassword(newPw);
            SafeSession.Clear();
            this.ClearSession();
            return;
        }
        throw new Error("Wails backend is not available");
    }

    // Delete current user account from server
    async DeleteAccount() {
        if (window.go?.main?.App?.DeleteAccount) {
            await window.go.main.App.DeleteAccount();
            this.ClearSession();
            return;
        }
        throw new Error("Wails backend is not available");
    }

    // Create a new folder entry
    async CreateFolder(name) {
        const trimmed = (name || "").trim();
        if (!trimmed) throw new Error("Folder name cannot be empty");
        if (this.fldMap[trimmed]) throw new Error("Folder name already exists!");

        // Dispatch folder creation to backend
        if (window.go?.main?.App?.CreateFolder) {
            await window.go.main.App.CreateFolder(trimmed);
            await this.LoadUser();
            this.InvalidateCache();
            return trimmed;
        }
        throw new Error("Wails backend is not available");
    }

    // Rename an existing folder entry
    async RenameFolder(rawOldName, rawNewName) {
        const oldName = (rawOldName || "").trim();
        const newName = (rawNewName || "").trim();
        if (!oldName || !newName) throw new Error("Folder name cannot be empty.");
        if (oldName === newName) return;

        // Dispatch folder rename to backend
        if (window.go?.main?.App?.RenameFolder) {
            await window.go.main.App.RenameFolder(oldName, newName);
            if (this.currentFolderName === oldName) {
                this.currentFolderName = newName;
                SafeSession.SetItem("oldFold", newName);
            }
            await this.LoadUser();
            this.InvalidateCache();
            return;
        }
        throw new Error("Wails backend is not available");
    }

    // Unlink folder from active view
    async UnlinkFolder(rawFolderName) {
        return this.DeleteFolder(rawFolderName);
    }

    // Delete folder from server and local map
    async DeleteFolder(rawFolderName) {
        const target = (rawFolderName || this.currentFolderName || "").trim();
        if (!target) return;

        // Dispatch folder deletion to backend
        if (window.go?.main?.App?.DeleteFolder) {
            await window.go.main.App.DeleteFolder(target);
            delete this.fldMap[target];
            if (this.currentFolderName === target) {
                this.currentFolderName = "";
                this.currentFolderId = "";
                this.currentFolderKey = null;
                this.flsMap = {};
                SafeSession.RemoveItem("oldFold");
            }
            await this.LoadUser();
            this.InvalidateCache();
        }
    }

    // Trim orphan files from target folder
    async TrimFolder(rawFolderName) {
        const target = (rawFolderName || this.currentFolderName || "").trim();
        if (!target) throw new Error("No folder specified");

        // Collect existing file PIDs
        const pids = [];
        for (const [, flInfo] of Object.entries(this.flsMap)) {
            pids.push(this.GetEntryPid(flInfo));
        }

        // Send trim command to backend
        if (window.go?.main?.App?.TrimFolder) {
            const res = await window.go.main.App.TrimFolder(target, pids);
            await this.LoadFolderFiles();
            this.InvalidateCache();
            return { text: res, pidsCount: pids.length };
        }
        return { text: "OK", pidsCount: pids.length };
    }

    // Export encrypted folder share token
    async ExportShareToken(folderName, password) {
        return Adapter.ExportShareToken(folderName, null, password);
    }

    // Import encrypted folder share token
    async ImportShareToken(tokenText, password) {
        const res = await Adapter.ImportShareToken(tokenText, password);
        if (res) {
            await this.LoadUser();
            this.InvalidateCache();
        }
        return res;
    }

    // Select active folder and load its contents
    async SelectFolder(folderName) {
        if (!folderName) {
            this.currentFolderName = "";
            this.currentFolderId = "";
            this.currentFolderKey = null;
            this.flsMap = {};
            SafeSession.RemoveItem("oldFold");
            return false;
        }

        // Match normalized folder key
        let actualKey = folderName;
        if (!this.fldMap[actualKey]) {
            const found = Object.keys(this.fldMap).find(k => k.normalize('NFC') === folderName.normalize('NFC'));
            if (found) actualKey = found;
            else return false;
        }

        // Set active folder properties
        this.currentFolderName = actualKey;
        this.currentFolderKey = this.fldMap[actualKey];
        if (this.currentFolderKey && this.currentFolderKey.length >= 44) {
            this.currentFolderId = ToHex(this.currentFolderKey.slice(32, 44));
        }

        SafeSession.SetItem("oldFold", actualKey);
        await this.LoadFolderFiles();
        return true;
    }

    // Fetch and populate file map for selected folder
    async LoadFolderFiles() {
        if (!this.currentFolderName) {
            this.flsMap = {};
            return;
        }
        this.keywordsBuilt = false;
        this.selectKeywords.clear();

        // Fetch decrypted files from backend
        if (window.go?.main?.App?.GetFiles) {
            try {
                const res = await window.go.main.App.GetFiles(this.currentFolderName);
                if (res) {
                    this.currentFolderId = res.folderId;
                    this.currentFolderKey = FromHex(res.folderKey);
                    this.flsMap = {};
                    for (const [name, entry] of Object.entries(res.files || {})) {
                        this.flsMap[name] = FromHex(entry.rawInfo);
                    }
                }
            } catch (err) {
                console.warn("Could not load folder files:", err);
                this.flsMap = {};
            }
        }
        this.BuildKeywords();
    }

    // Upload files using webview thumbnail and chunked streaming to backend temp file
    async UploadFiles(files, callbacks = {}) {
        if (!this.currentFolderName) {
            throw new Error("No folder selected for upload");
        }

        const {
            onStart,
            onFileProgress,
            onFileComplete,
            onSyncing,
            onComplete,
            onCancel
        } = callbacks;

        this.isUploadCancelled = false;
        this.isUploading = true;

        // Subscribe to backend remote chunk transfer progress (50% ~ 95%)
        const unoff = window.runtime?.EventsOn?.("file_progress", (data) => {
            if (onFileProgress && typeof data?.fileIdx === 'number') {
                onFileProgress(data.fileIdx, data.percent, files.length);
            }
        });

        try {
            // Case 1: Browser File objects provided from file input or drag-and-drop
            if (files && files.length > 0) {
                if (onStart) onStart(files);
                const chunkSize = 4 * 1024 * 1024; // 4MB slice chunk

                for (let i = 0; i < files.length; i++) {
                    if (this.isUploadCancelled) {
                        if (onCancel) onCancel(i);
                        break;
                    }
                    this.activeUploadFileIdx = i;
                    const file = files[i];

                    if (onFileProgress) onFileProgress(i, 0, files.length);

                    // Generate thumbnail in webview if image or video
                    let thumbBase64 = "";
                    const lowerName = file.name.toLowerCase();
                    const isImage = (file.type && file.type.startsWith("image/")) || /\.(jpe?g|png|gif|webp|bmp|ico|svg|avif)$/i.test(lowerName);
                    const isVideo = (file.type && file.type.startsWith("video/")) || /\.(mp4|webm|mov|mkv|avi|ts|m4v)$/i.test(lowerName);

                    if (isImage) {
                        const thumbBlob = await Adapter.MakeImageThumb(file);
                        thumbBase64 = await blobToBase64(thumbBlob);
                    } else if (isVideo) {
                        const thumbBlob = await Adapter.MakeVideoThumb(file);
                        thumbBase64 = await blobToBase64(thumbBlob);
                    }

                    // Begin upload session in Go backend with file index
                    const uploadId = await window.go.main.App.BeginFileUpload(
                        this.currentFolderName,
                        file.name,
                        file.size,
                        i,
                        thumbBase64
                    );

                    let offset = 0;
                    try {
                        // Stream 4MB chunks to Go backend's temp file (0% ~ 50%)
                        while (offset < file.size) {
                            if (this.isUploadCancelled) {
                                await window.go.main.App.CancelFileUpload(uploadId);
                                throw new Error("UPLOAD_CANCELLED");
                            }

                            const end = Math.min(offset + chunkSize, file.size);
                            const slice = file.slice(offset, end);
                            const buf = await slice.arrayBuffer();
                            const b64 = arrayBufferToBase64(buf);

                            await window.go.main.App.AppendFileUploadChunk(uploadId, b64);
                            offset = end;

                            if (onFileProgress) {
                                const percent = Math.min(50, Math.round((offset / (file.size || 1)) * 50));
                                onFileProgress(i, percent, files.length);
                            }
                        }

                        // Finalize backend encryption and remote chunked upload (50% ~ 95%)
                        await window.go.main.App.FinishFileUpload(uploadId);

                        // Mark this file complete (100%)
                        if (onFileProgress) onFileProgress(i, 100, files.length);
                        if (onFileComplete) onFileComplete(i, file.name);

                    } catch (err) {
                        await window.go?.main?.App?.CancelFileUpload(uploadId);
                        throw err;
                    }
                }

                // Sync folder state after uploads
                if (!this.isUploadCancelled) {
                    if (onSyncing) onSyncing();
                    await this.LoadFolderFiles();
                    this.InvalidateCache();
                    if (onComplete) onComplete(files.length);
                }
                return;
            }

            // Case 2: No files provided, trigger native desktop dialog
            if (window.go?.main?.App?.SelectAndUploadFiles) {
                const count = await window.go.main.App.SelectAndUploadFiles(this.currentFolderName);
                if (count > 0) {
                    if (onSyncing) onSyncing();
                    await this.LoadFolderFiles();
                    this.InvalidateCache();
                }
                if (onComplete) onComplete(count);
                return;
            }
            throw new Error("Wails backend upload is not available");

        } catch (err) {
            if (err.message === "UPLOAD_CANCELLED") {
                if (onCancel) onCancel(this.activeUploadFileIdx);
            } else {
                throw err;
            }
        } finally {
            this.isUploading = false;
            this.isUploadCancelled = false;
            this.activeUploadFileIdx = -1;
            if (typeof unoff === 'function') unoff();
        }
    }

    // Cancel current active upload operation
    CancelUpload(fileIdx) {
        this.isUploadCancelled = true;
        if (window.go?.main?.App?.CancelUpload) {
            window.go.main.App.CancelUpload();
        }
    }

    // Rename file in active folder
    async RenameFile(rawOldName, rawNewName) {
        const oldName = (rawOldName || "").trim();
        const newName = (rawNewName || "").trim();
        if (!oldName || !newName) throw new Error("File name cannot be empty.");
        if (oldName === newName) return;

        // Dispatch rename to backend
        if (window.go?.main?.App?.RenameFile) {
            await window.go.main.App.RenameFile(this.currentFolderName, oldName, newName);
            await this.LoadFolderFiles();
            this.InvalidateCache();
            return;
        }
        throw new Error("Wails backend is not available");
    }

    // Delete file from active folder
    async DeleteFile(fileName) {
        const target = (fileName || "").trim();
        if (!target) return;

        // Dispatch deletion to backend
        if (window.go?.main?.App?.DeleteFile) {
            await window.go.main.App.DeleteFile(this.currentFolderName, target);
            delete this.flsMap[target];
            await this.LoadFolderFiles();
            this.InvalidateCache();
        }
    }

    // Invalidate cached file sizes and aggregated lists
    InvalidateCache() {
        this.fileSizeCache = {};
        this.allFoldersFilesCache = null;
        this.allFoldersFilesCacheTime = 0;
    }

    // Render thumbnail or fallback SVG into target image element
    async LoadThumbnail(folderId, filePid, ext, imgEl, maskedFileKey) {
        const fallbackSvg = makeFallbackSvg(ext);
        const lowerExt = (ext || "").toLowerCase();
        const isMedia = /^(jpe?g|png|gif|webp|bmp|ico|svg|avif|mp4|webm|mov|mkv|avi|ts|m4v)$/i.test(lowerExt);

        // Render immediate fallback SVG for non-media or empty identifiers
        if (!isMedia || !folderId || !filePid) {
            imgEl.src = fallbackSvg;
            return;
        }

        // Attach error listener to replace with fallback SVG if remote load fails
        imgEl.onerror = () => {
            imgEl.onerror = null;
            imgEl.src = fallbackSvg;
        };

        try {
            // Attempt loading thumbnail via local proxy
            const url = await Adapter.LoadThumbnailUrl(folderId, filePid, maskedFileKey);
            if (url) {
                imgEl.src = url;
                return;
            }
        } catch { }

        imgEl.src = fallbackSvg;
    }

    // Extract search keywords from file name
    ExtractTokens(nameOnly) {
        const tokens = [];
        const lower = (nameOnly || "").normalize('NFC').toLowerCase();
        const remaining = lower.replace(bracketPattern, (_, group) => {
            const trimmed = group.trim();
            if (trimmed) tokens.push(trimmed);
            return " ";
        });
        const parts = remaining.split(splitPattern);
        for (const p of parts) {
            const trimmed = p.trim();
            if (trimmed) tokens.push(trimmed);
        }
        return tokens;
    }

    // Check if token qualifies as search keyword
    IsValidKeyword(token) {
        let byteLen = 0;
        for (let i = 0; i < token.length; i++) {
            const code = token.charCodeAt(i);
            if (code <= 0x7F) byteLen += 1;
            else if (code <= 0x7FF) byteLen += 2;
            else byteLen += 3;
        }
        if (byteLen < 4) return false;
        for (let i = 0; i < token.length; i++) {
            const c = token.charAt(i);
            if (c < '0' || c > '9') return true;
        }
        return false;
    }

    // Build keyword index for tag filtering
    BuildKeywords() {
        this.availKeywords.length = 0;
        Object.keys(this.keywordCounts).forEach(k => delete this.keywordCounts[k]);
        this.tokenCache.clear();
        const wordCount = {};

        // Aggregate unique tokens per file
        const allFiles = Object.keys(this.flsMap);
        for (const fileName of allFiles) {
            let nameOnly = fileName;
            const dotIdx = fileName.lastIndexOf('.');
            if (dotIdx > 0) nameOnly = fileName.substring(0, dotIdx);

            const tokens = this.ExtractTokens(nameOnly);
            const unique = new Set(tokens);
            this.tokenCache.set(fileName, unique);

            for (const t of unique) {
                if (this.IsValidKeyword(t)) {
                    wordCount[t] = (wordCount[t] || 0) + 1;
                }
            }
        }

        // Keep keywords with 4+ occurrences
        for (const [kw, count] of Object.entries(wordCount)) {
            if (count >= 4) {
                this.availKeywords.push(kw);
                this.keywordCounts[kw] = count;
            }
        }
        this.availKeywords.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

        // Prune stale selected keywords
        const availSet = new Set(this.availKeywords);
        for (const kw of Array.from(this.selectKeywords)) {
            if (!availSet.has(kw)) this.selectKeywords.delete(kw);
        }
        this.keywordsBuilt = true;
    }

    // Fetch and cache file sizes for specific folder
    async FetchFolderFileSizes(folderName) {
        if (!folderName) return {};
        if (this.fileSizeCache[folderName]) return this.fileSizeCache[folderName];

        if (window.go?.main?.App?.GetFiles) {
            try {
                const res = await window.go.main.App.GetFiles(folderName);
                const sizes = {};
                for (const [name, entry] of Object.entries(res?.files || {})) {
                    sizes[name] = entry.size || 0;
                }
                this.fileSizeCache[folderName] = sizes;
                return sizes;
            } catch {
                return {};
            }
        }
        return {};
    }

    // Fetch all files across all folders with caching
    async FetchAllFiles(forceRefresh = false) {
        const now = Date.now();
        if (!forceRefresh && this.allFoldersFilesCache && (now - this.allFoldersFilesCacheTime < 30000)) {
            return this.allFoldersFilesCache;
        }

        if (window.go?.main?.App?.GetFiles) {
            try {
                const folderEntries = Object.entries(this.fldMap);
                const allFiles = [];

                // Fetch files for every folder concurrently
                await Promise.all(folderEntries.map(async ([fName, fldKey]) => {
                    try {
                        const res = await window.go.main.App.GetFiles(fName);
                        for (const [flName, entry] of Object.entries(res?.files || {})) {
                            allFiles.push({
                                folderName: fName,
                                folderKey: fldKey,
                                folderId: res.folderId,
                                fileName: flName,
                                fileKey: FromHex(entry.fileKey),
                                size: entry.size || 0
                            });
                        }
                    } catch (err) {
                        console.warn(`Error fetching files for folder ${fName}:`, err);
                    }
                }));

                this.allFoldersFilesCache = allFiles;
                this.allFoldersFilesCacheTime = Date.now();
                return allFiles;
            } catch (err) {
                console.warn("Could not fetch all files:", err);
                return [];
            }
        }
        return [];
    }

    // Prepare files array from input
    PrepareFiles(fileList) {
        return Array.from(fileList || []);
    }
}

// Global drive service instance
export const Drive = new DriveService();
