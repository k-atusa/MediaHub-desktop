// Drive domain service for state management, folder catalog, and upload pipeline
import { Masker, Random, SymMaster } from '../engine/Bencrypt.js';
import { DecodeInt, EncodeInt, PadLen } from '../engine/Opsec.js';
import { SafeSession, ToHex, FromHex, GetObjPid, FormatBytes } from './utils.js';
import { Adapter } from './adapter.js';

const mask = new Masker();
const bracketPattern = /[\[\(]([^\]\)]+)[\]\)]/g;
const splitPattern = /[._\-\s]+/;

// File chunk stream reader for client-side encryption
class FileSrc {
    constructor(file) {
        this.file = file;
        this.off = 0;
    }

    // Read byte chunk slice from File object
    async read(size) {
        if (this.off >= this.file.size) return new Uint8Array(0);
        const chunk = this.file.slice(this.off, this.off + size);
        const buf = await chunk.arrayBuffer();
        this.off += buf.byteLength;
        return new Uint8Array(buf);
    }
}

// Drive state and file management service
export class DriveService {
    // Initialize state containers, search filters, and upload flags
    constructor() {
        this.serverUrl = window.location.origin;
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
        this.currentUploadXhr = null;
        this.activeUploadFileIdx = -1;
        this.isUploading = false;
    }

    // Mask raw key buffer with XOR mask
    MaskKey(rawKey) {
        if (!rawKey) return null;
        return mask.XOR(rawKey);
    }

    // Unmask XOR-masked key into raw key buffer
    UnmaskKey(maskedKey) {
        if (!maskedKey) return null;
        return mask.XOR(maskedKey);
    }

    // Initialize authenticated user session from SafeSession
    async InitSession() {
        await SafeSession.Init();
        this.usrHsh = SafeSession.GetItem("userHash");
        const rawUkHex = SafeSession.GetItem("userKey");
        if (rawUkHex) {
            const raw = FromHex(rawUkHex);
            this.usrKey = mask.XOR(raw);
            raw.fill(0);
        } else {
            this.usrKey = null;
        }
        return Boolean(this.usrHsh && this.usrKey);
    }

    // Reset all session state in memory and storage
    ClearSession() {
        if (this.usrKey) {
            const raw = mask.XOR(this.usrKey);
            raw.fill(0);
            this.usrKey = null;
        }
        this.usrHsh = null;
        this.fldMap = {};
        this.flsMap = {};
        this.currentFolderName = "";
        this.currentFolderKey = null;
        this.currentFolderId = "";
        this.fileSizeCache = {};
        this.allFoldersFilesCache = null;
        SafeSession.Clear();
    }

    // Fetch and decrypt user folder map from backend
    async LoadUser() {
        if (!this.usrHsh || !this.usrKey) return false;
        const map = await Adapter.LoadUserData(this.usrHsh, this.usrKey);
        this.fldMap = {};
        for (const [k, v] of Object.entries(map)) {
            this.fldMap[k] = mask.XOR(v);
            v.fill(0);
        }
        return true;
    }

    // Encrypt and save user folder map to backend
    async SaveUser() {
        if (!this.usrHsh || !this.usrKey) return false;
        const rawMap = {};
        for (const [k, v] of Object.entries(this.fldMap)) {
            rawMap[k] = mask.XOR(v);
        }
        try {
            await Adapter.SaveUserData(this.usrHsh, rawMap, this.usrKey);
            return true;
        } finally {
            for (const v of Object.values(rawMap)) if (v?.fill) v.fill(0);
        }
    }

    // Create a new empty folder entry
    async CreateFolder(name) {
        const trimmed = (name || "").trim();
        if (!trimmed || this.fldMap[trimmed]) {
            throw new Error("Invalid or duplicate folder name");
        }

        const rk = new Uint8Array(44);
        rk.set(Random(32), 0);
        rk.set(Random(12), 32);
        const maskedKey = mask.XOR(rk);
        rk.fill(0);

        this.fldMap[trimmed] = maskedKey;
        await this.SaveUser();
        this.InvalidateCache();
        return trimmed;
    }

    // Rename folder in catalog and persist changes
    async RenameFolder(rawOldName, rawNewName) {
        const oldName = (rawOldName || "").trim();
        const newName = (rawNewName || "").trim();
        if (!oldName || !newName) throw new Error("Folder name cannot be empty.");
        if (oldName.normalize('NFC') === newName.normalize('NFC')) return;

        let actualOldKey = oldName;
        if (!this.fldMap[actualOldKey]) {
            const found = Object.keys(this.fldMap).find(k => k.normalize('NFC') === oldName.normalize('NFC'));
            if (found) actualOldKey = found;
            else throw new Error(`Original folder "${oldName}" not found.`);
        }

        const duplicate = Object.keys(this.fldMap).find(k => k.normalize('NFC') === newName.normalize('NFC') && k !== actualOldKey);
        if (duplicate) throw new Error(`A folder named "${newName}" already exists.`);

        const origFldMap = { ...this.fldMap };
        const origCurrentName = this.currentFolderName;

        try {
            const maskedKey = this.fldMap[actualOldKey];
            this.fldMap[newName] = maskedKey;
            delete this.fldMap[actualOldKey];

            if (this.currentFolderName === actualOldKey || (this.currentFolderName && this.currentFolderName.normalize('NFC') === actualOldKey.normalize('NFC'))) {
                this.currentFolderName = newName;
                SafeSession.SetItem("oldFold", newName);
            }

            await this.SaveUser();
            this.InvalidateCache();
        } catch (err) {
            this.fldMap = origFldMap;
            this.currentFolderName = origCurrentName;
            throw err;
        }
    }

    // Unlink folder from user catalog without deleting remote files
    async UnlinkFolder(rawFolderName) {
        const target = (rawFolderName || this.currentFolderName || "").trim();
        if (!target) return;

        let actualKey = target;
        if (!this.fldMap[actualKey]) {
            const found = Object.keys(this.fldMap).find(k => k.normalize('NFC') === target.normalize('NFC'));
            if (found) actualKey = found;
            else return;
        }

        delete this.fldMap[actualKey];
        if (this.currentFolderName === actualKey || (this.currentFolderName && this.currentFolderName.normalize('NFC') === actualKey.normalize('NFC'))) {
            this.currentFolderName = "";
            this.currentFolderId = "";
            this.currentFolderKey = null;
            this.flsMap = {};
            SafeSession.RemoveItem("oldFold");
        }

        await this.SaveUser();
        this.InvalidateCache();
    }

    // Delete folder catalog entry and all files on server
    async DeleteFolder(rawFolderName) {
        const target = (rawFolderName || this.currentFolderName || "").trim();
        if (!target) return;

        let actualKey = target;
        if (!this.fldMap[actualKey]) {
            const found = Object.keys(this.fldMap).find(k => k.normalize('NFC') === target.normalize('NFC'));
            if (found) actualKey = found;
            else return;
        }

        const maskedKey = this.fldMap[actualKey];
        const rawK = mask.XOR(maskedKey);
        const fldId = GetObjPid(rawK);
        rawK.fill(0);

        await Adapter.DeleteFolderMeta(fldId, this.usrHsh);

        delete this.fldMap[actualKey];
        if (this.currentFolderName === actualKey || (this.currentFolderName && this.currentFolderName.normalize('NFC') === actualKey.normalize('NFC'))) {
            this.currentFolderName = "";
            this.currentFolderId = "";
            this.currentFolderKey = null;
            this.flsMap = {};
            SafeSession.RemoveItem("oldFold");
        }

        await this.SaveUser();
        this.InvalidateCache();
    }

    // Remove unmapped orphan files from folder storage
    async TrimFolder(rawFolderName) {
        const target = (rawFolderName || this.currentFolderName || "").trim();
        if (!target) throw new Error("No folder specified");

        let actualKey = target;
        if (!this.fldMap[actualKey]) {
            const found = Object.keys(this.fldMap).find(k => k.normalize('NFC') === target.normalize('NFC'));
            if (found) actualKey = found;
            else throw new Error(`Folder "${target}" not found`);
        }

        const maskedKey = this.fldMap[actualKey];
        const rawK = mask.XOR(maskedKey);
        const fldId = GetObjPid(rawK);
        rawK.fill(0);

        const pids = [];
        if (this.currentFolderName === actualKey && this.currentFolderId === fldId && Object.keys(this.flsMap).length > 0) {
            for (const [, fileKey] of Object.entries(this.flsMap)) {
                const rawFk = mask.XOR(fileKey);
                pids.push(GetObjPid(rawFk.slice(0, 44)));
                rawFk.fill(0);
            }
        } else {
            const map = await Adapter.LoadFolderMeta(fldId, maskedKey);
            for (const [, fileKey] of Object.entries(map)) {
                pids.push(GetObjPid(fileKey.slice(0, 44)));
            }
        }

        const text = await Adapter.TrimFolder(fldId, { pids }, this.usrHsh);
        if (this.currentFolderName === actualKey) {
            await this.LoadFolderFiles();
        }
        this.InvalidateCache();
        return { text, pidsCount: pids.length };
    }

    // Select active folder and load its file catalog
    async SelectFolder(folderName) {
        if (!folderName) {
            this.currentFolderName = "";
            this.currentFolderId = "";
            this.currentFolderKey = null;
            this.flsMap = {};
            SafeSession.RemoveItem("oldFold");
            return false;
        }

        let actualKey = folderName;
        if (!this.fldMap[actualKey]) {
            const found = Object.keys(this.fldMap).find(k => k.normalize('NFC') === folderName.normalize('NFC'));
            if (found) actualKey = found;
            else return false;
        }

        this.currentFolderName = actualKey;
        this.currentFolderKey = this.fldMap[actualKey];
        const rawK = mask.XOR(this.currentFolderKey);
        this.currentFolderId = GetObjPid(rawK);
        rawK.fill(0);

        SafeSession.SetItem("oldFold", actualKey);
        await this.LoadFolderFiles();
        return true;
    }

    // Load and decrypt file catalog for selected folder
    async LoadFolderFiles() {
        if (!this.currentFolderId || !this.currentFolderKey) {
            this.flsMap = {};
            return;
        }
        this.keywordsBuilt = false;
        this.selectKeywords.clear();

        const map = await Adapter.LoadFolderMeta(this.currentFolderId, this.currentFolderKey);
        this.flsMap = {};
        for (const [k, v] of Object.entries(map)) {
            this.flsMap[k] = mask.XOR(v);
            v.fill(0);
        }
        this.BuildKeywords();
    }

    // Rename file in active folder and sync metadata
    async RenameFile(rawOldName, rawNewName) {
        const oldName = (rawOldName || "").trim();
        const newName = (rawNewName || "").trim();
        if (!oldName || !newName) throw new Error("File name cannot be empty.");
        if (oldName.normalize('NFC') === newName.normalize('NFC')) return;

        let actualOldName = oldName;
        if (!this.flsMap[actualOldName]) {
            const found = Object.keys(this.flsMap).find(k => k.normalize('NFC') === oldName.normalize('NFC'));
            if (found) actualOldName = found;
            else throw new Error(`Original file "${oldName}" not found.`);
        }

        const duplicate = Object.keys(this.flsMap).find(k => k.normalize('NFC') === newName.normalize('NFC') && k !== actualOldName);
        if (duplicate) throw new Error(`A file named "${newName}" already exists in this folder.`);

        const origFlsMap = { ...this.flsMap };
        try {
            this.flsMap[newName] = this.flsMap[actualOldName];
            delete this.flsMap[actualOldName];

            const rawMap = {};
            for (const [k, v] of Object.entries(this.flsMap)) {
                rawMap[k] = mask.XOR(v);
            }
            await Adapter.SaveFolderMeta(this.currentFolderId, rawMap, this.currentFolderKey, this.usrHsh);
            for (const v of Object.values(rawMap)) if (v?.fill) v.fill(0);

            this.keywordsBuilt = false;
            this.BuildKeywords();
            this.InvalidateCache();
        } catch (err) {
            this.flsMap = origFlsMap;
            throw err;
        }
    }

    // Delete file and associated binaries from server
    async DeleteFile(fileName) {
        const target = (fileName || "").trim();
        if (!target || !this.flsMap[target]) return;

        const rawFk = mask.XOR(this.flsMap[target]);
        const flPid = GetObjPid(rawFk.slice(0, 44));
        rawFk.fill(0);

        try {
            await Adapter.DeleteMedia(this.currentFolderId, flPid, this.usrHsh);
        } catch (err) {
            console.warn("Error deleting media binaries:", err);
        }

        delete this.flsMap[target];

        const rawMap = {};
        for (const [k, v] of Object.entries(this.flsMap)) {
            rawMap[k] = mask.XOR(v);
        }
        await Adapter.SaveFolderMeta(this.currentFolderId, rawMap, this.currentFolderKey, this.usrHsh);
        for (const v of Object.values(rawMap)) if (v?.fill) v.fill(0);

        this.keywordsBuilt = false;
        this.BuildKeywords();
        this.InvalidateCache();
    }

    // Fetch and render thumbnail for file item
    async LoadThumbnail(folderId, filePid, ext, imgEl, fileKeyRaw) {
        try {
            const maskedFk = mask.XOR(fileKeyRaw);
            const thumbUrl = await Adapter.LoadThumbnailUrl(folderId, filePid, maskedFk);
            fileKeyRaw.fill(0);
            if (thumbUrl) {
                imgEl.src = thumbUrl;
            } else {
                imgEl.src = `data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='%23333'><rect width='24' height='24' rx='2'/><text x='50%' y='60%' font-family='sans-serif' font-size='5' font-weight='bold' fill='%23aaa' text-anchor='middle'>${ext}</text></svg>`;
            }
        } catch {
            fileKeyRaw.fill(0);
            imgEl.src = `data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='100' height='100' viewBox='0 0 24 24' fill='%23333'><rect width='24' height='24' rx='2'/><text x='50%' y='60%' font-family='sans-serif' font-size='5' font-weight='bold' fill='%23aaa' text-anchor='middle'>${ext}</text></svg>`;
        }
    }

    // Extract file size integer from masked key metadata
    GetEntrySize(flKeyMasked) {
        if (!flKeyMasked) return 0;
        const raw = mask.XOR(flKeyMasked);
        let sz = 0;
        if (raw.length >= 52) {
            sz = DecodeInt(raw.slice(44, 52));
        }
        raw.fill(0);
        return sz;
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

    // Check if token qualifies as a search keyword
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

        for (const [kw, count] of Object.entries(wordCount)) {
            if (count >= 4) {
                this.availKeywords.push(kw);
                this.keywordCounts[kw] = count;
            }
        }
        this.availKeywords.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

        const availSet = new Set(this.availKeywords);
        for (const kw of Array.from(this.selectKeywords)) {
            if (!availSet.has(kw)) this.selectKeywords.delete(kw);
        }
        this.keywordsBuilt = true;
    }

    // Fetch and cache file sizes for specified folder
    async FetchFolderFileSizes(folderName) {
        if (!folderName) return {};
        if (this.fileSizeCache[folderName]) return this.fileSizeCache[folderName];

        try {
            const fldKey = this.fldMap[folderName];
            if (!fldKey) return {};

            const rawK = mask.XOR(fldKey);
            const fldId = GetObjPid(rawK);
            rawK.fill(0);

            const flsMap = await Adapter.LoadFolderMeta(fldId, fldKey);
            const sizes = {};
            for (const [name, flInfo] of Object.entries(flsMap)) {
                if (flInfo && flInfo.length >= 52) {
                    sizes[name] = DecodeInt(flInfo.slice(44, 52));
                }
            }
            this.fileSizeCache[folderName] = sizes;
            return sizes;
        } catch (err) {
            console.warn("Could not load file sizes:", err);
            return {};
        }
    }

    // Fetch all files across all folders with caching
    async FetchAllFiles(forceRefresh = false) {
        const now = Date.now();
        if (!forceRefresh && this.allFoldersFilesCache && (now - this.allFoldersFilesCacheTime < 30000)) {
            return this.allFoldersFilesCache;
        }

        try {
            const folderEntries = Object.entries(this.fldMap);
            const allFiles = [];

            await Promise.all(folderEntries.map(async ([fName, fldKey]) => {
                try {
                    const rawK = mask.XOR(fldKey);
                    const fldId = GetObjPid(rawK);
                    rawK.fill(0);

                    const flsMap = await Adapter.LoadFolderMeta(fldId, fldKey);
                    for (const [flName, flKey] of Object.entries(flsMap)) {
                        let size = 0;
                        if (flKey && flKey.length >= 52) {
                            size = DecodeInt(flKey.slice(44, 52));
                        }
                        allFiles.push({
                            folderName: fName,
                            folderKey: fldKey,
                            folderId: fldId,
                            fileName: flName,
                            fileKey: flKey,
                            size: size
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
            console.warn("Could not fetch all folders files:", err);
            return [];
        }
    }

    // Reset cached file sizes and file lists
    InvalidateCache() {
        this.fileSizeCache = {};
        this.allFoldersFilesCache = null;
        this.allFoldersFilesCacheTime = 0;
    }

    // Update account password and re-encrypt user catalog
    async ChangePassword(newPw) {
        if (!newPw) throw new Error("Enter new password");
        const username = SafeSession.GetItem("username");
        if (!username) throw new Error("Session invalid. Please login again.");

        const { userHash: newHash, maskedKey: maskedNewKey } = await Adapter.DeriveKeys(username, newPw);
        if (newHash === this.usrHsh) {
            throw new Error("New password must be different");
        }

        const exists = await Adapter.CheckUserExists(newHash);
        if (exists) throw new Error("User already exists with this password");

        const rawMap = {};
        for (const [k, v] of Object.entries(this.fldMap)) {
            rawMap[k] = mask.XOR(v);
        }

        await Adapter.SaveUserData(newHash, rawMap, maskedNewKey, this.usrHsh);
        for (const v of Object.values(rawMap)) if (v?.fill) v.fill(0);

        await fetch(`${this.serverUrl}/api/userdata/${this.usrHsh}`, {
            method: "DELETE",
            headers: { "X-User-Hash": this.usrHsh }
        });

        const rawNewKey = mask.XOR(maskedNewKey);
        SafeSession.SetItem("userHash", newHash);
        SafeSession.SetItem("userKey", ToHex(rawNewKey));
        rawNewKey.fill(0);
        await SafeSession.Save();

        this.usrHsh = newHash;
        this.usrKey = maskedNewKey;
    }

    // Export password-encrypted folder share token
    async ExportShareToken(folderName, password) {
        const maskedKey = this.fldMap[folderName];
        if (!maskedKey) return null;
        return Adapter.ExportShareToken(folderName, maskedKey, password);
    }

    // Import and decrypt folder share token
    async ImportShareToken(tokenText, password) {
        return Adapter.ImportShareToken(tokenText, password);
    }

    // Cancel in-flight upload operation
    CancelUpload(fileIdx) {
        this.isUploadCancelled = true;
        if (this.currentUploadXhr) {
            try {
                this.currentUploadXhr.abort();
            } catch { }
        }
    }

    // Sanitize file list and deduplicate names
    PrepareFiles(fileList) {
        const dt = new DataTransfer();
        const ignoredNames = new Set([".DS_Store", "Thumbs.db", "desktop.ini"]);
        const seenNames = new Set();

        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            if (file.name.startsWith("._") || ignoredNames.has(file.name)) continue;

            let finalName = file.name;
            if (seenNames.has(finalName)) {
                if (file.webkitRelativePath) {
                    const parts = file.webkitRelativePath.split('/');
                    if (parts.length > 1) {
                        parts.shift();
                        finalName = parts.join('_');
                    }
                }
                let counter = 1;
                const origName = finalName;
                const lastDot = origName.lastIndexOf('.');
                const base = lastDot > 0 ? origName.slice(0, lastDot) : origName;
                const ext = lastDot > 0 ? origName.slice(lastDot) : '';
                while (seenNames.has(finalName)) {
                    finalName = `${base} (${counter})${ext}`;
                    counter++;
                }
            }
            seenNames.add(finalName);

            const uploadFile = (finalName === file.name)
                ? file
                : new File([file], finalName, { type: file.type, lastModified: file.lastModified });

            dt.items.add(uploadFile);
        }
        return Array.from(dt.files);
    }

    // Encrypt and upload files to server storage with progress callbacks
    async UploadFiles(files, callbacks = {}) {
        if (!files || files.length === 0) return;
        if (!this.currentFolderId || !this.currentFolderKey) {
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
        this.activeUploadFileIdx = -1;

        if (onStart) onStart(files);

        const folderId = this.currentFolderId;
        const userHash = this.usrHsh;
        let uploadedCount = 0;

        try {
            for (let i = 0; i < files.length; i++) {
                if (this.isUploadCancelled) break;
                this.activeUploadFileIdx = i;
                const file = files[i];

                if (onFileProgress) onFileProgress(i, 0, files.length);

                if (this.flsMap[file.name]) {
                    const oldRaw = mask.XOR(this.flsMap[file.name]);
                    const oldFlPid = GetObjPid(oldRaw.slice(0, 44));
                    oldRaw.fill(0);
                    try {
                        await Adapter.DeleteMedia(folderId, oldFlPid, userHash);
                    } catch (err) {
                        console.warn("Failed to delete existing file binary", err);
                    }
                }

                const fileKey = new Uint8Array(44);
                fileKey.set(Random(32), 0);
                fileKey.set(Random(12), 32);
                const filePid = GetObjPid(fileKey);

                let thumb = null;
                if (file.type.startsWith("image/") || file.name.toLowerCase().endsWith(".svg")) {
                    thumb = await Adapter.MakeImageThumb(file);
                } else if (file.type.startsWith("video/")) {
                    thumb = await Adapter.MakeVideoThumb(file);
                }

                if (this.isUploadCancelled) throw new Error("UPLOAD_CANCELLED");

                let encryptedBytes = 0;
                const smx = new SymMaster("gcmx1", fileKey.slice(0, 32));
                const encChunks = [];

                await smx.EnFile(new FileSrc(file), file.size, {
                    write: async (chunk) => {
                        if (this.isUploadCancelled) throw new Error("UPLOAD_CANCELLED");
                        encChunks.push(chunk);
                        encryptedBytes += chunk.length;
                        if (onFileProgress) {
                            const percent = Math.min(50, Math.round((encryptedBytes / (file.size || 1)) * 50));
                            onFileProgress(i, percent, files.length);
                        }
                    }
                });

                if (this.isUploadCancelled) throw new Error("UPLOAD_CANCELLED");

                const encSize = encChunks.reduce((a, c) => a + c.length, 0);
                const padSize = PadLen(encSize);
                const totSize = encSize + padSize;
                const medBuf = new Uint8Array(totSize);
                let offset = 0;
                for (const chunk of encChunks) {
                    medBuf.set(chunk, offset);
                    offset += chunk.length;
                }

                if (padSize > 0) {
                    let pOff = offset;
                    const pEnd = offset + padSize;
                    while (pOff < pEnd) {
                        const chunk = Math.min(32768, pEnd - pOff);
                        medBuf.set(Random(chunk), pOff);
                        pOff += chunk;
                    }
                }

                if (this.isUploadCancelled) throw new Error("UPLOAD_CANCELLED");

                // Upload encrypted payload in 16MB chunks with offset tracking
                const uploadChunkSize = 16 * 1024 * 1024;
                let uploadOffset = 0;

                do {
                    if (this.isUploadCancelled) throw new Error("UPLOAD_CANCELLED");

                    const nextOffset = Math.min(uploadOffset + uploadChunkSize, totSize);
                    const chunkData = medBuf.subarray(uploadOffset, nextOffset);
                    const curOffset = uploadOffset;

                    await new Promise((resolve, reject) => {
                        const xhr = new XMLHttpRequest();
                        this.currentUploadXhr = xhr;
                        xhr.open("POST", `${this.serverUrl}/api/media/${folderId}/${filePid}/dat`);
                        xhr.setRequestHeader("X-User-Hash", userHash);
                        xhr.setRequestHeader("X-Upload-Offset", curOffset.toString());
                        xhr.upload.onprogress = (e) => {
                            if (e.lengthComputable && onFileProgress) {
                                const loadedBytes = curOffset + e.loaded;
                                const uploadPercent = 50 + Math.min(45, Math.round((loadedBytes / (totSize || 1)) * 45));
                                onFileProgress(i, uploadPercent, files.length);
                            }
                        };
                        xhr.onload = () => {
                            if (xhr.status >= 200 && xhr.status < 300) resolve();
                            else reject(new Error(`Upload failed with status ${xhr.status}`));
                        };
                        xhr.onabort = () => reject(new Error("UPLOAD_CANCELLED"));
                        xhr.onerror = () => reject(new Error("Network upload failed"));
                        xhr.send(chunkData);
                    });
                    this.currentUploadXhr = null;

                    uploadOffset = nextOffset;
                } while (uploadOffset < totSize);

                if (thumb) {
                    const thmSm = new SymMaster("gcm1", fileKey.slice(0, 32));
                    await fetch(`${this.serverUrl}/api/media/${folderId}/${filePid}/thumb`, {
                        method: "POST",
                        headers: { "X-User-Hash": userHash },
                        body: await thmSm.EnBin(new Uint8Array(await thumb.arrayBuffer()))
                    });
                }

                if (onFileProgress) onFileProgress(i, 100, files.length);
                if (onFileComplete) onFileComplete(i, file.name);

                const flInfo = new Uint8Array(52);
                flInfo.set(fileKey, 0);
                flInfo.set(EncodeInt(file.size, 8), 44);
                this.flsMap[file.name] = mask.XOR(flInfo);
                fileKey.fill(0);
                flInfo.fill(0);
                uploadedCount++;
            }

            if (uploadedCount > 0 && !this.isUploadCancelled) {
                if (onSyncing) onSyncing();
                const rawMap = {};
                for (const [k, v] of Object.entries(this.flsMap)) {
                    rawMap[k] = mask.XOR(v);
                }
                await Adapter.SaveFolderMeta(folderId, rawMap, this.currentFolderKey, userHash);
                for (const v of Object.values(rawMap)) if (v?.fill) v.fill(0);

                this.keywordsBuilt = false;
                this.BuildKeywords();
                this.InvalidateCache();
            }

            if (onComplete) onComplete(uploadedCount);
        } catch (err) {
            if (err.message === "UPLOAD_CANCELLED") {
                if (onCancel) onCancel(this.activeUploadFileIdx);
            } else {
                throw err;
            }
        } finally {
            this.isUploadCancelled = false;
            this.isUploading = false;
            this.currentUploadXhr = null;
            this.activeUploadFileIdx = -1;
        }
    }
}

// Global drive service instance
export const Drive = new DriveService();
