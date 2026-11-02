// Media streaming and full download view controller
import { AppRouter } from '../core/router.js';
import { Drive } from '../core/drive.js';
import { Adapter } from '../core/adapter.js';
import { SafeSession, ShowNotice, ShowConfirmModal, FormatBytes, EscapeHtml, ToHex, FromHex, GetObjPid, GetKind, GetMime, OrderFileEntries } from '../core/utils.js';

// Media view controller
class ViewerViewService {
    // --------------------------------------------------
    // 01. Lifecycle & Initialization
    // --------------------------------------------------

    // Initialize container reference and runtime media state
    constructor() {
        this.container = document.getElementById('view-viewer');
        this.initialized = false;

        this.folderId = null;
        this.folderKey = null;
        this.fileKey = null;
        this.fileName = null;
        this.origSize = 0;
        this.currentBlobUrl = null;
        this.neighborKeys = [];
    }

    // Attach toolbar and menu action listeners
    init() {
        if (this.initialized) return;
        this.initialized = true;

        // Bind back button
        const btnBack = document.getElementById("btnViewerBack");
        if (btnBack) {
            btnBack.addEventListener("click", () => {
                this.CleanupCurrentMedia();
                AppRouter.Navigate('/drive');
            });
        }

        // Bind Escape key
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && AppRouter.currentPath === '/viewer') {
                const renameModal = document.getElementById("renameFileModal");
                if (renameModal && renameModal.open) return;
                this.CleanupCurrentMedia();
                AppRouter.Navigate('/drive');
            }
        });

        const btnShare = document.getElementById("btnViewerShare");
        const btnEdit = document.getElementById("btnViewerEdit");
        const btnDown = document.getElementById("btnViewerDown");
        const btnDelete = document.getElementById("btnViewerDelete");
        const btnViewerMore = document.getElementById("btnViewerMore");
        const viewerActionMenu = document.getElementById("viewerActionMenu");

        // Bind toolbar buttons
        if (btnShare) btnShare.addEventListener("click", () => this.shareCurrentFile());
        if (btnEdit) btnEdit.addEventListener("click", () => this.openRenameModal());
        if (btnDown) btnDown.addEventListener("click", () => this.downloadCurrentFile());
        if (btnDelete) btnDelete.addEventListener("click", () => this.deleteCurrentFile());

        // Bind toolbar dropdown menu
        if (btnViewerMore && viewerActionMenu) {
            btnViewerMore.addEventListener("click", (e) => {
                e.stopPropagation();
                const isOpen = viewerActionMenu.classList.toggle("open");
                btnViewerMore.classList.toggle("open", isOpen);
                viewerActionMenu.style.display = isOpen ? "block" : "none";
            });

            // Close dropdown when click outside
            document.addEventListener("click", (e) => {
                if (viewerActionMenu.classList.contains("open")) {
                    if (!viewerActionMenu.contains(e.target) && !btnViewerMore.contains(e.target)) {
                        viewerActionMenu.classList.remove("open");
                        btnViewerMore.classList.remove("open");
                        viewerActionMenu.style.display = "none";
                    }
                }
            });
        }

        // Bind dropdown menu items
        document.getElementById("viewerMenuShare")?.addEventListener("click", () => {
            this.closeViewerMenu();
            this.shareCurrentFile();
        });
        document.getElementById("viewerMenuRename")?.addEventListener("click", () => {
            this.closeViewerMenu();
            this.openRenameModal();
        });
        document.getElementById("viewerMenuDownload")?.addEventListener("click", () => {
            this.closeViewerMenu();
            this.downloadCurrentFile();
        });
        document.getElementById("viewerMenuDelete")?.addEventListener("click", () => {
            this.closeViewerMenu();
            this.deleteCurrentFile();
        });

        const renameFileModal = document.getElementById("renameFileModal");
        const btnConfirmRenameFile = document.getElementById("btnConfirmRenameFile");
        const btnCancelRenameFile = document.getElementById("btnCancelRenameFile");
        const modalRenameFileInput = document.getElementById("modalRenameFileInput");
        const renameFileErrorText = document.getElementById("renameFileErrorText");

        // Bind rename file modal buttons
        if (btnConfirmRenameFile) {
            btnConfirmRenameFile.addEventListener("click", async () => {
                const newName = modalRenameFileInput?.value.trim();
                if (!newName) { // no newname
                    if (renameFileErrorText) {
                        renameFileErrorText.textContent = "Please enter a file name.";
                        renameFileErrorText.style.display = "block";
                    }
                    return;
                }
                const ok = await this.performRename(newName);
                if (ok) renameFileModal?.close();
                else if (renameFileErrorText) { // rename failed
                    renameFileErrorText.textContent = "Rename failed. A file with this name might already exist.";
                    renameFileErrorText.style.display = "block";
                }
            });
        }
        if (btnCancelRenameFile) btnCancelRenameFile.addEventListener("click", () => renameFileModal?.close());
    }

    // Hide viewer action dropdown
    closeViewerMenu() {
        const viewerActionMenu = document.getElementById("viewerActionMenu");
        const btnViewerMore = document.getElementById("btnViewerMore");
        if (viewerActionMenu) {
            viewerActionMenu.classList.remove("open");
            viewerActionMenu.style.display = "none";
        }
        if (btnViewerMore) btnViewerMore.classList.remove("open");
    }

    // --------------------------------------------------
    // 02. Viewer Start & Management
    // --------------------------------------------------

    // Mount viewer and restore state from session
    async Mount() {
        this.init();
        this.CleanupCurrentMedia();

        // Get session data
        this.folderId = SafeSession.GetItem("currentFolderId");
        this.fileName = SafeSession.GetItem("currentFileName");
        const rawFolderKeyHex = SafeSession.GetItem("currentFolderKey");
        const rawFileKeyHex = SafeSession.GetItem("currentFileKey");

        // Get folder key
        if (rawFolderKeyHex) {
            this.folderKey = Drive.MaskKey(FromHex(rawFolderKeyHex));
        } else {
            this.folderKey = null;
        }

        // Get file key and original size
        if (rawFileKeyHex) {
            const rawFileKey = FromHex(rawFileKeyHex);
            this.origSize = Drive.GetEntrySize(rawFileKey, true);
            this.fileKey = Drive.MaskKey(rawFileKey);
            rawFileKey.fill(0);
        } else {
            this.fileKey = null;
            this.origSize = 0;
        }

        // Return to drive if file not found
        if (!this.fileKey || !this.fileName || !this.folderId || !this.folderKey) {
            return AppRouter.Navigate('/drive', true);
        }

        // Set filename, render media
        const txName = document.getElementById("txName");
        if (txName) {
            txName.textContent = this.fileName;
            txName.title = this.fileName;
        }
        this.applyCapabilities();
        await this.renderFilePreview();
        await this.setupNeighborNavigation();
    }

    // Mount viewer with URL deep-link query parameters
    async MountWithQuery(query = {}) {
        this.init();

        // Get query data
        const folderPid = query.f;
        const filePid = query.p;
        if (!folderPid || !filePid) {
            return this.Mount();
        }
        await Drive.LoadUser();

        // Find target folder by PID
        let targetFolderName = "";
        let targetFolderKey = null;
        for (const [name, key] of Object.entries(Drive.fldMap)) {
            const raw = Drive.UnmaskKey(key);
            if (GetObjPid(raw) === folderPid) {
                targetFolderName = name;
                targetFolderKey = key;
                raw.fill(0);
                break;
            }
            raw.fill(0);
        }
        if (!targetFolderName || !targetFolderKey) {
            await ShowNotice("Folder not found or you lack permission to access it.", "Access Denied", "error");
            return AppRouter.Navigate('/drive', true);
        }

        // Load target folder, find file by PID
        await Drive.SelectFolder(targetFolderName);
        const filesMap = await Adapter.LoadFolderMeta(folderPid, targetFolderKey);
        let foundFileName = "";
        let foundFileKey = null;

        for (const [name, key] of Object.entries(filesMap)) {
            if (GetObjPid(key.slice(0, 44)) === filePid) {
                foundFileName = name;
                foundFileKey = key;
                break;
            }
        }
        if (!foundFileName || !foundFileKey) {
            await ShowNotice("The requested file was not found in this folder.", "File Not Found", "error");
            return AppRouter.Navigate('/drive', true);
        }

        // Save to session, start mount
        const rawFolderKey = Drive.UnmaskKey(targetFolderKey);
        SafeSession.SetItem("currentFolderName", targetFolderName);
        SafeSession.SetItem("currentFolderId", folderPid);
        SafeSession.SetItem("currentFolderKey", ToHex(rawFolderKey));
        SafeSession.SetItem("currentFileName", foundFileName);
        SafeSession.SetItem("currentFileKey", ToHex(foundFileKey));
        SafeSession.SetItem("oldFold", targetFolderName);
        rawFolderKey.fill(0);
        foundFileKey.fill(0);
        await SafeSession.Save();
        return this.Mount();
    }

    // Adapter-supplied UI permissions; server remains the authority.
    applyCapabilities() {
        const caps = Adapter.GetViewerCapabilities?.() ?? {};
        const set = (ids, allowed) => ids.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = allowed === false ? 'none' : '';
        });
        set(['btnViewerShare', 'viewerMenuShare'], caps.share);
        set(['btnViewerEdit', 'viewerMenuRename'], caps.rename);
        set(['btnViewerDelete', 'viewerMenuDelete'], caps.delete);
        set(['btnViewerDown', 'viewerMenuDownload'], caps.download);
    }

    // Clean up active player instance and revoke blob URL
    CleanupCurrentMedia() {
        // Clear keys
        for (const key of this.neighborKeys) key.fill(0);
        this.neighborKeys = [];

        // Clear buttons
        const btnPrev = document.getElementById("btnPrevFile");
        const btnNext = document.getElementById("btnNextFile");
        if (btnPrev) btnPrev.onclick = null;
        if (btnNext) btnNext.onclick = null;

        // Clear media
        const body = document.getElementById("viewBody");
        if (body) {
            const mediaEls = body.querySelectorAll("video, audio");
            mediaEls.forEach(el => {
                try {
                    el.pause();
                    el.removeAttribute('src');
                    el.load();
                } catch { }
            });
            body.innerHTML = "";
        }

        // Clear viewer and url
        if (window.currentViewer) {
            try { window.currentViewer.destroy(); } catch { }
            window.currentViewer = null;
        }
        if (this.currentBlobUrl) {
            try { URL.revokeObjectURL(this.currentBlobUrl); } catch { }
            this.currentBlobUrl = null;
        }
        try { Adapter.ReleaseStreaming(); } catch (err) {
            console.warn('Stream cleanup failed:', err);
        }
    }

    // --------------------------------------------------
    // 03. Media Rendering
    // --------------------------------------------------

    // Render media preview using streaming or download fallback
    async renderFilePreview() {
        const rawKey = Drive.UnmaskKey(this.fileKey);
        const filePid = GetObjPid(rawKey.slice(0, 44));
        rawKey.fill(0);

        // Set body and kind
        const body = document.getElementById("viewBody");
        if (!body) return;
        const kind = GetKind(this.fileName);
        if (kind === 'unsupported' && this.origSize > 4096) {
            return this.renderUnsupported(body);
        }

        // Prepare streaming if video or audio
        if (kind === 'video' || kind === 'audio') {
            body.innerHTML = `<p style="color:var(--preview-subtext);font-size:13px;margin:20px 0">Preparing ${kind} stream…</p>`;
            try {
                // Get stream url and fallback if streaming failed
                const streamUrl = await Adapter.GetStreamUrl(this.folderId, filePid, this.fileKey, this.origSize, this.fileName);
                const fallbackToFullDown = async (reason) => {
                    console.warn(`Streaming failed (${reason}). Falling back to full download...`);
                    await this.fullDownloadAndRender(filePid, body);
                };

                // Render audio or video player
                body.innerHTML = '';
                if (kind === 'audio') {
                    this.renderAudioPlayer(streamUrl, body, fallbackToFullDown);
                } else {
                    const video = document.createElement('video');
                    video.controls = true;
                    video.playsInline = true;
                    video.preload = 'metadata';
                    video.style.width = '100%';
                    video.src = streamUrl;
                    video.addEventListener('error', () => fallbackToFullDown(video.error ? `Code ${video.error.code}` : "Video error"));
                    body.appendChild(video);
                }
                return;
            } catch (err) {
                console.warn('Streaming error, fallback to full download:', err);
                await this.fullDownloadAndRender(filePid, body);
                return;
            }
        }

        // Default full download and render
        await this.fullDownloadAndRender(filePid, body);
    }

    // Render card for unsupported file type with download trigger
    renderUnsupported(body) {
        const sizeStr = this.origSize > 0 ? FormatBytes(this.origSize) : '';
        body.innerHTML = `
            <div class="unsupported-preview-card">
                <div class="unsupported-icon-box">
                    <span class="material-symbols-outlined unsupported-icon">draft</span>
                </div>
                <h2 class="unsupported-title">No preview available</h2>
                <p class="unsupported-msg">Preview is not supported for this file.</p>
                <div class="unsupported-meta">
                    <span class="unsupported-filename" title="${EscapeHtml(this.fileName)}">${EscapeHtml(this.fileName)}</span>
                    ${sizeStr ? `<span class="unsupported-filesize">${sizeStr}</span>` : ''}
                </div>
                <button type="button" class="btn-unsupported-download" id="btnUnsupportedDownload">
                    <span class="material-symbols-outlined">download</span>
                    <span>Download</span>
                </button>
            </div>
        `;
        document.getElementById("btnUnsupportedDownload")?.addEventListener("click", () => this.downloadCurrentFile());
    }

    // Render audio player card
    renderAudioPlayer(srcUrl, body, onError) {
        const sizeStr = this.origSize > 0 ? FormatBytes(this.origSize) : '';
        body.innerHTML = `
            <div class="audio-player-card">
                <div class="audio-hero-icon-box">
                    <span class="material-symbols-outlined audio-hero-icon">graphic_eq</span>
                </div>
                <div class="audio-title" title="${EscapeHtml(this.fileName)}">${EscapeHtml(this.fileName)}</div>
                <div class="audio-meta">${sizeStr}</div>
                <audio controls autoplay class="audio-element" id="audioPlayer"></audio>
            </div>
        `;
        const audio = body.querySelector('#audioPlayer');
        if (audio) audio.src = srcUrl;
        if (onError) {
            body.querySelector('#audioPlayer')?.addEventListener('error', () => onError('Audio playback error'));
        }
    }

    // Download entire ciphertext and decrypt in memory
    async fullDownloadAndRender(filePid, body) {
        body.innerHTML = `
            <div class="full-download-loading" style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:32px 20px;color:var(--preview-text);">
                <div class="m3-circular-progress" style="width:36px;height:36px;margin-bottom:14px;border-width:3px;"></div>
                <div id="fullDownloadStatus" style="font-size:14.5px;font-weight:500;margin-bottom:4px;">Preparing download…</div>
                <div id="fullDownloadMeta" style="font-size:12.5px;color:var(--preview-subtext);">0%</div>
            </div>
        `;
        const statusEl = document.getElementById("fullDownloadStatus");
        const metaEl = document.getElementById("fullDownloadMeta");

        try { // Load and decrypt file
            const blobUrl = await Adapter.LoadMediaBlob(
                this.folderId,
                filePid,
                this.fileKey,
                this.origSize,
                GetMime(this.fileName),
                (p) => {
                    if (p.phase === 'downloading') { // Update downloading progress
                        if (statusEl) statusEl.textContent = `Downloading ${p.percent}%`;
                        if (metaEl) metaEl.textContent = p.total > 0 ? `${FormatBytes(p.loaded)} / ${FormatBytes(p.total)}` : `${FormatBytes(p.loaded)}`;
                    } else if (p.phase === 'decrypting') { // Update decrypting progress
                        if (statusEl) statusEl.textContent = `Decrypting file…`;
                        if (metaEl) metaEl.textContent = `Almost ready`;
                    }
                }
            );
            this.currentBlobUrl = blobUrl;
            await this.renderDecryptedMedia(blobUrl, body);
        } catch (err) { // Download or decrypt failed
            body.innerHTML = `
                <div style="text-align: center; padding: 40px 20px; color: var(--preview-subtext);">
                    <span class="material-symbols-outlined" style="font-size: 48px; color: var(--preview-danger); margin-bottom: 12px; display: block;">error_outline</span>
                    <h3 style="margin: 0 0 8px 0; color: var(--preview-text);">Unable to load file</h3>
                    <p style="margin: 0 0 20px 0; font-size: 14px;">${EscapeHtml(err.message || "Failed to load media")}</p>
                </div>
            `;
        }
    }

    // Mount decrypted blob into corresponding media DOM element
    async renderDecryptedMedia(blobUrl, body) {
        const kind = GetKind(this.fileName);
        body.innerHTML = "";

        if (kind === 'video') { // render video player
            const video = document.createElement("video");
            video.controls = true;
            video.src = blobUrl;
            video.style.width = "100%";
            body.appendChild(video);

        } else if (kind === 'image') { // render image
            const img = document.createElement("img");
            img.src = blobUrl;
            img.alt = this.fileName;
            img.style.display = "none";
            body.appendChild(img);

            if (window.Viewer) { // initialize viewer
                window.currentViewer = new window.Viewer(img, {
                    inline: true,
                    button: false,
                    navbar: false,
                    title: false,
                    toolbar: {
                        zoomIn: 1, zoomOut: 1, oneToOne: 1, reset: 1, prev: 0, play: 0, next: 0, rotateLeft: 1, rotateRight: 1, flipHorizontal: 1, flipVertical: 1,
                    },
                    backdrop: 'static'
                });
            }

        } else if (kind === 'audio') { // render audio player
            this.renderAudioPlayer(blobUrl, body);

        } else if (kind === 'text') { // render text
            const response = await fetch(blobUrl);
            if (!response.ok) throw new Error(`Unable to read text preview (HTTP ${response.status})`);
            const content = await response.text();
            if (this.currentBlobUrl !== blobUrl) return; // viewer changed during async read
            const pre = document.createElement('pre');
            pre.className = 'viewer-text-preview';
            pre.textContent = content; // embed as text (not executable)
            pre.setAttribute('aria-label', `Text preview: ${this.fileName}`);
            body.appendChild(pre);

        } else if (kind === 'pdf') { // render pdf
            const obj = document.createElement("object");
            obj.data = blobUrl;
            obj.type = "application/pdf";
            obj.style.width = "100%";
            obj.style.height = "90vh";
            body.appendChild(obj);

        } else { // unsupported kind
            this.renderUnsupported(body);
        }
    }

    // --------------------------------------------------
    // 04. File Handling
    // --------------------------------------------------

    // Configure next and previous navigation within current folder
    async setupNeighborNavigation() {
        // Clear buttons and keys
        const btnPrev = document.getElementById("btnPrevFile");
        const btnNext = document.getElementById("btnNextFile");
        if (btnPrev) { btnPrev.classList.add("hidden"); btnPrev.onclick = null; }
        if (btnNext) { btnNext.classList.add("hidden"); btnNext.onclick = null; }
        for (const key of this.neighborKeys) key.fill(0);
        this.neighborKeys = [];

        let entries = [];
        try {
            // Find current media position
            const filesMap = await Adapter.LoadFolderMeta(this.folderId, this.folderKey);
            const sameFolder = Drive.currentFolderId === this.folderId;
            if (sameFolder && Drive.selectKeywords.size > 0 && !Drive.keywordsBuilt) Drive.BuildKeywords();
            const searchQuery = sameFolder ? document.getElementById('topSearchInput')?.value || '' : '';
            entries = OrderFileEntries(Object.entries(filesMap), {
                query: searchQuery,
                keywords: sameFolder ? Drive.selectKeywords : null,
                tokenCache: sameFolder ? Drive.tokenCache : null,
                sortMode: sameFolder ? Drive.sortMode : 'name-asc',
                getSize: rawKey => Drive.GetEntrySize(rawKey, true)
            });
            const idx = entries.findIndex(([name]) => name === this.fileName);
            if (idx === -1) return; // current file is not in folder

            // Set button click handler for previous/next file
            const setNeighbor = (button, entry) => {
                if (!button || !entry) return;
                const [name, rawKey] = entry;
                const maskedKey = Drive.MaskKey(rawKey);
                this.neighborKeys.push(maskedKey);

                // Show and bind button
                button.classList.remove("hidden");
                button.onclick = async () => {
                    if (!maskedKey.some(v => v !== 0)) return;
                    const key = Drive.UnmaskKey(maskedKey);
                    try {
                        SafeSession.SetItem("currentFileName", name);
                        SafeSession.SetItem("currentFileKey", ToHex(key));
                        await SafeSession.Save();
                    } finally {
                        key.fill(0);
                    }
                    await this.Mount();
                };
            };

            // Set buttons if valid index exist
            if (idx > 0) setNeighbor(btnPrev, entries[idx - 1]);
            if (idx < entries.length - 1) setNeighbor(btnNext, entries[idx + 1]);
        } catch (err) {
            console.error("Neighbor navigation error:", err);
        } finally {
            for (const [, key] of entries) if (key?.fill) key.fill(0);
        }
    }

    // Copy file deep link URL to clipboard
    async shareCurrentFile() {
        if (!this.folderId || !this.fileKey) return;
        const rawKey = Drive.UnmaskKey(this.fileKey);
        const filePid = GetObjPid(rawKey.slice(0, 44));
        rawKey.fill(0);
        try {
            const url = await Adapter.CreateShareLink(this.folderId, filePid, this.fileKey, this.fileName, this.origSize);
            try {
                await navigator.clipboard.writeText(url);
                ShowNotice("Deep link copied to clipboard.", "Share", "check_circle");
            } catch {
                prompt("Copy link:", url);
            }
        } catch (err) {
            ShowNotice("Share failed: " + err.message, "Error", "error");
        }
    }

    // Open file rename modal dialog
    openRenameModal() {
        const modal = document.getElementById("renameFileModal");
        const input = document.getElementById("modalRenameFileInput");
        const errText = document.getElementById("renameFileErrorText");
        if (errText) errText.style.display = "none";
        if (input) {
            input.value = this.fileName;
            const lastDot = this.fileName.lastIndexOf('.');
            if (lastDot > 0) input.setSelectionRange(0, lastDot);
            else input.select();
        }
        modal?.showModal();
    }

    // Rename active file on backend and update session
    async performRename(newName) {
        if (!newName || newName === this.fileName) return false;
        try {
            await Drive.RenameFile(this.fileName, newName);
            SafeSession.SetItem("currentFileName", newName);
            await SafeSession.Save();

            // Update UI
            this.fileName = newName;
            const tx = document.getElementById("txName");
            if (tx) { tx.textContent = newName; tx.title = newName; }
            ShowNotice(`Renamed to "${newName}"`, "Success", "check_circle");
            return true;
        } catch (err) {
            ShowNotice("Rename failed: " + err.message, "Error", "error");
            return false;
        }
    }

    // Trigger download of decrypted media blob
    async downloadCurrentFile() {
        if (this.currentBlobUrl) { // download via blob URL
            const a = document.createElement('a');
            a.href = this.currentBlobUrl;
            a.download = this.fileName;
            document.body.appendChild(a);
            a.click();
            a.remove();
            return;
        }

        // Download via drive key
        const rawKey = Drive.UnmaskKey(this.fileKey);
        const filePid = GetObjPid(rawKey.slice(0, 44));
        rawKey.fill(0);
        try {
            await Adapter.DownloadFile(
                this.folderId,
                filePid,
                this.fileKey,
                this.fileName,
                this.origSize
            );
        } catch (err) {
            ShowNotice("Download failed: " + err.message, "Error", "error");
        }
    }

    // Delete active file and return to drive view
    async deleteCurrentFile() {
        const ok = await ShowConfirmModal(
            `Are you sure you want to delete "<strong>${EscapeHtml(this.fileName)}</strong>"?`,
            "Delete file?",
            "delete",
            "Delete",
            true
        );
        if (!ok) return;
        try {
            await Drive.DeleteFile(this.fileName);
            ShowNotice(`Deleted "${this.fileName}"`, "Success", "check_circle");
            this.CleanupCurrentMedia();
            AppRouter.Navigate('/drive');
        } catch (err) {
            ShowNotice("Delete failed: " + err.message, "Error", "error");
        }
    }
}

// Global viewer instance
export const ViewerView = new ViewerViewService();