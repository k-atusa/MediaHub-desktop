// Media viewer view controller for streaming and full download playback
import { AppRouter } from '../core/router.js';
import { Drive } from '../core/drive.js';
import { Adapter } from '../core/adapter.js';
import {
    SafeSession, ShowNotice, ShowConfirmModal, FormatBytes, EscapeHtml,
    ToHex, FromHex, GetObjPid, GetKind, GetMime
} from '../core/utils.js';

// Media viewer view controller
class ViewerViewService {
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
    }

    // Attach toolbar and menu action listeners
    init() {
        if (this.initialized) return;
        this.initialized = true;

        const btnBack = document.getElementById("btnViewerBack");
        if (btnBack) {
            btnBack.addEventListener("click", () => {
                AppRouter.Navigate('/drive');
            });
        }

        const btnShare = document.getElementById("btnViewerShare");
        const btnEdit = document.getElementById("btnViewerEdit");
        const btnDown = document.getElementById("btnViewerDown");
        const btnDelete = document.getElementById("btnViewerDelete");
        const btnViewerMore = document.getElementById("btnViewerMore");
        const viewerActionMenu = document.getElementById("viewerActionMenu");

        if (btnShare) btnShare.addEventListener("click", () => this.shareCurrentFile());
        if (btnEdit) btnEdit.addEventListener("click", () => this.openRenameModal());
        if (btnDown) btnDown.addEventListener("click", () => this.downloadCurrentFile());
        if (btnDelete) btnDelete.addEventListener("click", () => this.deleteCurrentFile());

        if (btnViewerMore && viewerActionMenu) {
            btnViewerMore.addEventListener("click", (e) => {
                e.stopPropagation();
                const isOpen = viewerActionMenu.classList.toggle("open");
                btnViewerMore.classList.toggle("open", isOpen);
                viewerActionMenu.style.display = isOpen ? "block" : "none";
            });

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

        if (btnConfirmRenameFile) {
            btnConfirmRenameFile.addEventListener("click", async () => {
                const newName = modalRenameFileInput?.value.trim();
                if (!newName) {
                    if (renameFileErrorText) {
                        renameFileErrorText.textContent = "Please enter a file name.";
                        renameFileErrorText.style.display = "block";
                    }
                    return;
                }
                const ok = await this.performRename(newName);
                if (ok) renameFileModal?.close();
                else if (renameFileErrorText) {
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

    // Mount viewer and restore state from session
    async Mount() {
        this.init();
        this.CleanupCurrentMedia();

        this.folderId = SafeSession.GetItem("currentFolderId");
        this.fileName = SafeSession.GetItem("currentFileName");

        const rawFolderKeyHex = SafeSession.GetItem("currentFolderKey");
        const rawFileKeyHex = SafeSession.GetItem("currentFileKey");

        if (rawFolderKeyHex) {
            this.folderKey = Drive.MaskKey(FromHex(rawFolderKeyHex));
        } else {
            this.folderKey = null;
        }

        if (rawFileKeyHex) {
            const rawFileKey = FromHex(rawFileKeyHex);
            this.origSize = Drive.GetEntrySize(rawFileKey);
            this.fileKey = Drive.MaskKey(rawFileKey);
            rawFileKey.fill(0);
        } else {
            this.fileKey = null;
            this.origSize = 0;
        }

        if (!this.fileKey || !this.fileName || !this.folderId || !this.folderKey) {
            return AppRouter.Navigate('/drive', true);
        }

        const txName = document.getElementById("txName");
        if (txName) {
            txName.textContent = this.fileName;
            txName.title = this.fileName;
        }

        await this.renderFilePreview();
        await this.setupNeighborNavigation();
    }

    // Mount viewer with URL deep-link query parameters
    async MountWithQuery(query = {}) {
        this.init();
        const folderPid = query.f;
        const filePid = query.p;

        if (!folderPid || !filePid) {
            return this.Mount();
        }

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

    // Clean up active player instance and revoke blob URL
    CleanupCurrentMedia() {
        if (window.currentViewer) {
            try { window.currentViewer.destroy(); } catch { }
            window.currentViewer = null;
        }
        if (this.currentBlobUrl) {
            try { URL.revokeObjectURL(this.currentBlobUrl); } catch { }
            this.currentBlobUrl = null;
        }
    }

    // Render media preview using streaming or download fallback
    async renderFilePreview() {
        const rawKey = Drive.UnmaskKey(this.fileKey);
        const filePid = GetObjPid(rawKey.slice(0, 44));
        rawKey.fill(0);

        const body = document.getElementById("viewBody");
        if (!body) return;
        const kind = GetKind(this.fileName);

        if (kind === 'unsupported' && this.origSize > 4096) {
            return this.renderUnsupported(body);
        }

        if (kind === 'video' || kind === 'audio') {
            body.innerHTML = `<p style="color:var(--preview-subtext);font-size:13px;margin:20px 0">Preparing ${kind} stream…</p>`;
            try {
                const streamUrl = await Adapter.GetStreamUrl(this.folderId, filePid, this.fileKey, this.origSize, this.fileName);

                const fallbackToFullDown = async (reason) => {
                    console.warn(`Streaming failed (${reason}). Falling back to full download...`);
                    await this.fullDownloadAndRender(filePid, body);
                };

                body.innerHTML = '';
                if (kind === 'audio') {
                    this.renderAudioPlayer(streamUrl, body, fallbackToFullDown);
                } else {
                    const video = document.createElement('video');
                    video.controls = true;
                    video.crossOrigin = 'anonymous';
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

        await this.fullDownloadAndRender(filePid, body);
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
                <audio controls autoplay class="audio-element" id="audioPlayer" src="${srcUrl}"></audio>
            </div>
        `;
        if (onError) {
            body.querySelector('#audioPlayer')?.addEventListener('error', () => onError('Audio playback error'));
        }
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

    // Download entire ciphertext and decrypt in memory
    async fullDownloadAndRender(filePid, body) {
        const prog = document.createElement("div");
        prog.style.position = "fixed";
        prog.style.top = "50%";
        prog.style.width = "100%";
        prog.style.textAlign = "center";
        prog.textContent = "🔒 Loading & Decrypting…";
        body.appendChild(prog);

        try {
            const blobUrl = await Adapter.LoadMediaBlob(
                this.folderId,
                filePid,
                this.fileKey,
                this.origSize,
                GetMime(this.fileName)
            );
            this.currentBlobUrl = blobUrl;
            body.removeChild(prog);
            this.renderDecryptedMedia(blobUrl, body);
        } catch (err) {
            if (prog.parentNode) body.removeChild(prog);
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
    renderDecryptedMedia(blobUrl, body) {
        const kind = GetKind(this.fileName);
        body.innerHTML = "";

        if (kind === 'video') {
            const video = document.createElement("video");
            video.controls = true;
            video.src = blobUrl;
            video.style.width = "100%";
            body.appendChild(video);
        } else if (kind === 'image') {
            const img = document.createElement("img");
            img.src = blobUrl;
            img.alt = this.fileName;
            img.style.display = "none";
            body.appendChild(img);

            if (window.Viewer) {
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
        } else if (kind === 'audio') {
            this.renderAudioPlayer(blobUrl, body);
        } else if (kind === 'pdf') {
            const obj = document.createElement("object");
            obj.data = blobUrl;
            obj.type = "application/pdf";
            obj.style.width = "100%";
            obj.style.height = "90vh";
            body.appendChild(obj);
        } else {
            this.renderUnsupported(body);
        }
    }

    // Configure next and previous navigation within current folder
    async setupNeighborNavigation() {
        const btnPrev = document.getElementById("btnPrevFile");
        const btnNext = document.getElementById("btnNextFile");
        if (btnPrev) btnPrev.classList.add("hidden");
        if (btnNext) btnNext.classList.add("hidden");

        try {
            const filesMap = await Adapter.LoadFolderMeta(this.folderId, this.folderKey);
            const entries = Object.entries(filesMap).sort((a, b) => a[0].localeCompare(b[0]));
            const idx = entries.findIndex(([name]) => name === this.fileName);

            if (idx === -1) {
                for (const [, v] of entries) if (v?.fill) v.fill(0);
                return;
            }

            if (idx > 0 && btnPrev) {
                const [prevName, prevKey] = entries[idx - 1];
                btnPrev.classList.remove("hidden");
                btnPrev.onclick = () => {
                    SafeSession.SetItem("currentFileName", prevName);
                    SafeSession.SetItem("currentFileKey", ToHex(prevKey));
                    SafeSession.Save();
                    this.Mount();
                };
            }

            if (idx < entries.length - 1 && btnNext) {
                const [nextName, nextKey] = entries[idx + 1];
                btnNext.classList.remove("hidden");
                btnNext.onclick = () => {
                    SafeSession.SetItem("currentFileName", nextName);
                    SafeSession.SetItem("currentFileKey", ToHex(nextKey));
                    SafeSession.Save();
                    this.Mount();
                };
            }

            for (const [, v] of entries) if (v?.fill) v.fill(0);
        } catch (err) {
            console.error("Neighbor navigation error:", err);
        }
    }

    // Copy file deep link URL to clipboard
    async shareCurrentFile() {
        if (!this.folderId || !this.fileKey) return;
        const rawKey = Drive.UnmaskKey(this.fileKey);
        const filePid = GetObjPid(rawKey.slice(0, 44));
        rawKey.fill(0);

        const url = `${window.location.origin}/drive?f=${encodeURIComponent(this.folderId)}&p=${encodeURIComponent(filePid)}`;
        try {
            await navigator.clipboard.writeText(url);
            ShowNotice("Deep link copied to clipboard.", "Share", "check_circle");
        } catch {
            prompt("Copy link:", url);
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
        if (this.currentBlobUrl) {
            const a = document.createElement('a');
            a.href = this.currentBlobUrl;
            a.download = this.fileName;
            a.click();
            return;
        }

        const rawKey = Drive.UnmaskKey(this.fileKey);
        const filePid = GetObjPid(rawKey.slice(0, 44));
        rawKey.fill(0);

        ShowNotice(`Preparing download for "${this.fileName}"...`, "Downloading", "download");
        try {
            const blobUrl = await Adapter.LoadMediaBlob(
                this.folderId,
                filePid,
                this.fileKey,
                this.origSize,
                GetMime(this.fileName)
            );
            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = this.fileName;
            a.click();
            URL.revokeObjectURL(blobUrl);
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
            AppRouter.Navigate('/drive');
        } catch (err) {
            ShowNotice("Delete failed: " + err.message, "Error", "error");
        }
    }
}

// Global viewer view instance
export const ViewerView = new ViewerViewService();
