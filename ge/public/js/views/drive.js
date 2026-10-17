// Drive workspace UI view controller
import { Drive } from '../core/drive.js';
import { AppRouter } from '../core/router.js';
import {
    SafeSession, ShowNotice, ShowConfirmModal, FormatBytes, EscapeHtml,
    ToHex, FromHex, GetObjPid, GetGoogleFileIcon
} from '../core/utils.js';

const ringCircumference = 56.548;

// Drive workspace view controller
class DriveViewService {
    // Initialize view state, pagination, and upload status
    constructor() {
        this.container = document.getElementById('view-drive');
        this.initialized = false;
        this.page = 1;
        this.limit = 30;
        this.isInfiniteLoading = false;
        this.rootSearchCounter = 0;
        this.activeFolderMoreBtn = null;
        this.activeFileMoreBtn = null;
        this.fileBeingRenamed = null;
        this.folderBeingRenamed = null;

        this.activeUploadFiles = [];
        this.uploadDismissTimer = null;
        this.isWidgetHovered = false;
    }

    // Bind all UI components and event listeners
    init() {
        if (this.initialized) return;
        this.initialized = true;

        this.bindHeader();
        this.bindSidebar();
        this.bindWorkspaceActions();
        this.bindContextMenuListeners();
        this.bindModals();
        this.bindUploadAndDragDrop();
        this.bindUploadWidget();
    }

    // Bind header buttons, search input, and profile menu
    bindHeader() {
        const btnToggleSidebar = document.getElementById("btnToggleSidebar");
        const btnCloseSidebarDrawer = document.getElementById("btnCloseSidebarDrawer");
        const sidebarBackdrop = document.getElementById("sidebarBackdrop");
        const driveSidebar = document.querySelector(".drive-sidebar");

        const toggleSidebar = () => {
            if (window.innerWidth <= 768) {
                if (driveSidebar) {
                    const isOpen = driveSidebar.classList.toggle("mobile-open");
                    if (sidebarBackdrop) {
                        sidebarBackdrop.classList.toggle("active", isOpen);
                    }
                }
            } else {
                const isCollapsed = document.body.classList.toggle("sidebar-collapsed");
                localStorage.setItem("mediahub_sidebar_collapsed", isCollapsed ? "true" : "false");
            }
        };

        const closeMobileSidebar = () => {
            if (driveSidebar) driveSidebar.classList.remove("mobile-open");
            if (sidebarBackdrop) sidebarBackdrop.classList.remove("active");
        };

        if (btnToggleSidebar) btnToggleSidebar.addEventListener("click", toggleSidebar);
        if (btnCloseSidebarDrawer) btnCloseSidebarDrawer.addEventListener("click", closeMobileSidebar);
        if (sidebarBackdrop) sidebarBackdrop.addEventListener("click", closeMobileSidebar);

        if (window.innerWidth > 768 && localStorage.getItem("mediahub_sidebar_collapsed") === "true") {
            document.body.classList.add("sidebar-collapsed");
        }

        const topSearchInput = document.getElementById("topSearchInput");
        const btnSearchClear = document.getElementById("btnSearchClear");
        const btnMobileSearchToggle = document.getElementById("btnMobileSearchToggle");
        const btnMobileSearchClose = document.getElementById("btnMobileSearchClose");
        const driveHeader = document.querySelector(".drive-header");

        if (topSearchInput) {
            let debounce = null;
            const onSearch = () => {
                const val = (topSearchInput.value || "").trim();
                if (btnSearchClear) {
                    btnSearchClear.style.display = val.length > 0 ? "inline-flex" : "none";
                }
                clearTimeout(debounce);
                debounce = setTimeout(() => {
                    if (!Drive.currentFolderName) {
                        this.renderRootFolderGrid();
                    } else {
                        this.page = 1;
                        this.renderFiles(false);
                    }
                }, 100);
            };

            topSearchInput.addEventListener("input", onSearch);
            topSearchInput.addEventListener("compositionend", onSearch);
            topSearchInput.addEventListener("keydown", (e) => {
                if (e.key === "Escape") {
                    topSearchInput.value = "";
                    topSearchInput.blur();
                    if (btnSearchClear) btnSearchClear.style.display = "none";
                    if (driveHeader) driveHeader.classList.remove("mobile-search-active");
                    onSearch();
                }
            });
        }

        if (btnSearchClear) {
            btnSearchClear.addEventListener("click", () => {
                if (topSearchInput) {
                    topSearchInput.value = "";
                    btnSearchClear.style.display = "none";
                    topSearchInput.focus();
                    if (!Drive.currentFolderName) {
                        this.renderRootFolderGrid();
                    } else {
                        this.page = 1;
                        this.renderFiles(false);
                    }
                }
            });
        }

        if (btnMobileSearchToggle) {
            btnMobileSearchToggle.addEventListener("click", () => {
                if (driveHeader) {
                    driveHeader.classList.add("mobile-search-active");
                    setTimeout(() => topSearchInput?.focus(), 50);
                }
            });
        }

        if (btnMobileSearchClose) {
            btnMobileSearchClose.addEventListener("click", () => {
                if (driveHeader) driveHeader.classList.remove("mobile-search-active");
                if (topSearchInput) {
                    topSearchInput.value = "";
                    if (btnSearchClear) btnSearchClear.style.display = "none";
                    if (!Drive.currentFolderName) this.renderRootFolderGrid();
                    else {
                        this.page = 1;
                        this.renderFiles(false);
                    }
                }
            });
        }

        const btnAccountMenu = document.getElementById("btnAccountMenu");
        const accountDropdownMenu = document.getElementById("accountDropdownMenu");
        const accountMenuWrapper = document.getElementById("accountMenuWrapper");
        const accountMenuItemTheme = document.getElementById("accountMenuItemTheme");
        const accountMenuItemPassword = document.getElementById("accountMenuItemPassword");
        const accountMenuItemLogout = document.getElementById("accountMenuItemLogout");
        const pwModal = document.getElementById("pwModal");

        if (btnAccountMenu && accountDropdownMenu) {
            btnAccountMenu.addEventListener("click", (e) => {
                e.stopPropagation();
                this.closeAllDropdowns();
                const isOpen = accountDropdownMenu.classList.toggle("open");
                btnAccountMenu.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });

            document.addEventListener("click", (e) => {
                if (accountMenuWrapper && !accountMenuWrapper.contains(e.target)) {
                    accountDropdownMenu.classList.remove("open");
                    btnAccountMenu.setAttribute("aria-expanded", "false");
                }
            });
        }

        if (accountMenuItemTheme) {
            accountMenuItemTheme.addEventListener("click", () => {
                accountDropdownMenu?.classList.remove("open");
                const current = localStorage.getItem("theme") || "system";
                const next = current === "system" ? "dark" : current === "dark" ? "light" : "system";
                this.setTheme(next);
            });
        }

        if (accountMenuItemPassword) {
            accountMenuItemPassword.addEventListener("click", () => {
                accountDropdownMenu?.classList.remove("open");
                const p1 = document.getElementById("newPassword");
                const p2 = document.getElementById("newPasswordConfirm");
                if (p1) p1.value = "";
                if (p2) p2.value = "";
                if (pwModal) pwModal.showModal();
                p1?.focus();
            });
        }

        if (accountMenuItemLogout) {
            accountMenuItemLogout.addEventListener("click", () => {
                accountDropdownMenu?.classList.remove("open");
                Drive.ClearSession();
                AppRouter.Navigate('/login');
            });
        }
    }

    // Set theme mode and update DOM attributes
    setTheme(mode) {
        if (mode === "system") {
            localStorage.setItem("theme", "system");
            document.documentElement.removeAttribute("data-theme");
        } else {
            localStorage.setItem("theme", mode);
            document.documentElement.setAttribute("data-theme", mode);
        }
        this.UpdateThemeUI();
    }

    // Update account menu theme icon and text
    UpdateThemeUI() {
        const mode = localStorage.getItem("theme") || "system";
        const accountMenuThemeLabel = document.getElementById("accountMenuThemeLabel");
        const accountMenuThemeIcon = document.getElementById("accountMenuThemeIcon");
        if (mode === "dark") {
            if (accountMenuThemeIcon) accountMenuThemeIcon.textContent = "dark_mode";
            if (accountMenuThemeLabel) accountMenuThemeLabel.textContent = "Theme: Dark";
        } else if (mode === "light") {
            if (accountMenuThemeIcon) accountMenuThemeIcon.textContent = "light_mode";
            if (accountMenuThemeLabel) accountMenuThemeLabel.textContent = "Theme: Light";
        } else {
            if (accountMenuThemeIcon) accountMenuThemeIcon.textContent = "brightness_auto";
            if (accountMenuThemeLabel) accountMenuThemeLabel.textContent = "Theme: System (Auto)";
        }
    }

    // Bind sidebar navigation and new button dropdowns
    bindSidebar() {
        const btnNewDropdown = document.getElementById("btnNewDropdown");
        const newDriveMenu = document.getElementById("newDriveMenu");
        const newActionWrapper = document.getElementById("newActionWrapper");
        const menuItemNewFolder = document.getElementById("menuItemNewFolder");
        const btnImport = document.getElementById("btnImport");

        if (btnNewDropdown && newDriveMenu) {
            btnNewDropdown.addEventListener("click", (e) => {
                e.stopPropagation();
                this.closeAllDropdowns();
                const isOpen = newDriveMenu.classList.toggle("open");
                btnNewDropdown.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });

            document.addEventListener("click", (e) => {
                if (newActionWrapper && !newActionWrapper.contains(e.target)) {
                    newDriveMenu.classList.remove("open");
                    btnNewDropdown.setAttribute("aria-expanded", "false");
                }
            });
        }

        if (menuItemNewFolder) {
            menuItemNewFolder.addEventListener("click", () => {
                newDriveMenu?.classList.remove("open");
                const modal = document.getElementById("newFolderModal");
                const input = document.getElementById("modalFolderNameInput");
                if (input) input.value = "";
                if (modal) modal.showModal();
                input?.focus();
            });
        }

        if (btnImport) {
            btnImport.addEventListener("click", () => {
                newDriveMenu?.classList.remove("open");
                this.handleImportShare();
            });
        }

        const sidebarMyDriveHeader = document.getElementById("sidebarMyDriveHeader");
        const logoWrap = document.querySelector(".logo-wrap");
        const breadcrumbLink = document.querySelector(".breadcrumb-link");

        const navRoot = async () => {
            await this.Mount("");
            await AppRouter.Navigate('/drive');
        };
        if (sidebarMyDriveHeader) sidebarMyDriveHeader.addEventListener("click", navRoot);
        if (logoWrap) logoWrap.addEventListener("click", navRoot);
        if (breadcrumbLink) breadcrumbLink.addEventListener("click", navRoot);
    }

    // Bind view mode, sort, and keyword filter controls
    bindWorkspaceActions() {
        const btnViewMenu = document.getElementById("btnViewMenu");
        const viewDropdownMenu = document.getElementById("viewDropdownMenu");
        const viewActionWrapper = document.getElementById("viewActionWrapper");

        if (btnViewMenu && viewDropdownMenu) {
            btnViewMenu.addEventListener("click", (e) => {
                e.stopPropagation();
                this.closeAllDropdowns();
                const isOpen = viewDropdownMenu.classList.toggle("open");
                btnViewMenu.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });

            document.addEventListener("click", (e) => {
                if (viewActionWrapper && !viewActionWrapper.contains(e.target)) {
                    viewDropdownMenu.classList.remove("open");
                    btnViewMenu.setAttribute("aria-expanded", "false");
                }
            });
        }

        document.querySelectorAll(".view-menu-item").forEach(item => {
            item.addEventListener("click", () => {
                const mode = item.getAttribute("data-view");
                this.applyViewMode(mode);
                viewDropdownMenu?.classList.remove("open");
                btnViewMenu?.setAttribute("aria-expanded", "false");
            });
        });

        this.applyViewMode(localStorage.getItem("driveViewMode") || "medium");

        const btnSortMenu = document.getElementById("btnSortMenu");
        const sortDropdownMenu = document.getElementById("sortDropdownMenu");
        const sortActionWrapper = document.getElementById("sortActionWrapper");

        if (btnSortMenu && sortDropdownMenu) {
            btnSortMenu.addEventListener("click", (e) => {
                e.stopPropagation();
                this.closeAllDropdowns();
                const isOpen = sortDropdownMenu.classList.toggle("open");
                btnSortMenu.setAttribute("aria-expanded", isOpen ? "true" : "false");
            });

            document.addEventListener("click", (e) => {
                if (sortActionWrapper && !sortActionWrapper.contains(e.target)) {
                    sortDropdownMenu.classList.remove("open");
                    btnSortMenu.setAttribute("aria-expanded", "false");
                }
            });
        }

        document.querySelectorAll(".sort-menu-item").forEach(item => {
            item.addEventListener("click", () => {
                const mode = item.getAttribute("data-sort");
                this.applySortMode(mode);
                sortDropdownMenu?.classList.remove("open");
                btnSortMenu?.setAttribute("aria-expanded", "false");
            });
        });

        this.updateSortMenuUI(Drive.sortMode);

        const btnKeywordFilter = document.getElementById("btnKeywordFilter");
        const filterDropdownMenu = document.getElementById("filterDropdownMenu");
        const filterActionWrapper = document.getElementById("filterActionWrapper");
        const keywordFilterSearchInput = document.getElementById("keywordFilterSearchInput");
        const btnClearActiveChips = document.getElementById("btnClearActiveChips");
        const btnClearAllKeywords = document.getElementById("btnClearAllKeywords");

        if (btnKeywordFilter && filterDropdownMenu) {
            btnKeywordFilter.addEventListener("click", (e) => {
                e.stopPropagation();
                this.closeAllDropdowns();
                const isOpen = filterDropdownMenu.classList.toggle("open");
                btnKeywordFilter.setAttribute("aria-expanded", isOpen ? "true" : "false");
                if (isOpen) {
                    if (keywordFilterSearchInput) keywordFilterSearchInput.value = "";
                    this.renderKeywordDropdownItems("");
                    setTimeout(() => keywordFilterSearchInput?.focus(), 50);
                }
            });

            document.addEventListener("click", (e) => {
                if (filterActionWrapper && !filterActionWrapper.contains(e.target)) {
                    filterDropdownMenu.classList.remove("open");
                    btnKeywordFilter.setAttribute("aria-expanded", "false");
                }
            });
        }

        if (keywordFilterSearchInput) {
            const onFilterSearch = () => {
                this.renderKeywordDropdownItems(keywordFilterSearchInput.value);
            };
            keywordFilterSearchInput.addEventListener("input", onFilterSearch);
            keywordFilterSearchInput.addEventListener("compositionend", onFilterSearch);
        }

        const clearKeywords = () => {
            Drive.selectKeywords.clear();
            this.page = 1;
            this.renderFiles(false);
            this.updateKeywordFilterUI();
        };

        if (btnClearActiveChips) btnClearActiveChips.addEventListener("click", clearKeywords);
        if (btnClearAllKeywords) btnClearAllKeywords.addEventListener("click", clearKeywords);

        const btnCurrentFolderMore = document.getElementById("btnCurrentFolderMore");
        if (btnCurrentFolderMore) {
            btnCurrentFolderMore.addEventListener("click", (e) => {
                e.stopPropagation();
                if (Drive.currentFolderName) {
                    this.openFolderContextMenu(e, Drive.currentFolderName, btnCurrentFolderMore);
                }
            });
        }

        const mediaContainer = document.getElementById("mediaContainer");
        if (mediaContainer) {
            mediaContainer.addEventListener("scroll", () => {
                this.closeFolderContextMenu();
                this.closeFileContextMenu();
                this.handleInfiniteScroll();
            });
        }
    }

    // Close all open dropdown menus
    closeAllDropdowns() {
        document.querySelectorAll(".account-dropdown-menu, .new-drive-menu, .view-dropdown-menu, .sort-dropdown-menu, .filter-dropdown-menu").forEach(menu => {
            menu.classList.remove("open");
        });
        document.querySelectorAll("[aria-expanded='true']").forEach(btn => {
            btn.setAttribute("aria-expanded", "false");
        });
    }

    // Apply grid or list view mode styling
    applyViewMode(mode) {
        let cleanMode = mode;
        if (cleanMode === "grid") cleanMode = "medium";
        else if (cleanMode === "list") cleanMode = "details";
        else if (cleanMode === "large-grid") cleanMode = "large";

        localStorage.setItem("driveViewMode", cleanMode);
        const mediaGrid = document.getElementById("mediaGrid");
        const mediaContainer = document.getElementById("mediaContainer");
        const viewModeIcon = document.getElementById("viewModeIcon");

        if (mediaGrid && mediaContainer) {
            mediaGrid.classList.remove("view-extra-large", "view-large", "view-medium", "view-small", "view-details", "list-view", "large-grid");
            mediaContainer.classList.remove("is-list-mode");

            if (cleanMode === "details") {
                mediaGrid.classList.add("view-details", "list-view");
                mediaContainer.classList.add("is-list-mode");
                if (viewModeIcon) viewModeIcon.textContent = "view_list";
            } else if (cleanMode === "extra-large") {
                mediaGrid.classList.add("view-extra-large");
                if (viewModeIcon) viewModeIcon.textContent = "photo_size_select_actual";
            } else if (cleanMode === "large") {
                mediaGrid.classList.add("view-large");
                if (viewModeIcon) viewModeIcon.textContent = "view_module";
            } else if (cleanMode === "small") {
                mediaGrid.classList.add("view-small");
                if (viewModeIcon) viewModeIcon.textContent = "view_compact";
            } else {
                cleanMode = "medium";
                mediaGrid.classList.add("view-medium");
                if (viewModeIcon) viewModeIcon.textContent = "grid_view";
            }
        }

        document.querySelectorAll(".view-menu-item").forEach(item => {
            item.classList.toggle("active", item.getAttribute("data-view") === cleanMode);
        });

        if (cleanMode === "details") {
            this.enhanceCardsForListView();
        }
    }

    // Apply sorting mode to file list
    applySortMode(mode) {
        Drive.sortMode = mode;
        localStorage.setItem("mediahub_sort", mode);
        this.updateSortMenuUI(mode);
        this.page = 1;
        this.renderFiles(false);
    }

    // Update active sort option in menu
    updateSortMenuUI(mode) {
        const sortModeText = document.getElementById("sortModeText");
        const sortModeIcon = document.getElementById("sortModeIcon");

        document.querySelectorAll(".sort-menu-item").forEach(item => {
            item.classList.toggle("active", item.getAttribute("data-sort") === mode);
        });

        if (sortModeText && sortModeIcon) {
            if (mode === "name-asc") {
                sortModeText.textContent = "Sort: Name (A-Z)";
                sortModeIcon.textContent = "arrow_upward";
            } else if (mode === "name-desc") {
                sortModeText.textContent = "Sort: Name (Z-A)";
                sortModeIcon.textContent = "arrow_downward";
            } else if (mode === "size-asc") {
                sortModeText.textContent = "Sort: Size (Small)";
                sortModeIcon.textContent = "straighten";
            } else if (mode === "size-desc") {
                sortModeText.textContent = "Sort: Size (Large)";
                sortModeIcon.textContent = "inventory_2";
            }
        }
    }

    // Bind action listeners for folder and file context menus
    bindContextMenuListeners() {
        const folderActionMenu = document.getElementById("folderActionMenu");
        const fileActionMenu = document.getElementById("fileActionMenu");

        document.getElementById("folderMenuRename")?.addEventListener("click", (e) => {
            e.stopPropagation();
            const target = folderActionMenu?.dataset.targetFolder;
            this.closeFolderContextMenu();
            if (target) this.openRenameFolderModal(target);
        });

        document.getElementById("folderMenuShare")?.addEventListener("click", (e) => {
            e.stopPropagation();
            const target = folderActionMenu?.dataset.targetFolder;
            this.closeFolderContextMenu();
            if (target) this.openShareFolderModal(target);
        });

        document.getElementById("folderMenuTrim")?.addEventListener("click", (e) => {
            e.stopPropagation();
            const target = folderActionMenu?.dataset.targetFolder;
            this.closeFolderContextMenu();
            if (target) this.openTrimFolderModal(target);
        });

        document.getElementById("folderMenuUnlink")?.addEventListener("click", (e) => {
            e.stopPropagation();
            const target = folderActionMenu?.dataset.targetFolder;
            this.closeFolderContextMenu();
            if (target) this.openUnlinkFolderModal(target);
        });

        document.getElementById("folderMenuDelete")?.addEventListener("click", (e) => {
            e.stopPropagation();
            const target = folderActionMenu?.dataset.targetFolder;
            this.closeFolderContextMenu();
            if (target) this.openDeleteFolderModal(target);
        });

        document.getElementById("fileMenuShare")?.addEventListener("click", async (e) => {
            e.stopPropagation();
            const target = fileActionMenu?.dataset.targetFile;
            this.closeFileContextMenu();
            if (target) this.shareFile(target);
        });

        document.getElementById("fileMenuRename")?.addEventListener("click", (e) => {
            e.stopPropagation();
            const target = fileActionMenu?.dataset.targetFile;
            this.closeFileContextMenu();
            if (target) this.openRenameFileModal(target);
        });

        document.getElementById("fileMenuDownload")?.addEventListener("click", async (e) => {
            e.stopPropagation();
            const target = fileActionMenu?.dataset.targetFile;
            this.closeFileContextMenu();
            if (target) this.downloadFile(target);
        });

        document.getElementById("fileMenuDelete")?.addEventListener("click", async (e) => {
            e.stopPropagation();
            const target = fileActionMenu?.dataset.targetFile;
            this.closeFileContextMenu();
            if (target) this.deleteFile(target);
        });

        document.addEventListener("click", (e) => {
            if (folderActionMenu?.classList.contains("open")) {
                if (!folderActionMenu.contains(e.target) && (!this.activeFolderMoreBtn || !this.activeFolderMoreBtn.contains(e.target))) {
                    this.closeFolderContextMenu();
                }
            }
            if (fileActionMenu?.classList.contains("open")) {
                if (!fileActionMenu.contains(e.target) && (!this.activeFileMoreBtn || !this.activeFileMoreBtn.contains(e.target))) {
                    this.closeFileContextMenu();
                }
            }
        });
    }

    // Close folder context menu dropdown
    closeFolderContextMenu() {
        const folderActionMenu = document.getElementById("folderActionMenu");
        if (folderActionMenu) {
            folderActionMenu.classList.remove("open");
            folderActionMenu.style.display = "none";
        }
        if (this.activeFolderMoreBtn) {
            this.activeFolderMoreBtn.classList.remove("open");
            this.activeFolderMoreBtn = null;
        }
    }

    // Position and open context menu for folder
    openFolderContextMenu(e, folderName, btn) {
        const folderActionMenu = document.getElementById("folderActionMenu");
        if (!folderActionMenu) return;
        if (folderActionMenu.classList.contains("open") && this.activeFolderMoreBtn === btn) {
            this.closeFolderContextMenu();
            return;
        }

        this.closeAllDropdowns();
        this.closeFileContextMenu();
        if (this.activeFolderMoreBtn) this.activeFolderMoreBtn.classList.remove("open");

        this.activeFolderMoreBtn = btn;
        btn.classList.add("open");
        folderActionMenu.dataset.targetFolder = folderName;

        folderActionMenu.style.visibility = "hidden";
        folderActionMenu.style.display = "block";

        const btnRect = btn.getBoundingClientRect();
        const menuWidth = folderActionMenu.offsetWidth || 190;
        const menuHeight = folderActionMenu.offsetHeight || 140;

        let left = btnRect.right + 6;
        let top = btnRect.top - 4;

        if (left + menuWidth > window.innerWidth - 10) {
            left = btnRect.left - menuWidth - 6;
            if (left < 10) left = window.innerWidth - menuWidth - 10;
        }
        if (top + menuHeight > window.innerHeight - 10) {
            top = window.innerHeight - menuHeight - 10;
        }
        if (top < 10) top = 10;

        folderActionMenu.style.left = `${left}px`;
        folderActionMenu.style.top = `${top}px`;
        folderActionMenu.style.visibility = "";
        folderActionMenu.classList.add("open");
    }

    // Close file context menu dropdown
    closeFileContextMenu() {
        const fileActionMenu = document.getElementById("fileActionMenu");
        if (fileActionMenu) {
            fileActionMenu.classList.remove("open");
            fileActionMenu.style.display = "none";
        }
        if (this.activeFileMoreBtn) {
            this.activeFileMoreBtn.classList.remove("open");
            this.activeFileMoreBtn = null;
        }
    }

    // Position and open context menu for file
    openFileContextMenu(e, fileName, btn) {
        const fileActionMenu = document.getElementById("fileActionMenu");
        if (!fileActionMenu) return;
        if (fileActionMenu.classList.contains("open") && this.activeFileMoreBtn === btn) {
            this.closeFileContextMenu();
            return;
        }

        this.closeAllDropdowns();
        this.closeFolderContextMenu();
        if (this.activeFileMoreBtn) this.activeFileMoreBtn.classList.remove("open");

        this.activeFileMoreBtn = btn;
        btn.classList.add("open");
        fileActionMenu.dataset.targetFile = fileName;

        fileActionMenu.style.visibility = "hidden";
        fileActionMenu.style.display = "block";

        const btnRect = btn.getBoundingClientRect();
        const menuWidth = fileActionMenu.offsetWidth || 190;
        const menuHeight = fileActionMenu.offsetHeight || 140;

        let left = btnRect.right + 6;
        let top = btnRect.top - 4;

        if (left + menuWidth > window.innerWidth - 10) {
            left = btnRect.left - menuWidth - 6;
            if (left < 10) left = window.innerWidth - menuWidth - 10;
        }
        if (top + menuHeight > window.innerHeight - 10) {
            top = window.innerHeight - menuHeight - 10;
        }
        if (top < 10) top = 10;

        fileActionMenu.style.left = `${left}px`;
        fileActionMenu.style.top = `${top}px`;
        fileActionMenu.style.visibility = "";
        fileActionMenu.classList.add("open");
    }

    // Bind modal actions for folder creation, rename, and password change
    bindModals() {
        const newFolderModal = document.getElementById("newFolderModal");
        const btnConfirmNewFolder = document.getElementById("btnConfirmNewFolder");
        const btnCancelNewFolder = document.getElementById("btnCancelNewFolder");
        const modalFolderNameInput = document.getElementById("modalFolderNameInput");

        const handleCreateFolder = async () => {
            const name = modalFolderNameInput?.value.trim();
            if (!name) return;
            try {
                await Drive.CreateFolder(name);
                newFolderModal?.close();
                this.renderSidebarFolderList();
                this.renderRootFolderGrid();
                ShowNotice(`Folder "${name}" created successfully.`, "Success", "check_circle");
            } catch (err) {
                ShowNotice("Failed to create folder: " + err.message, "Error", "error");
            }
        };

        if (btnConfirmNewFolder) btnConfirmNewFolder.addEventListener("click", handleCreateFolder);
        if (btnCancelNewFolder) btnCancelNewFolder.addEventListener("click", () => newFolderModal?.close());
        if (modalFolderNameInput) {
            modalFolderNameInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    handleCreateFolder();
                }
            });
        }

        const renameFolderModal = document.getElementById("renameFolderModal");
        const btnConfirmRenameFolder = document.getElementById("btnConfirmRenameFolder");
        const btnCancelRenameFolder = document.getElementById("btnCancelRenameFolder");
        const modalRenameFolderNameInput = document.getElementById("modalRenameFolderNameInput");
        const renameFolderErrorText = document.getElementById("renameFolderErrorText");

        const handleRenameFolder = async () => {
            if (!this.folderBeingRenamed) return;
            const newName = modalRenameFolderNameInput?.value.trim();
            if (!newName) {
                if (renameFolderErrorText) {
                    renameFolderErrorText.textContent = "Please enter a folder name.";
                    renameFolderErrorText.style.display = "block";
                }
                return;
            }
            try {
                await Drive.RenameFolder(this.folderBeingRenamed, newName);
                renameFolderModal?.close();
                this.renderSidebarFolderList();
                if (Drive.currentFolderName === newName) {
                    this.updateFolderHeader(newName);
                } else {
                    this.renderRootFolderGrid();
                }
                ShowNotice(`Folder renamed to "${newName}"`, "Success", "check_circle");
            } catch (err) {
                if (renameFolderErrorText) {
                    renameFolderErrorText.textContent = err.message || "Failed to rename folder.";
                    renameFolderErrorText.style.display = "block";
                }
            }
        };

        if (btnConfirmRenameFolder) btnConfirmRenameFolder.addEventListener("click", handleRenameFolder);
        if (btnCancelRenameFolder) btnCancelRenameFolder.addEventListener("click", () => renameFolderModal?.close());
        if (modalRenameFolderNameInput) {
            modalRenameFolderNameInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    handleRenameFolder();
                }
            });
            modalRenameFolderNameInput.addEventListener("input", () => {
                if (renameFolderErrorText) renameFolderErrorText.style.display = "none";
            });
        }

        const renameFileModal = document.getElementById("renameFileModal");
        const btnConfirmRenameFile = document.getElementById("btnConfirmRenameFile");
        const btnCancelRenameFile = document.getElementById("btnCancelRenameFile");
        const modalRenameFileNameInput = document.getElementById("modalRenameFileNameInput");
        const renameFileErrorText = document.getElementById("renameFileErrorText");

        const handleRenameFile = async () => {
            if (!this.fileBeingRenamed) return;
            const newName = modalRenameFileNameInput?.value.trim();
            if (!newName) {
                if (renameFileErrorText) {
                    renameFileErrorText.textContent = "Please enter a file name.";
                    renameFileErrorText.style.display = "block";
                }
                return;
            }
            try {
                await Drive.RenameFile(this.fileBeingRenamed, newName);
                renameFileModal?.close();
                this.renderFiles(false);
                ShowNotice(`Renamed to "${newName}"`, "Success", "check_circle");
            } catch (err) {
                if (renameFileErrorText) {
                    renameFileErrorText.textContent = err.message || "Failed to rename file.";
                    renameFileErrorText.style.display = "block";
                }
            }
        };

        if (btnConfirmRenameFile) btnConfirmRenameFile.addEventListener("click", handleRenameFile);
        if (btnCancelRenameFile) btnCancelRenameFile.addEventListener("click", () => renameFileModal?.close());
        if (modalRenameFileNameInput) {
            modalRenameFileNameInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    handleRenameFile();
                }
            });
            modalRenameFileNameInput.addEventListener("input", () => {
                if (renameFileErrorText) renameFileErrorText.style.display = "none";
            });
        }

        const pwModal = document.getElementById("pwModal");
        const btnConfirmPw = document.getElementById("btnConfirmPw");
        const btnCancelPw = document.getElementById("btnCancelPw");

        if (btnConfirmPw) {
            btnConfirmPw.addEventListener("click", async () => {
                const newPw = document.getElementById("newPassword").value;
                const confirmPw = document.getElementById("newPasswordConfirm").value;
                if (!newPw) return ShowNotice("Please enter a new password.", "Notice", "warning");
                if (newPw !== confirmPw) return ShowNotice("Passwords do not match.", "Notice", "warning");

                try {
                    await Drive.ChangePassword(newPw);
                    pwModal?.close();
                    this.syncUserProfileUI();
                    ShowNotice("Password changed successfully.", "Success", "check_circle");
                } catch (err) {
                    ShowNotice("Failed to change password: " + err.message, "Error", "error");
                }
            });
        }
        if (btnCancelPw) btnCancelPw.addEventListener("click", () => pwModal?.close());

        const trimFolderModal = document.getElementById("trimFolderModal");
        const btnConfirmTrimFolder = document.getElementById("btnConfirmTrimFolder");
        const btnCancelTrimFolder = document.getElementById("btnCancelTrimFolder");

        if (btnConfirmTrimFolder) {
            btnConfirmTrimFolder.addEventListener("click", async () => {
                const folderName = trimFolderModal?.dataset.folderName;
                if (!folderName) return;

                const statusArea = document.getElementById("trimFolderStatusArea");
                const resultText = document.getElementById("trimFolderResultText");
                const desc = document.getElementById("trimFolderDesc");
                const actions = document.getElementById("trimFolderActions");

                if (statusArea) statusArea.style.display = "block";
                if (desc) desc.style.display = "none";
                if (actions) actions.style.display = "none";

                try {
                    const res = await Drive.TrimFolder(folderName);
                    if (statusArea) statusArea.style.display = "none";
                    if (resultText) {
                        resultText.style.display = "block";
                        resultText.textContent = res.text || "Trim completed successfully.";
                    }
                    setTimeout(() => {
                        trimFolderModal?.close();
                        if (actions) actions.style.display = "flex";
                        if (desc) desc.style.display = "block";
                        if (resultText) resultText.style.display = "none";
                        if (Drive.currentFolderName === folderName) {
                            this.renderFiles(false);
                        }
                    }, 1200);
                } catch (err) {
                    if (statusArea) statusArea.style.display = "none";
                    if (resultText) {
                        resultText.style.display = "block";
                        resultText.textContent = "Error: " + err.message;
                    }
                    if (actions) actions.style.display = "flex";
                }
            });
        }
        if (btnCancelTrimFolder) btnCancelTrimFolder.addEventListener("click", () => trimFolderModal?.close());

        document.querySelectorAll("dialog").forEach(dialog => {
            dialog.addEventListener("click", (e) => {
                const rect = dialog.getBoundingClientRect();
                const inDialog = (rect.top <= e.clientY && e.clientY <= rect.top + rect.height && rect.left <= e.clientX && e.clientX <= rect.left + rect.width);
                if (!inDialog) dialog.close();
            });
        });
    }

    // Open rename dialog for selected folder
    openRenameFolderModal(folderName) {
        this.folderBeingRenamed = folderName;
        const modal = document.getElementById("renameFolderModal");
        const input = document.getElementById("modalRenameFolderNameInput");
        const errText = document.getElementById("renameFolderErrorText");
        if (errText) errText.style.display = "none";
        if (input) {
            input.value = folderName;
            input.select();
        }
        if (modal) modal.showModal();
    }

    // Open rename dialog for selected file
    openRenameFileModal(fileName) {
        this.fileBeingRenamed = fileName;
        const modal = document.getElementById("renameFileModal");
        const input = document.getElementById("modalRenameFileNameInput");
        const errText = document.getElementById("renameFileErrorText");
        if (errText) errText.style.display = "none";
        if (input) {
            input.value = fileName;
            const lastDot = fileName.lastIndexOf(".");
            if (lastDot > 0) input.setSelectionRange(0, lastDot);
            else input.select();
        }
        if (modal) modal.showModal();
    }

    // Open password prompt modal to export folder share token
    async openShareFolderModal(folderName) {
        const modal = document.getElementById("shareModal");
        const descEl = document.getElementById("shareModalDesc");
        const pwInput = document.getElementById("sharePasswordInput");
        const errText = document.getElementById("shareErrorText");
        const btnConfirm = document.getElementById("btnConfirmShare");
        const btnCancel = document.getElementById("btnCancelShare");

        if (descEl) {
            descEl.innerHTML = `Set a password to encrypt this folder's share token for "<strong>${EscapeHtml(folderName)}</strong>". Anyone with the token file and password can access the folder.`;
        }
        if (pwInput) pwInput.value = "";
        if (errText) errText.style.display = "none";

        modal?.showModal();
        pwInput?.focus();

        const cleanup = () => {
            btnConfirm?.removeEventListener("click", onConfirm);
            btnCancel?.removeEventListener("click", onCancel);
        };
        const onCancel = () => { cleanup(); modal?.close(); };
        const onConfirm = async () => {
            const pw = pwInput?.value;
            if (!pw) {
                if (errText) {
                    errText.textContent = "Please enter a password.";
                    errText.style.display = "block";
                }
                return;
            }
            cleanup();
            modal?.close();

            const token = await Drive.ExportShareToken(folderName, pw);
            if (!token) return;

            const blob = new Blob([token], { type: "text/plain" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            const safeName = folderName.replace(/[\\/:*?"<>|]/g, "_");
            a.download = `${safeName}_share.txt`;
            a.click();
            URL.revokeObjectURL(url);
            ShowNotice("Share token downloaded successfully.", "Share Folder", "check_circle");
        };

        btnConfirm?.addEventListener("click", onConfirm);
        btnCancel?.addEventListener("click", onCancel);
    }

    // File picker prompt to import and decrypt folder share token
    async handleImportShare() {
        const input = document.createElement("input");
        input.type = "file";
        input.accept = ".txt";
        input.onchange = async () => {
            if (!input.files[0]) return;
            const fileText = (await input.files[0].text()).trim();

            const modal = document.getElementById("importShareModal");
            const pwInput = document.getElementById("importPasswordInput");
            const errText = document.getElementById("importErrorText");
            const btnConfirm = document.getElementById("btnConfirmImportShare");
            const btnCancel = document.getElementById("btnCancelImportShare");

            if (pwInput) pwInput.value = "";
            if (errText) errText.style.display = "none";
            modal?.showModal();
            pwInput?.focus();

            const cleanup = () => {
                btnConfirm?.removeEventListener("click", onConfirm);
                btnCancel?.removeEventListener("click", onCancel);
            };
            const onCancel = () => { cleanup(); modal?.close(); };
            const onConfirm = async () => {
                const pw = pwInput?.value;
                if (!pw) {
                    if (errText) {
                        errText.textContent = "Please enter the password.";
                        errText.style.display = "block";
                    }
                    return;
                }
                cleanup();
                modal?.close();

                const info = await Drive.ImportShareToken(fileText, pw);
                if (!info) {
                    return ShowNotice("Invalid token or incorrect password.", "Error", "error");
                }

                const effectiveName = info.name;
                if (Drive.fldMap[effectiveName]) {
                    const overwrite = await ShowConfirmModal(
                        `A folder named "${effectiveName}" already exists. Overwrite?`,
                        "Overwrite Folder?",
                        "warning",
                        "Overwrite",
                        true
                    );
                    if (!overwrite) return;
                }

                Drive.fldMap[effectiveName] = info.key;
                await Drive.SaveUser();
                await Drive.LoadUser();
                this.renderSidebarFolderList();
                this.renderRootFolderGrid();
                ShowNotice(`Folder "${effectiveName}" imported successfully.`, "Success", "check_circle");
            };

            btnConfirm?.addEventListener("click", onConfirm);
            btnCancel?.addEventListener("click", onCancel);
        };
        input.click();
    }

    // Open orphan file trim confirmation modal
    openTrimFolderModal(folderName) {
        const modal = document.getElementById("trimFolderModal");
        if (modal) {
            modal.dataset.folderName = folderName;
            modal.showModal();
        }
    }

    // Unlink folder from current user catalog
    async openUnlinkFolderModal(folderName) {
        const ok = await ShowConfirmModal(
            `Are you sure you want to remove folder "<strong>${EscapeHtml(folderName)}</strong>" from your account? The folder will remain accessible for other users sharing it.`,
            "Remove Folder?",
            "link_off",
            "Remove"
        );
        if (!ok) return;
        try {
            await Drive.UnlinkFolder(folderName);
            this.renderSidebarFolderList();
            if (Drive.currentFolderName === folderName) {
                await this.Mount("");
                await AppRouter.Navigate('/drive');
            } else {
                this.renderRootFolderGrid();
            }
            ShowNotice(`Removed "${folderName}" from your account.`, "Success", "check_circle");
        } catch (err) {
            ShowNotice("Failed to remove folder: " + err.message, "Error", "error");
        }
    }

    // Permanently delete folder and all contents on server
    async openDeleteFolderModal(folderName) {
        const ok = await ShowConfirmModal(
            `Are you sure you want to delete "<strong>${EscapeHtml(folderName)}</strong>" permanently? All files and encrypted metadata inside it will be permanently deleted from the server for ALL users.`,
            "Delete Permanently?",
            "delete_forever",
            "Delete Permanently",
            true
        );
        if (!ok) return;
        try {
            await Drive.DeleteFolder(folderName);
            this.renderSidebarFolderList();
            if (Drive.currentFolderName === folderName) {
                await this.Mount("");
                await AppRouter.Navigate('/drive');
            } else {
                this.renderRootFolderGrid();
            }
            ShowNotice(`Folder "${folderName}" permanently deleted.`, "Deleted", "delete");
        } catch (err) {
            ShowNotice("Failed to delete folder: " + err.message, "Error", "error");
        }
    }

    // Bind file selection and full-window drag & drop handlers
    bindUploadAndDragDrop() {
        const fileInput = document.getElementById("fileInput");
        const folderInput = document.getElementById("folderInput");
        const menuItemFileUpload = document.getElementById("menuItemFileUpload");
        const menuItemFolderUpload = document.getElementById("menuItemFolderUpload");
        const btnEmptyUploadAction = document.getElementById("btnEmptyUploadAction");

        const triggerFile = () => {
            this.closeAllDropdowns();
            if (!Drive.currentFolderName) {
                return ShowNotice("Please select or create a folder first to upload files.", "Select Folder", "warning");
            }
            if (fileInput) { fileInput.value = ""; fileInput.click(); }
        };

        const triggerFolder = () => {
            this.closeAllDropdowns();
            if (!Drive.currentFolderName) {
                return ShowNotice("Please select or create a folder first to upload files.", "Select Folder", "warning");
            }
            if (folderInput) { folderInput.value = ""; folderInput.click(); }
        };

        if (menuItemFileUpload) menuItemFileUpload.addEventListener("click", triggerFile);
        if (menuItemFolderUpload) menuItemFolderUpload.addEventListener("click", triggerFolder);
        if (btnEmptyUploadAction) btnEmptyUploadAction.addEventListener("click", triggerFile);

        if (fileInput) {
            fileInput.addEventListener("change", () => {
                if (fileInput.files.length > 0) {
                    const prepared = Drive.PrepareFiles(fileInput.files);
                    this.executeUpload(prepared);
                }
            });
        }

        if (folderInput) {
            folderInput.addEventListener("change", () => {
                if (folderInput.files.length > 0) {
                    const prepared = Drive.PrepareFiles(folderInput.files);
                    this.executeUpload(prepared);
                }
            });
        }

        const dragDropOverlay = document.getElementById("dragDropOverlay");
        const dragDropSubtitle = document.getElementById("dragDropSubtitle");
        let dragCounter = 0;

        window.addEventListener("dragenter", (e) => {
            e.preventDefault();
            if (e.dataTransfer && e.dataTransfer.types && Array.from(e.dataTransfer.types).includes("Files")) {
                dragCounter++;
                if (dragCounter === 1 && dragDropOverlay) {
                    const cur = Drive.currentFolderName;
                    if (dragDropSubtitle) dragDropSubtitle.textContent = cur ? `Upload to "${cur}"` : "Please select a folder first";
                    dragDropOverlay.classList.add("active");
                }
            }
        });

        window.addEventListener("dragleave", (e) => {
            e.preventDefault();
            dragCounter--;
            if (dragCounter <= 0) {
                dragCounter = 0;
                dragDropOverlay?.classList.remove("active");
            }
        });

        window.addEventListener("dragover", (e) => {
            e.preventDefault();
            if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
        });

        window.addEventListener("drop", async (e) => {
            e.preventDefault();
            dragCounter = 0;
            dragDropOverlay?.classList.remove("active");

            if (!Drive.currentFolderName) {
                return ShowNotice("Please select or create a folder first before uploading files.", "Select Folder", "warning");
            }

            if (!e.dataTransfer) return;
            const files = Array.from(e.dataTransfer.files || []);
            if (files.length > 0) {
                const prepared = Drive.PrepareFiles(files);
                this.executeUpload(prepared);
            }
        });
    }

    // Execute upload workflow with conflict confirmation
    async executeUpload(files) {
        if (!files || files.length === 0) return;

        const confirmedFiles = [];
        for (const file of files) {
            if (Drive.flsMap[file.name]) {
                const overwrite = await ShowConfirmModal(
                    `File "${file.name}" already exists. Overwrite?`,
                    "File Exists",
                    "warning",
                    "Overwrite",
                    true
                );
                if (overwrite) confirmedFiles.push(file);
            } else {
                confirmedFiles.push(file);
            }
        }
        if (confirmedFiles.length === 0) return;

        try {
            await Drive.UploadFiles(confirmedFiles, {
                onStart: (fls) => this.showUploadProgressWidget(fls),
                onFileProgress: (idx, percent, total) => this.updateFileProgress(idx, percent, total),
                onFileComplete: (idx, name) => this.markFileUploaded(idx, name),
                onSyncing: () => this.setUploadSyncingState(),
                onComplete: () => {
                    this.markUploadComplete();
                    this.renderFiles(false);
                },
                onCancel: (idx) => this.markUploadCancelled(idx)
            });
        } catch (err) {
            ShowNotice("Upload failed: " + err.message, "Upload Error", "error");
        }
    }

    // Bind upload floating widget collapse and hover listeners
    bindUploadWidget() {
        const uploadProgressWidget = document.getElementById("uploadProgressWidget");
        const uploadWidgetHeader = document.getElementById("uploadWidgetHeader");
        const btnMinimizeUploadWidget = document.getElementById("btnMinimizeUploadWidget");
        const btnCloseUploadWidget = document.getElementById("btnCloseUploadWidget");
        const uploadWidgetChevron = document.getElementById("uploadWidgetChevron");
        const uploadWidgetBody = document.getElementById("uploadWidgetBody");

        const toggleCollapse = () => {
            if (!uploadWidgetBody) return;
            const collapsed = uploadWidgetBody.classList.toggle("collapsed");
            if (uploadWidgetChevron) {
                uploadWidgetChevron.textContent = collapsed ? "keyboard_arrow_up" : "keyboard_arrow_down";
            }
        };

        if (uploadWidgetHeader) {
            uploadWidgetHeader.addEventListener("click", (e) => {
                if (!e.target.closest("#btnCloseUploadWidget")) toggleCollapse();
            });
        }
        if (btnMinimizeUploadWidget) btnMinimizeUploadWidget.addEventListener("click", (e) => { e.stopPropagation(); toggleCollapse(); });
        if (btnCloseUploadWidget) {
            btnCloseUploadWidget.addEventListener("click", (e) => {
                e.stopPropagation();
                uploadProgressWidget?.classList.add("hidden");
                clearTimeout(this.uploadDismissTimer);
            });
        }

        if (uploadProgressWidget) {
            uploadProgressWidget.addEventListener("mouseenter", () => {
                this.isWidgetHovered = true;
                clearTimeout(this.uploadDismissTimer);
            });
            uploadProgressWidget.addEventListener("mouseleave", () => {
                this.isWidgetHovered = false;
                if (!Drive.isUploading && !uploadProgressWidget.classList.contains("hidden")) {
                    this.uploadDismissTimer = setTimeout(() => {
                        uploadProgressWidget.classList.add("hidden");
                    }, 4000);
                }
            });
        }
    }

    // Display floating upload progress widget
    showUploadProgressWidget(files) {
        clearTimeout(this.uploadDismissTimer);
        this.activeUploadFiles = files || [];
        const uploadProgressWidget = document.getElementById("uploadProgressWidget");
        const uploadWidgetTitle = document.getElementById("uploadWidgetTitle");
        const uploadFileList = document.getElementById("uploadFileList");
        const uploadWidgetBody = document.getElementById("uploadWidgetBody");
        const uploadWidgetChevron = document.getElementById("uploadWidgetChevron");

        if (uploadProgressWidget) {
            uploadProgressWidget.classList.remove("hidden");
            uploadProgressWidget.style.opacity = "1";
            uploadProgressWidget.style.transform = "translateY(0)";
        }
        if (uploadWidgetBody) uploadWidgetBody.classList.remove("collapsed");
        if (uploadWidgetChevron) uploadWidgetChevron.textContent = "keyboard_arrow_down";

        const count = this.activeUploadFiles.length;
        if (uploadWidgetTitle) uploadWidgetTitle.textContent = `Uploading ${count} ${count === 1 ? 'item' : 'items'}...`;

        if (uploadFileList) {
            uploadFileList.innerHTML = "";
            this.activeUploadFiles.forEach((f, idx) => {
                const info = GetGoogleFileIcon(f.name);
                const item = document.createElement("div");
                item.className = "upload-file-item";
                item.id = `uploadItem_${idx}`;
                item.dataset.fileName = f.name;
                item.innerHTML = `
                    <span class="material-symbols-outlined upload-item-type-icon" style="color: ${info.color};">${info.icon}</span>
                    <span class="upload-item-name" title="${EscapeHtml(f.name)}">${EscapeHtml(f.name)}</span>
                    <div class="upload-item-status" id="uploadItemStatus_${idx}">
                        ${idx === 0 ? this.createProgressRingHtml(idx, 0) : '<span class="material-symbols-outlined" style="font-size: 18px; color: var(--g-text-muted);">schedule</span>'}
                    </div>
                `;
                uploadFileList.appendChild(item);
            });
        }
    }

    // Render circular progress ring SVG button
    createProgressRingHtml(idx, percent = 0) {
        const offset = ringCircumference - (ringCircumference * Math.max(0, Math.min(100, percent)) / 100);
        return `
            <button type="button" class="upload-progress-btn" id="uploadProgressBtn_${idx}" title="Cancel upload">
                <svg class="progress-ring-svg" viewBox="0 0 24 24">
                    <circle class="progress-ring-bg" cx="12" cy="12" r="9"></circle>
                    <circle class="progress-ring-circle" cx="12" cy="12" r="9" style="stroke-dasharray: ${ringCircumference}; stroke-dashoffset: ${offset};"></circle>
                </svg>
                <span class="material-symbols-outlined progress-cancel-icon">close</span>
            </button>
        `;
    }

    // Update progress ring and status text for uploading item
    updateFileProgress(fileIdx, percent, totalFiles) {
        const total = totalFiles || this.activeUploadFiles.length || 1;
        const statusEl = document.getElementById(`uploadItemStatus_${fileIdx}`);
        if (statusEl) {
            if (percent >= 100) {
                statusEl.innerHTML = `<span class="material-symbols-outlined status-complete-icon">check_circle</span>`;
            } else {
                let circle = statusEl.querySelector(".progress-ring-circle");
                if (!circle) {
                    statusEl.innerHTML = this.createProgressRingHtml(fileIdx, percent);
                    circle = statusEl.querySelector(".progress-ring-circle");
                    statusEl.querySelector(".upload-progress-btn")?.addEventListener("click", (e) => {
                        e.stopPropagation();
                        Drive.CancelUpload(fileIdx);
                    });
                }
                if (circle) {
                    const offset = ringCircumference - (ringCircumference * Math.max(0, Math.min(100, percent)) / 100);
                    circle.style.strokeDashoffset = `${offset}`;
                }
            }
        }
        const uploadWidgetTitle = document.getElementById("uploadWidgetTitle");
        if (uploadWidgetTitle) {
            uploadWidgetTitle.textContent = `Uploading ${total} ${total === 1 ? 'item' : 'items'} (${fileIdx + 1}/${total})...`;
        }
    }

    // Mark single file status completed
    markFileUploaded(idx, name) {
        const statusEl = document.getElementById(`uploadItemStatus_${idx}`);
        if (statusEl) {
            statusEl.innerHTML = `<span class="material-symbols-outlined status-complete-icon">check_circle</span>`;
        }
    }

    // Update widget title to metadata sync phase
    setUploadSyncingState() {
        const uploadWidgetTitle = document.getElementById("uploadWidgetTitle");
        if (uploadWidgetTitle) uploadWidgetTitle.textContent = "Syncing with MediaHub...";
    }

    // Finalize upload widget state and schedule dismiss
    markUploadComplete() {
        const total = this.activeUploadFiles.length || 1;
        const uploadWidgetTitle = document.getElementById("uploadWidgetTitle");
        if (uploadWidgetTitle) uploadWidgetTitle.textContent = `${total} ${total === 1 ? 'upload' : 'uploads'} complete`;

        const uploadFileList = document.getElementById("uploadFileList");
        if (uploadFileList) {
            uploadFileList.querySelectorAll(".upload-file-item").forEach((item) => {
                const name = item.dataset.fileName;
                item.classList.add("completed");
                item.onclick = () => {
                    this.openFileInViewer(name);
                };
            });
        }

        clearTimeout(this.uploadDismissTimer);
        this.uploadDismissTimer = setTimeout(() => {
            if (!this.isWidgetHovered) {
                const widget = document.getElementById("uploadProgressWidget");
                if (widget) widget.classList.add("hidden");
            }
        }, 7000);
    }

    // Mark canceled status on upload item
    markUploadCancelled(fileIdx) {
        const uploadWidgetTitle = document.getElementById("uploadWidgetTitle");
        if (uploadWidgetTitle) uploadWidgetTitle.textContent = "Upload cancelled";
        if (fileIdx !== undefined && fileIdx >= 0) {
            const statusEl = document.getElementById(`uploadItemStatus_${fileIdx}`);
            if (statusEl) statusEl.innerHTML = `<span class="material-symbols-outlined" style="font-size: 20px; color: var(--g-text-muted);">block</span>`;
        }
    }

    // Mount drive view, load user catalog, and render folder or root
    async Mount(folderName = "") {
        this.init();
        this.syncUserProfileUI();
        await Drive.LoadUser();
        this.renderSidebarFolderList();

        if (!folderName) {
            Drive.SelectFolder("");
            this.updateFolderHeader("");
            this.renderRootFolderGrid();
        } else {
            const ok = await Drive.SelectFolder(folderName);
            if (!ok) {
                ShowNotice("Folder not found", "Notice", "warning");
                return AppRouter.Navigate('/drive');
            }
            this.updateFolderHeader(folderName);
            this.page = 1;
            await this.renderFiles(false);
        }
    }

    // Update breadcrumb and toolbar headers according to active folder
    updateFolderHeader(folderName) {
        const breadcrumbName = document.getElementById("breadcrumbFolderName");
        const breadcrumbSeparator = document.getElementById("breadcrumbSeparator");
        const folderTitle = document.getElementById("currentFolderTitle");
        const rootFolderView = document.getElementById("rootFolderView");
        const mediaContainer = document.getElementById("mediaContainer");
        const sidebarMyDriveHeader = document.getElementById("sidebarMyDriveHeader");
        const filterActionWrapper = document.getElementById("filterActionWrapper");
        const viewActionWrapper = document.getElementById("viewActionWrapper");
        const sortActionWrapper = document.getElementById("sortActionWrapper");
        const btnCurrentFolderMore = document.getElementById("btnCurrentFolderMore");

        if (folderName) {
            if (breadcrumbName) { breadcrumbName.textContent = folderName; breadcrumbName.style.display = "inline"; }
            if (breadcrumbSeparator) breadcrumbSeparator.style.display = "inline";
            if (folderTitle) folderTitle.textContent = folderName;
            if (rootFolderView) rootFolderView.style.display = "none";
            if (mediaContainer) mediaContainer.style.display = "flex";
            if (sidebarMyDriveHeader) sidebarMyDriveHeader.classList.remove("active");
            if (filterActionWrapper) filterActionWrapper.style.display = "";
            if (viewActionWrapper) viewActionWrapper.style.display = "";
            if (sortActionWrapper) sortActionWrapper.style.display = "";
            if (btnCurrentFolderMore) btnCurrentFolderMore.style.display = "inline-flex";

            document.querySelectorAll(".nav-folder-item").forEach(item => {
                item.classList.toggle("active", item.dataset.folderName === folderName);
            });
        } else {
            if (breadcrumbName) { breadcrumbName.textContent = ""; breadcrumbName.style.display = "none"; }
            if (breadcrumbSeparator) breadcrumbSeparator.style.display = "none";
            if (folderTitle) folderTitle.textContent = "My Drive";
            if (rootFolderView) rootFolderView.style.display = "flex";
            if (mediaContainer) mediaContainer.style.display = "none";
            if (sidebarMyDriveHeader) sidebarMyDriveHeader.classList.add("active");
            if (filterActionWrapper) filterActionWrapper.style.display = "none";
            if (viewActionWrapper) viewActionWrapper.style.display = "none";
            if (sortActionWrapper) sortActionWrapper.style.display = "none";
            if (btnCurrentFolderMore) btnCurrentFolderMore.style.display = "none";

            document.querySelectorAll(".nav-folder-item").forEach(item => {
                item.classList.remove("active");
            });
        }
    }

    // Render folder items in left navigation sidebar
    renderSidebarFolderList() {
        const sidebarFolderList = document.getElementById("sidebarFolderList");
        if (!sidebarFolderList) return;
        sidebarFolderList.innerHTML = "";

        const folders = Object.keys(Drive.fldMap);
        if (folders.length === 0) {
            sidebarFolderList.innerHTML = '<div style="padding: 10px 14px; font-size: 13px; color: var(--g-text-muted);">No folders</div>';
            return;
        }

        folders.forEach(name => {
            const item = document.createElement("div");
            item.className = "nav-folder-item" + (name === Drive.currentFolderName ? " active" : "");
            item.dataset.folderName = name;

            const iconSpan = document.createElement("span");
            iconSpan.className = "material-symbols-outlined nav-folder-icon";
            iconSpan.textContent = "folder";

            const nameSpan = document.createElement("span");
            nameSpan.className = "folder-name-label";
            nameSpan.textContent = name;
            nameSpan.title = name;

            const moreBtn = document.createElement("button");
            moreBtn.type = "button";
            moreBtn.className = "folder-more-btn";
            moreBtn.title = "More options";
            moreBtn.setAttribute("aria-label", "More options");
            moreBtn.innerHTML = '<span class="material-symbols-outlined">more_vert</span>';

            item.appendChild(iconSpan);
            item.appendChild(nameSpan);
            item.appendChild(moreBtn);

            item.addEventListener("click", async () => {
                if (window.innerWidth <= 768) {
                    document.querySelector(".drive-sidebar")?.classList.remove("mobile-open");
                    document.getElementById("sidebarBackdrop")?.classList.remove("active");
                }
                await this.Mount(name);
                await AppRouter.Navigate('/drive');
            });
            moreBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.openFolderContextMenu(e, name, moreBtn);
            });
            sidebarFolderList.appendChild(item);
        });
    }

    // Render root catalog folder grid and global search results
    async renderRootFolderGrid() {
        const rootFolderGrid = document.getElementById("rootFolderGrid");
        if (!rootFolderGrid) return;

        const searchInput = document.getElementById("topSearchInput");
        const query = (searchInput ? searchInput.value || "" : "").normalize('NFC').trim().toLowerCase();

        if (!query) {
            rootFolderGrid.innerHTML = "";
            const folders = Object.keys(Drive.fldMap);
            if (folders.length === 0) {
                rootFolderGrid.innerHTML = `
                    <div style="grid-column: 1 / -1; padding: 40px; text-align: center; color: var(--g-text-muted);">
                        <span class="material-symbols-outlined" style="font-size: 48px; margin-bottom: 8px;">folder_off</span>
                        <div style="font-size: 16px; font-weight: 500; color: var(--g-text-main); margin-bottom: 4px;">No folders created</div>
                        <div style="font-size: 13px;">Click "+ New" to create your first folder.</div>
                    </div>
                `;
                return;
            }

            folders.forEach(name => {
                const card = document.createElement("div");
                card.className = "root-folder-card";

                const icon = document.createElement("span");
                icon.className = "material-symbols-outlined";
                icon.textContent = "folder";

                const nameSpan = document.createElement("span");
                nameSpan.className = "root-folder-card-name";
                nameSpan.textContent = name;
                nameSpan.title = name;

                const moreBtn = document.createElement("button");
                moreBtn.type = "button";
                moreBtn.className = "folder-more-btn";
                moreBtn.title = "More options";
                moreBtn.setAttribute("aria-label", "More options");
                moreBtn.innerHTML = '<span class="material-symbols-outlined">more_vert</span>';

                card.appendChild(icon);
                card.appendChild(nameSpan);
                card.appendChild(moreBtn);

                card.addEventListener("click", async () => {
                    await this.Mount(name);
                    await AppRouter.Navigate('/drive');
                });
                moreBtn.addEventListener("click", (e) => {
                    e.stopPropagation();
                    this.openFolderContextMenu(e, name, moreBtn);
                });
                rootFolderGrid.appendChild(card);
            });
            return;
        }

        const thisReq = ++this.rootSearchCounter;
        rootFolderGrid.innerHTML = `
            <div style="grid-column: 1 / -1; padding: 36px 20px; text-align: center; color: var(--g-text-muted);">
                <div class="m3-circular-progress" style="width: 28px; height: 28px; margin: 0 auto 12px auto; border-width: 3px;"></div>
                <div style="font-size: 14px; color: var(--g-text-main);">Searching across all folders...</div>
            </div>
        `;

        const allFiles = await Drive.FetchAllFiles();
        if (thisReq !== this.rootSearchCounter) return;

        const folders = Object.keys(Drive.fldMap);
        const matchingFolders = folders.filter(f => f.normalize('NFC').toLowerCase().includes(query));
        const matchingFiles = allFiles.filter(f => f.fileName.normalize('NFC').toLowerCase().includes(query));

        if (matchingFolders.length === 0 && matchingFiles.length === 0) {
            rootFolderGrid.innerHTML = `
                <div style="grid-column: 1 / -1; padding: 48px 20px; text-align: center; color: var(--g-text-muted);">
                    <span class="material-symbols-outlined" style="font-size: 48px; margin-bottom: 8px; opacity: 0.6;">search_off</span>
                    <div style="font-size: 16px; font-weight: 500; color: var(--g-text-main); margin-bottom: 4px;">No matching results</div>
                    <div style="font-size: 13px;">No folders or files matching "${query}".</div>
                </div>
            `;
            return;
        }

        rootFolderGrid.innerHTML = "";

        if (matchingFolders.length > 0) {
            const h = document.createElement("div");
            h.className = "root-folder-header";
            h.style.gridColumn = "1 / -1";
            h.textContent = `Folders (${matchingFolders.length})`;
            rootFolderGrid.appendChild(h);

            matchingFolders.forEach(name => {
                const card = document.createElement("div");
                card.className = "root-folder-card";

                const icon = document.createElement("span");
                icon.className = "material-symbols-outlined";
                icon.textContent = "folder";

                const nameSpan = document.createElement("span");
                nameSpan.className = "root-folder-card-name";
                nameSpan.textContent = name;
                nameSpan.title = name;

                const moreBtn = document.createElement("button");
                moreBtn.type = "button";
                moreBtn.className = "folder-more-btn";
                moreBtn.title = "More options";
                moreBtn.innerHTML = '<span class="material-symbols-outlined">more_vert</span>';

                card.appendChild(icon);
                card.appendChild(nameSpan);
                card.appendChild(moreBtn);

                card.addEventListener("click", async () => {
                    await this.Mount(name);
                    await AppRouter.Navigate('/drive');
                });
                moreBtn.addEventListener("click", (e) => { e.stopPropagation(); this.openFolderContextMenu(e, name, moreBtn); });
                rootFolderGrid.appendChild(card);
            });
        }

        if (matchingFiles.length > 0) {
            const h = document.createElement("div");
            h.className = "root-folder-header";
            h.style.gridColumn = "1 / -1";
            h.style.margin = (matchingFolders.length > 0) ? "24px 0 4px 0" : "0 0 4px 0";
            h.textContent = `Files (${matchingFiles.length})`;
            rootFolderGrid.appendChild(h);

            const grid = document.createElement("div");
            grid.className = "media-grid";
            grid.style.gridColumn = "1 / -1";
            grid.style.width = "100%";

            matchingFiles.forEach(file => {
                const card = document.createElement("div");
                card.className = "media-card";
                const img = document.createElement("img");
                img.className = "thumb-img";
                img.alt = "Loading...";

                const rawFK = file.fileKey.slice();
                const fkSlice = rawFK.slice(0, 44);
                const ext = file.fileName.split('.').pop().toUpperCase();
                Drive.LoadThumbnail(file.folderId, GetObjPid(fkSlice), ext, img, fkSlice);

                const title = document.createElement("div");
                title.className = "file-title";
                title.textContent = file.fileName;

                const folderChip = document.createElement("div");
                folderChip.className = "file-folder-chip";
                folderChip.innerHTML = `<span class="material-symbols-outlined">folder</span><span>${EscapeHtml(file.folderName)}</span>`;

                card.appendChild(img);
                card.appendChild(title);
                card.appendChild(folderChip);

                card.addEventListener("click", () => {
                    this.openFileInViewer(file.fileName, file.fileKey, file.folderId, file.folderKey, file.folderName);
                });
                grid.appendChild(card);
            });
            rootFolderGrid.appendChild(grid);
        }
    }

    // Render paginated file cards for active folder
    async renderFiles(isAppend = false) {
        const grid = document.getElementById("mediaGrid");
        const emptyState = document.getElementById("emptyStateContainer");
        if (!grid) return;

        if (!isAppend) grid.innerHTML = "";

        let entries = Object.entries(Drive.flsMap);

        const searchInput = document.getElementById("topSearchInput");
        const query = (searchInput ? searchInput.value || "" : "").normalize('NFC').trim().toLowerCase();
        if (query) {
            entries = entries.filter(([name]) => name.normalize('NFC').toLowerCase().includes(query));
        }

        if (Drive.selectKeywords.size > 0) {
            if (!Drive.keywordsBuilt) Drive.BuildKeywords();
            entries = entries.filter(([name]) => {
                const tokens = Drive.tokenCache.get(name);
                if (!tokens) return false;
                for (const kw of Drive.selectKeywords) {
                    if (!tokens.has(kw)) return false;
                }
                return true;
            });
        }

        const sortMode = Drive.sortMode;
        if (sortMode === "name-desc") {
            entries.sort((a, b) => b[0].localeCompare(a[0], undefined, { numeric: true, sensitivity: 'base' }));
        } else if (sortMode === "size-asc") {
            entries.sort((a, b) => {
                const szA = Drive.GetEntrySize(a[1]);
                const szB = Drive.GetEntrySize(b[1]);
                return (szA - szB) || a[0].localeCompare(b[0], undefined, { numeric: true, sensitivity: 'base' });
            });
        } else if (sortMode === "size-desc") {
            entries.sort((a, b) => {
                const szA = Drive.GetEntrySize(a[1]);
                const szB = Drive.GetEntrySize(b[1]);
                return (szB - szA) || a[0].localeCompare(b[0], undefined, { numeric: true, sensitivity: 'base' });
            });
        } else {
            entries.sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true, sensitivity: 'base' }));
        }

        if (entries.length === 0) {
            if (emptyState) emptyState.style.display = "flex";
            const emptyTitle = document.getElementById("emptyStateTitle");
            const emptySubtitle = document.getElementById("emptyStateSubtitle");
            const emptyIcon = document.getElementById("emptyStateIcon");
            const emptyBtn = document.getElementById("btnEmptyUploadAction");

            if (query) {
                if (emptyIcon) emptyIcon.textContent = "search_off";
                if (emptyTitle) emptyTitle.textContent = "No matching files found";
                if (emptySubtitle) emptySubtitle.textContent = `No files matching "${query}".`;
                if (emptyBtn) emptyBtn.style.display = "none";
            } else if (Drive.selectKeywords.size > 0) {
                if (emptyIcon) emptyIcon.textContent = "filter_list_off";
                if (emptyTitle) emptyTitle.textContent = "No files match selected keywords";
                if (emptySubtitle) emptySubtitle.textContent = "Try unchecking some keywords or click clear to reset.";
                if (emptyBtn) {
                    emptyBtn.style.display = "inline-flex";
                    emptyBtn.innerHTML = `<span class="material-symbols-outlined">filter_alt_off</span><span>Clear filter</span>`;
                    emptyBtn.onclick = () => { Drive.selectKeywords.clear(); this.renderFiles(false); this.updateKeywordFilterUI(); };
                }
            } else {
                if (emptyIcon) emptyIcon.textContent = "cloud_upload";
                if (emptyTitle) emptyTitle.textContent = "This folder is empty";
                if (emptySubtitle) emptySubtitle.textContent = "Drag and drop files anywhere on the page, or use the upload button.";
                if (emptyBtn) {
                    emptyBtn.style.display = "inline-flex";
                    emptyBtn.innerHTML = `<span class="material-symbols-outlined">add</span><span>Upload</span>`;
                    emptyBtn.onclick = () => document.getElementById("fileInput")?.click();
                }
            }
            this.updateKeywordFilterUI();
            return;
        }

        if (emptyState) emptyState.style.display = "none";

        const start = isAppend ? (this.page - 1) * this.limit : 0;
        const end = Math.min(this.page * this.limit, entries.length);

        for (const [name, fileKey] of entries.slice(start, end)) {
            const card = document.createElement("div");
            card.className = "media-card";
            card.dataset.fileName = name;

            const img = document.createElement("img");
            img.className = "thumb-img";
            img.alt = "Loading...";

            const rawFK = fileKey.slice();
            const fkSlice = rawFK.slice(0, 44);
            const ext = name.split('.').pop().toUpperCase();
            Drive.LoadThumbnail(Drive.currentFolderId, GetObjPid(fkSlice), ext, img, fkSlice);

            const title = document.createElement("div");
            title.className = "file-title";
            title.textContent = name;
            title.title = name;

            const moreBtn = document.createElement("button");
            moreBtn.type = "button";
            moreBtn.className = "file-more-btn";
            moreBtn.title = "More options";
            moreBtn.innerHTML = '<span class="material-symbols-outlined">more_vert</span>';
            moreBtn.addEventListener("click", (e) => {
                e.stopPropagation();
                this.openFileContextMenu(e, name, moreBtn);
            });

            card.appendChild(img);
            card.appendChild(title);
            card.appendChild(moreBtn);

            card.addEventListener("click", () => {
                this.openFileInViewer(name);
            });

            grid.appendChild(card);
        }

        this.enhanceCardsForListView();
        this.updateKeywordFilterUI();
    }

    // Enhance grid cards with size and list layout columns
    async enhanceCardsForListView() {
        const mode = localStorage.getItem("driveViewMode");
        if (mode !== "details") return;
        const grid = document.getElementById("mediaGrid");
        const cards = grid?.querySelectorAll(".media-card");
        if (!cards || cards.length === 0) return;

        cards.forEach(card => {
            if (!card.dataset.enhanced) {
                card.dataset.enhanced = "true";
                const img = card.querySelector(".thumb-img");
                const title = card.querySelector(".file-title");
                const moreBtn = card.querySelector(".file-more-btn");

                const nameCol = document.createElement("div");
                nameCol.className = "list-col-name";
                if (img) nameCol.appendChild(img);
                if (title) nameCol.appendChild(title);
                card.appendChild(nameCol);

                const sizeCol = document.createElement("div");
                sizeCol.className = "list-col-size";
                sizeCol.textContent = "...";
                card.appendChild(sizeCol);

                const moreCol = document.createElement("div");
                moreCol.className = "list-col-more";
                if (moreBtn) moreCol.appendChild(moreBtn);
                card.appendChild(moreCol);
            }
        });

        const currentFolder = Drive.currentFolderName;
        if (currentFolder) {
            const sizes = await Drive.FetchFolderFileSizes(currentFolder);
            cards.forEach(card => {
                const titleEl = card.querySelector(".file-title");
                const sizeEl = card.querySelector(".list-col-size");
                if (titleEl && sizeEl) {
                    const fn = titleEl.textContent;
                    if (sizes && sizes[fn] !== undefined) {
                        sizeEl.textContent = FormatBytes(sizes[fn]);
                    } else {
                        sizeEl.textContent = "-";
                    }
                }
            });
        }
    }

    // Fetch next page when scrolling near bottom of grid
    handleInfiniteScroll() {
        if (this.isInfiniteLoading || !Drive.currentFolderName) return;
        const mediaContainer = document.getElementById("mediaContainer");
        const infiniteScrollLoader = document.getElementById("infiniteScrollLoader");
        if (!mediaContainer) return;

        const remaining = mediaContainer.scrollHeight - mediaContainer.scrollTop - mediaContainer.clientHeight;
        if (remaining <= 320) {
            const total = Object.keys(Drive.flsMap).length;
            const maxPage = Math.ceil(total / this.limit);
            if (this.page < maxPage) {
                this.isInfiniteLoading = true;
                if (infiniteScrollLoader) infiniteScrollLoader.style.display = "flex";
                this.page++;
                setTimeout(async () => {
                    await this.renderFiles(true);
                    this.isInfiniteLoading = false;
                    if (infiniteScrollLoader) infiniteScrollLoader.style.display = "none";
                }, 150);
            }
        }
    }

    // Render keyword items inside filter dropdown
    renderKeywordDropdownItems(filterQuery = "") {
        const keywordListContainer = document.getElementById("keywordListContainer");
        const keywordEmptyMessage = document.getElementById("keywordEmptyMessage");
        const keywordSearchWrap = document.getElementById("keywordSearchWrap");
        const btnClearAllKeywords = document.getElementById("btnClearAllKeywords");
        const filterMenuHeader = document.getElementById("filterMenuHeader");
        if (!keywordListContainer) return;

        const { availKeywords, keywordCounts, selectKeywords } = Drive;
        keywordListContainer.innerHTML = "";

        const query = (filterQuery || "").normalize('NFC').trim().toLowerCase();
        const filtered = availKeywords.filter(kw => !query || kw.normalize('NFC').toLowerCase().includes(query));

        if (keywordSearchWrap) {
            keywordSearchWrap.style.display = availKeywords.length >= 6 ? "block" : "none";
        }

        const hasSelected = selectKeywords.size > 0;
        if (btnClearAllKeywords) btnClearAllKeywords.style.display = hasSelected ? "inline-block" : "none";
        if (filterMenuHeader) filterMenuHeader.classList.toggle("has-clear", hasSelected);

        if (availKeywords.length === 0 || filtered.length === 0) {
            keywordListContainer.style.display = "none";
            if (keywordEmptyMessage) {
                keywordEmptyMessage.style.display = "block";
                keywordEmptyMessage.innerHTML = `<span class="material-symbols-outlined" style="font-size: 24px; margin-bottom: 4px; display: block; opacity: 0.6;">search_off</span><div style="font-size: 13px; font-weight: 500;">No keywords found</div>`;
            }
            return;
        }

        keywordListContainer.style.display = "flex";
        if (keywordEmptyMessage) keywordEmptyMessage.style.display = "none";

        filtered.forEach(kw => {
            const isChecked = selectKeywords.has(kw);
            const count = keywordCounts[kw] || 0;
            const item = document.createElement("div");
            item.className = "filter-menu-item" + (isChecked ? " active" : "");
            item.innerHTML = `
                <div class="filter-item-left">
                    <input type="checkbox" class="filter-item-checkbox" ${isChecked ? "checked" : ""}>
                    <span class="filter-item-name">${EscapeHtml(kw)}</span>
                </div>
                <span class="filter-item-count">${count}</span>
            `;
            const chk = item.querySelector(".filter-item-checkbox");
            item.addEventListener("click", (e) => {
                if (e.target !== chk) chk.checked = !chk.checked;
                if (Drive.selectKeywords.has(kw)) Drive.selectKeywords.delete(kw);
                else Drive.selectKeywords.add(kw);
                this.page = 1;
                this.renderFiles(false);
                this.updateKeywordFilterUI();
            });
            keywordListContainer.appendChild(item);
        });
    }

    // Update active keyword filter chips bar
    updateKeywordFilterUI() {
        const btnKeywordFilter = document.getElementById("btnKeywordFilter");
        const filterCountBadge = document.getElementById("filterCountBadge");
        const activeFilterChipsBar = document.getElementById("activeFilterChipsBar");
        const activeChipsList = document.getElementById("activeChipsList");

        const count = Drive.selectKeywords.size;
        if (btnKeywordFilter) btnKeywordFilter.classList.toggle("active-filter", count > 0);
        if (filterCountBadge) {
            filterCountBadge.style.display = count > 0 ? "inline-flex" : "none";
            filterCountBadge.textContent = count;
        }

        if (activeFilterChipsBar && activeChipsList) {
            if (count > 0) {
                activeFilterChipsBar.style.display = "flex";
                activeChipsList.innerHTML = "";
                Drive.selectKeywords.forEach(kw => {
                    const chip = document.createElement("span");
                    chip.className = "filter-chip";
                    chip.innerHTML = `<span>${EscapeHtml(kw)}</span><button type="button" class="chip-remove-btn"><span class="material-symbols-outlined" style="font-size: 14px;">close</span></button>`;
                    chip.querySelector(".chip-remove-btn").addEventListener("click", (e) => {
                        e.stopPropagation();
                        Drive.selectKeywords.delete(kw);
                        this.page = 1;
                        this.renderFiles(false);
                        this.updateKeywordFilterUI();
                    });
                    activeChipsList.appendChild(chip);
                });
            } else {
                activeFilterChipsBar.style.display = "none";
                activeChipsList.innerHTML = "";
            }
        }
    }

    // Save active file credentials to session and open viewer route
    openFileInViewer(name, customFlKey, customFldId, customFldKey, customFldName) {
        let fldId = customFldId || Drive.currentFolderId;
        let fldName = customFldName || Drive.currentFolderName;
        let fldKey = customFldKey || Drive.currentFolderKey;
        let flKey = customFlKey || Drive.flsMap[name];

        if (!flKey || !fldId || !fldKey) return;

        const rawFK = Drive.UnmaskKey(flKey);
        const rawFldK = Drive.UnmaskKey(fldKey);

        SafeSession.SetItem("currentFileName", name);
        SafeSession.SetItem("currentFileKey", ToHex(rawFK));
        SafeSession.SetItem("currentFolderId", fldId);
        SafeSession.SetItem("currentFolderKey", ToHex(rawFldK));
        SafeSession.SetItem("oldFold", fldName);
        rawFK.fill(0);
        rawFldK.fill(0);
        SafeSession.Save();

        AppRouter.Navigate('/viewer');
    }

    // Locate file by PID and open in viewer
    async OpenFileByPid(filePid) {
        if (!filePid || !Drive.currentFolderId) return false;
        for (const [name, key] of Object.entries(Drive.flsMap)) {
            const rawFK = Drive.UnmaskKey(key);
            const pid = GetObjPid(rawFK.slice(0, 44));
            rawFK.fill(0);
            if (pid === filePid) {
                this.openFileInViewer(name);
                return true;
            }
        }
        return false;
    }

    // Generate deep link for file and copy to clipboard
    async shareFile(name) {
        const fileKey = Drive.flsMap[name];
        if (!fileKey || !Drive.currentFolderId) return;
        const rawFK = Drive.UnmaskKey(fileKey);
        const pid = GetObjPid(rawFK.slice(0, 44));
        rawFK.fill(0);

        const url = `${window.location.origin}/drive?f=${encodeURIComponent(Drive.currentFolderId)}&p=${encodeURIComponent(pid)}`;
        try {
            await navigator.clipboard.writeText(url);
            ShowNotice("Deep link copied to clipboard.", "Share", "check_circle");
        } catch {
            prompt("Copy link:", url);
        }
    }

    // Trigger file download via viewer helper
    async downloadFile(name) {
        ShowNotice(`Preparing download for "${name}"...`, "Downloading", "download");
        const fileKey = Drive.flsMap[name];
        if (!fileKey) return;
        this.openFileInViewer(name);
    }

    // Delete file and refresh grid
    async deleteFile(name) {
        const ok = await ShowConfirmModal(
            `Are you sure you want to delete "<strong>${EscapeHtml(name)}</strong>"?`,
            "Delete file?",
            "delete",
            "Delete",
            true
        );
        if (!ok) return;
        try {
            await Drive.DeleteFile(name);
            this.renderFiles(false);
            ShowNotice(`Deleted "${name}"`, "Success", "check_circle");
        } catch (err) {
            ShowNotice("Delete failed: " + err.message, "Error", "error");
        }
    }

    // Update avatar and username display in header and account menu
    syncUserProfileUI() {
        const username = SafeSession.GetItem("username") || "User";
        const usrHsh = SafeSession.GetItem("userHash") || "";
        const initial = (username.slice(0, 2) || "TE").toUpperCase();

        const headerAvatar = document.getElementById("headerAvatar");
        const menuLargeAvatar = document.getElementById("menuLargeAvatar");
        const menuUsername = document.getElementById("menuUsername");
        const menuUserHashShort = document.getElementById("menuUserHashShort");

        if (headerAvatar) headerAvatar.textContent = initial;
        if (menuLargeAvatar) menuLargeAvatar.textContent = initial;
        if (menuUsername) menuUsername.textContent = username;
        if (menuUserHashShort) {
            menuUserHashShort.textContent = usrHsh ? `ID: ${usrHsh.slice(0, 8)}...${usrHsh.slice(-4)}` : "E2EE Account";
        }
    }
}

// Global drive view instance
export const DriveView = new DriveViewService();
