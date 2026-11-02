// SPA entry point & routing orchestration
import { AppRouter } from './core/router.js';
import { Drive } from './core/drive.js';
import { LoginView } from './views/login.js';
import { DriveView } from './views/drive.js';
import { ViewerView } from './views/viewer.js';
import { SafeSession, ShowAlert, DisableAllAutocomplete, GetObjPid, setSessionAdapter } from './core/utils.js';
import { Adapter } from './core/adapter.js';

window.alert = ShowAlert;
window.cancelUpload = (idx) => Drive.CancelUpload(idx);

// Toggle visibility of target view container
function activateView(viewId) {
    document.querySelectorAll('.view-container').forEach(el => {
        el.classList.remove('active');
    });
    const target = document.getElementById(viewId);
    if (target) {
        target.classList.add('active');
    }
}

// Bootstrap application, session state, and route handlers
async function bootstrap() {
    // Inject adapter into session manager (breaks circular dependency)
    setSessionAdapter(Adapter);
    await SafeSession.Init();
    await Drive.InitSession();

    // Set theme and changing logic
    const savedTheme = localStorage.getItem('theme') || 'system';
    if (savedTheme === 'dark' || savedTheme === 'light') {
        document.documentElement.setAttribute('data-theme', savedTheme);
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
        if ((localStorage.getItem("theme") || "system") === "system") {
            DriveView.UpdateThemeUI();
            LoginView.UpdateThemeUI();
        }
    });

    // Register ServiceWorker
    if ('serviceWorker' in navigator) {
        if (Adapter.RequiresServiceWorker) {
            navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(err => { console.warn('[App] ServiceWorker registration failed:', err); });
        } else {
            navigator.serviceWorker.getRegistrations()
                .then(regs => Promise.all(regs.filter(r =>
                    new URL(r.scope).origin === window.location.origin &&
                    new URL(r.scope).pathname === '/'
                ).map(r => r.unregister())))
                .catch(err => console.warn('[App] Old ServiceWorker cleanup failed:', err));
        }
    }

    // Route guards
    AppRouter.BeforeEach(async (path, query) => {
        // Stop audio/video playback
        if (AppRouter.currentPath === '/viewer' && path !== '/viewer') {
            ViewerView.CleanupCurrentMedia();
        }

        // Check if session is authenticated
        const isAuth = Boolean(SafeSession.GetItem("userHash") && SafeSession.GetItem("userKey"));

        // Allow public access if Adapter allows
        const isPublic = (typeof Adapter.IsPublicRoute === 'function') ? await Adapter.IsPublicRoute(path, query) : Boolean(query?.s);

        // Redirect to login if not authenticated
        if (!isAuth && !isPublic && path !== '/login') {
            const redirectUrl = window.location.pathname + window.location.search;
            SafeSession.SetItem("redirectAfterLogin", redirectUrl);
            return '/login';
        }
        if (isAuth && path === '/login') {
            return '/drive';
        }
        return null;
    });

    // Login page
    AppRouter.On('/login', async () => {
        activateView('view-login');
        await LoginView.Mount();
    });

    // Drive page
    AppRouter.On('/drive', async ({ query }) => {
        // Check if direct file share
        const fldPid = query.f;
        const filePid = query.p;
        if (filePid && fldPid) {
            await AppRouter.Replace(`/viewer?f=${encodeURIComponent(fldPid)}&p=${encodeURIComponent(filePid)}`);
            return;
        }
        activateView('view-drive');

        // Try to find folder name to open
        let targetFolderName = "";
        if (fldPid) { // get from url PID
            await Drive.LoadUser();
            for (const [name, key] of Object.entries(Drive.fldMap)) {
                const raw = Drive.UnmaskKey(key);
                if (GetObjPid(raw) === fldPid) {
                    targetFolderName = name;
                    raw.fill(0);
                    break;
                }
                raw.fill(0);
            }
        } else if (Drive.currentFolderName) { // get from session
            targetFolderName = Drive.currentFolderName;
        } else { // get from history
            const savedFold = SafeSession.GetItem("oldFold");
            if (savedFold) {
                targetFolderName = savedFold;
            }
        }

        // Mount folder and open file
        await DriveView.Mount(targetFolderName);
        if (filePid && targetFolderName) { // get from url PID
            const opened = await DriveView.OpenFileByPid(filePid);
            if (opened) {
                await AppRouter.Replace('/viewer');
                return;
            }
        }

        // Trim url after auto-open
        if (fldPid || filePid) {
            window.history.replaceState(null, '', '/drive');
        }
    });

    // Viewer page
    AppRouter.On('/viewer', async ({ query }) => {
        activateView('view-viewer');
        if (query.f || query.p || query.s) { // mount if url param exists
            await ViewerView.MountWithQuery(query);
            window.history.replaceState(null, '', '/viewer');
            return;
        }
        await ViewerView.Mount();
    });

    // Initialize router
    DisableAllAutocomplete();
    await AppRouter.Init();
    document.body.classList.add('app-ready');
    document.documentElement.classList.remove('boot-pending');
}

// Bootstrap after DOM is loaded
if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', bootstrap);
} else {
    bootstrap();
}
