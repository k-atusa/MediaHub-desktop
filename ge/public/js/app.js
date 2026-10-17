// Single page application entry point and routing orchestration
import { AppRouter } from './core/router.js';
import { Drive } from './core/drive.js';
import { LoginView } from './views/login.js';
import { DriveView } from './views/drive.js';
import { ViewerView } from './views/viewer.js';
import { SafeSession, ShowNotice, ShowAlert, DisableAllAutocomplete, GetObjPid } from './core/utils.js';

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
    await SafeSession.Init();
    await Drive.InitSession();

    const savedTheme = localStorage.getItem('theme') || 'system';
    if (savedTheme === 'dark' || savedTheme === 'light') {
        document.documentElement.setAttribute('data-theme', savedTheme);
    } else {
        document.documentElement.removeAttribute('data-theme');
    }

    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
        if ((localStorage.getItem("theme") || "system") === "system") {
            DriveView.UpdateThemeUI();
        }
    });

    AppRouter.BeforeEach(async (path) => {
        const isAuth = Boolean(SafeSession.GetItem("userHash") && SafeSession.GetItem("userKey"));

        if (!isAuth && path !== '/login') {
            const redirectUrl = window.location.pathname + window.location.search;
            SafeSession.SetItem("redirectAfterLogin", redirectUrl);
            return '/login';
        }

        if (isAuth && path === '/login') {
            return '/drive';
        }

        return null;
    });

    AppRouter.On('/login', async () => {
        activateView('view-login');
        await LoginView.Mount();
    });

    AppRouter.On('/drive', async ({ query }) => {
        activateView('view-drive');

        let targetFolderName = "";
        const fldPid = query.f;
        const filePid = query.p;

        if (fldPid) {
            for (const [name, key] of Object.entries(Drive.fldMap)) {
                const raw = Drive.UnmaskKey(key);
                if (GetObjPid(raw) === fldPid) {
                    targetFolderName = name;
                    raw.fill(0);
                    break;
                }
                raw.fill(0);
            }
        }

        await DriveView.Mount(targetFolderName);

        if (filePid && targetFolderName) {
            const opened = await DriveView.OpenFileByPid(filePid);
            if (opened) {
                await AppRouter.Replace('/viewer');
                return;
            }
        }

        if (fldPid || filePid) {
            window.history.replaceState(null, '', '/drive');
        }
    });

    AppRouter.On('/viewer', async ({ query }) => {
        activateView('view-viewer');

        if (query.f || query.p) {
            await ViewerView.MountWithQuery(query);
            window.history.replaceState(null, '', '/viewer');
            return;
        }

        await ViewerView.Mount();
    });

    DisableAllAutocomplete();
    await AppRouter.Init();
}

if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', bootstrap);
} else {
    bootstrap();
}
