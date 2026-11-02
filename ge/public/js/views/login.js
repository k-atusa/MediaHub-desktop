// Login & Registration view controller
import { AppRouter } from '../core/router.js';
import { SafeSession, ShowNotice, ToHex } from '../core/utils.js';
import { Drive } from '../core/drive.js';
import { Adapter } from '../core/adapter.js';

// Login & Registration view controller
class LoginViewService {
    // --------------------------------------------------
    // 01. Lifecycle & Initialization
    // --------------------------------------------------

    // Initialize container reference and event flag
    constructor() {
        this.container = document.getElementById('view-login');
        this.initialized = false;
    }

    // Attach click and enter key handlers
    init() {
        if (this.initialized) return;
        this.initialized = true;

        const btnLogin = document.getElementById("btnLogin");
        const btnRegister = document.getElementById("btnRegister");
        const usernameInput = document.getElementById("username");
        const passwordInput = document.getElementById("password");

        // Bind buttons and input events
        if (btnLogin) {
            btnLogin.addEventListener("click", () => this.handleLogin());
        }
        if (btnRegister) {
            btnRegister.addEventListener("click", () => this.handleRegister());
        }
        if (usernameInput) {
            usernameInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") btnLogin?.click();
            });
        }
        if (passwordInput) {
            passwordInput.addEventListener("keydown", (e) => {
                if (e.key === "Enter") btnLogin?.click();
            });
        }

        // Bind other buttons events
        const btnLoginNotice = document.getElementById("btnLoginNotice");
        if (btnLoginNotice) {
            btnLoginNotice.addEventListener("click", () => this.showNoticePopup());
        }
        const btnAppInfo = document.getElementById("btnAppInfo");
        if (btnAppInfo) {
            btnAppInfo.addEventListener("click", () => Adapter.ShowAppInfo());
        }
        const btnThemeToggle = document.getElementById("btnThemeToggle");
        if (btnThemeToggle) {
            btnThemeToggle.addEventListener("click", () => this.toggleTheme());
        }
    }

    // --------------------------------------------------
    // 02. Main Event Handlers
    // --------------------------------------------------

    // Authenticate user credentials and sign in
    async handleLogin() {
        const username = document.getElementById("username")?.value.trim() || "";
        const password = document.getElementById("password")?.value || "";
        if (!username || !password) { // no username or password
            await ShowNotice("Please fill in all fields.", "Notice", "warning");
            return;
        }

        // Set login button to loading state
        const btnLogin = document.getElementById("btnLogin");
        const origText = btnLogin ? btnLogin.textContent : "";
        if (btnLogin) {
            btnLogin.disabled = true;
            btnLogin.textContent = "Signing in...";
        }

        try { // derive user keys
            const { userHash, maskedKey } = await Adapter.DeriveKeys(username, password);
            const exists = await Adapter.CheckUserExists(userHash);
            if (!exists) { // no user
                await ShowNotice("Invalid username or password.", "Login Failed", "error");
                return;
            }
            await this.setSession(userHash, maskedKey, username);
            await Adapter.SaveCredentials(username, password);
        } catch (err) { // error
            await ShowNotice("Login failed: " + (err.message || "Unknown error"), "Login Failed", "error");
        } finally { // reset loading state
            if (btnLogin) {
                btnLogin.disabled = false;
                btnLogin.textContent = origText;
            }
        }
    }

    // Handle registration dialog and account creation
    async handleRegister() {
        const username = document.getElementById("username")?.value.trim() || "";
        const password = document.getElementById("password")?.value || "";
        if (!username || !password) { // no username or password
            await ShowNotice("Please fill in all fields.", "Notice", "warning");
            return;
        }

        try { // derive user keys
            const { userHash, maskedKey } = await Adapter.DeriveKeys(username, password);
            const exists = await Adapter.CheckUserExists(userHash);
            if (exists) { // already registered
                await ShowNotice("This account is already registered.", "Already Registered", "warning");
                return;
            }

            // Get invite code
            const inviteModal = document.getElementById("inviteModal");
            const inviteCodeInput = document.getElementById("inviteCodeInput");
            if (!inviteModal || !inviteCodeInput) return;

            inviteCodeInput.value = "";
            inviteModal.showModal();
            inviteCodeInput.focus();

            // Submit invite code
            const submitInvite = async () => {
                const inviteCode = inviteCodeInput.value.trim();
                inviteModal.close();
                try {
                    await Adapter.RegisterUser(userHash, inviteCode);
                    await ShowNotice("Account registered successfully.", "Success", "check_circle");
                    await this.setSession(userHash, maskedKey, username);
                } catch (err) {
                    await ShowNotice("Registration failed: " + (err.message || "Unknown error"), "Registration Failed", "error");
                }
            };

            // Submit and cancel event handlers
            document.getElementById("btnConfirmInvite").onclick = submitInvite;
            inviteCodeInput.onkeydown = (e) => {
                if (e.key === "Enter") {
                    e.preventDefault();
                    submitInvite();
                }
            };
            document.getElementById("btnCancelInvite").onclick = () => {
                inviteModal.close();
            };
        } catch (err) { // error
            await ShowNotice("Registration failed: " + (err.message || "Unknown error"), "Registration Failed", "error");
        }
    }

    // --------------------------------------------------
    // 03. State Management & Navigation
    // --------------------------------------------------

    // Persist session tokens and redirect to target route
    async setSession(userHash, maskedKey, username) {
        const rawUk = Drive.UnmaskKey(maskedKey);
        const redirectUrl = SafeSession.GetItem("redirectAfterLogin");

        SafeSession.Clear();
        SafeSession.SetItem("userHash", userHash);
        SafeSession.SetItem("userKey", ToHex(rawUk));
        SafeSession.SetItem("username", username);
        rawUk.fill(0);

        await SafeSession.Save(); // save to session
        await Drive.InitSession();

        if (redirectUrl) { // redirect to target route
            SafeSession.RemoveItem("redirectAfterLogin");
            await AppRouter.Navigate(redirectUrl);
        } else { // default route
            await AppRouter.Navigate('/drive');
        }
    }

    // Display server notice dialog manually when notice button is clicked
    async showNoticePopup() {
        try {
            const notice = await Adapter.FetchNotice();
            if (notice && notice.trim() !== "") { // has notice
                await ShowNotice(notice, "Notice", "campaign");
            } else { // no notice
                await ShowNotice("There are no active notices.", "Notice", "campaign");
            }
        } catch (err) { // error
            await ShowNotice("Failed to load notice: " + (err.message || "Unknown error"), "Notice", "campaign");
        }
    }

    // Toggle theme mode from login view
    toggleTheme() {
        const current = localStorage.getItem("theme") || "system";
        const next = current === "system" ? "dark" : (current === "dark" ? "light" : "system");
        if (next === "system") {
            localStorage.setItem("theme", "system");
            document.documentElement.removeAttribute("data-theme");
        } else {
            localStorage.setItem("theme", next);
            document.documentElement.setAttribute("data-theme", next);
        }
        this.UpdateThemeUI();
    }

    // Synchronize login view theme toggle icon
    UpdateThemeUI() {
        const mode = localStorage.getItem("theme") || "system";
        const iconEl = document.getElementById("themeToggleIcon");
        if (!iconEl) return;
        if (mode === "dark") {
            iconEl.textContent = "dark_mode";
            iconEl.parentElement?.setAttribute("title", "Theme: Dark");
        } else if (mode === "light") {
            iconEl.textContent = "light_mode";
            iconEl.parentElement?.setAttribute("title", "Theme: Light");
        } else {
            iconEl.textContent = "brightness_auto";
            iconEl.parentElement?.setAttribute("title", "Theme: System (Auto)");
        }
    }

    // Mount view and restore saved credentials
    async Mount() {
        this.init();
        this.UpdateThemeUI();
        const creds = await Adapter.GetSavedCredentials();
        if (creds && creds.username && creds.password) { // restore saved credentials
            const userInput = document.getElementById("username");
            const pwdInput = document.getElementById("password");
            if (userInput) userInput.value = creds.username;
            if (pwdInput) pwdInput.value = creds.password;
        } else { // clear password
            const pwdInput = document.getElementById("password");
            if (pwdInput) pwdInput.value = "";
        }
    }
}

// Global login view instance
export const LoginView = new LoginViewService();
