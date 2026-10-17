// User authentication and account registration view controller
import { AppRouter } from '../core/router.js';
import { SafeSession, ShowNotice, ToHex } from '../core/utils.js';
import { Drive } from '../core/drive.js';
import { Adapter } from '../core/adapter.js';

// Authentication view controller
class LoginViewService {
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
    }

    // Persist session tokens and redirect to target route
    async setSession(userHash, maskedKey, username) {
        const rawUk = Drive.UnmaskKey(maskedKey);
        const redirectUrl = SafeSession.GetItem("redirectAfterLogin");

        SafeSession.Clear();
        SafeSession.SetItem("userHash", userHash);
        SafeSession.SetItem("userKey", ToHex(rawUk));
        SafeSession.SetItem("username", username);
        rawUk.fill(0);

        await SafeSession.Save();
        await Drive.InitSession();

        if (redirectUrl) {
            SafeSession.RemoveItem("redirectAfterLogin");
            await AppRouter.Navigate(redirectUrl);
        } else {
            await AppRouter.Navigate('/drive');
        }
    }

    // Authenticate user credentials and sign in
    async handleLogin() {
        const username = document.getElementById("username")?.value.trim() || "";
        const password = document.getElementById("password")?.value || "";

        if (!username || !password) {
            await ShowNotice("Please fill in all fields.", "Notice", "warning");
            return;
        }

        const btnLogin = document.getElementById("btnLogin");
        const origText = btnLogin ? btnLogin.textContent : "";
        if (btnLogin) {
            btnLogin.disabled = true;
            btnLogin.textContent = "Signing in...";
        }

        try {
            const { userHash, maskedKey } = await Adapter.DeriveKeys(username, password);

            const exists = await Adapter.CheckUserExists(userHash);
            if (!exists) {
                await ShowNotice("Invalid username or password.", "Login Failed", "error");
                return;
            }

            await this.setSession(userHash, maskedKey, username);
            await Adapter.SaveCredentials(username, password);
        } catch (err) {
            await ShowNotice("Login failed: " + (err.message || "Unknown error"), "Login Failed", "error");
        } finally {
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

        if (!username || !password) {
            await ShowNotice("Please fill in all fields.", "Notice", "warning");
            return;
        }

        try {
            const { userHash, maskedKey } = await Adapter.DeriveKeys(username, password);

            const exists = await Adapter.CheckUserExists(userHash);
            if (exists) {
                await ShowNotice("This account is already registered.", "Already Registered", "warning");
                return;
            }

            const inviteModal = document.getElementById("inviteModal");
            const inviteCodeInput = document.getElementById("inviteCodeInput");
            if (!inviteModal || !inviteCodeInput) return;

            inviteCodeInput.value = "";
            inviteModal.showModal();
            inviteCodeInput.focus();

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
        } catch (err) {
            await ShowNotice("Registration failed: " + (err.message || "Unknown error"), "Registration Failed", "error");
        }
    }

    // Check server notification and show modal if unread
    async checkNotice() {
        try {
            const notice = await Adapter.FetchNotice();
            if (notice && notice.trim() !== "" && !SafeSession.GetItem("noticeShown")) {
                await ShowNotice(notice, "Notice", "campaign");
                SafeSession.SetItem("noticeShown", "true");
            }
        } catch (err) {
            console.error("Failed to load notice:", err);
        }
    }

    // Mount view and restore saved credentials
    async Mount() {
        this.init();
        const creds = await Adapter.GetSavedCredentials();
        if (creds && creds.username && creds.password) {
            const userInput = document.getElementById("username");
            const pwdInput = document.getElementById("password");
            if (userInput) userInput.value = creds.username;
            if (pwdInput) pwdInput.value = creds.password;
        } else {
            const pwdInput = document.getElementById("password");
            if (pwdInput) pwdInput.value = "";
        }
        this.checkNotice();
    }
}

// Global login view instance
export const LoginView = new LoginViewService();
