// History API SPA client router
export class Router {
    // Initialize router instance and bind popstate event
    constructor() {
        this.routes = [];
        this.beforeHooks = [];
        this.currentPath = '';
        this.isNavigating = false;

        window.addEventListener('popstate', () => this.handleRoute());
    }

    // Register navigation guard hook
    BeforeEach(hook) {
        this.beforeHooks.push(hook);
    }

    // Register route handler pattern
    On(pattern, handler) {
        const paramNames = [];
        const regexStr = pattern.replace(/:([a-zA-Z0-9_]+)/g, (match, paramName) => {
            paramNames.push(paramName);
            return '([^/?]+)';
        });
        const regex = new RegExp(`^${regexStr}$`);
        this.routes.push({ pattern, regex, paramNames, handler });
        return this;
    }

    // Parse current window path and query parameters
    ParseUrl() {
        let path = window.location.pathname;
        if (!path || path === '/') {
            path = '/drive';
        }

        const query = {};
        const search = window.location.search;
        if (search) {
            new URLSearchParams(search.slice(1)).forEach((val, key) => {
                query[key] = val;
            });
        }
        return { path, query, fullPath: path + search };
    }

    // Navigate to path and update browser history
    async Navigate(targetUrl, replace = false) {
        let url = targetUrl;
        if (url.startsWith('#')) url = url.slice(1);
        if (!url.startsWith('/')) url = '/' + url;

        const current = window.location.pathname + window.location.search;
        if (current !== url) {
            if (replace) {
                window.history.replaceState(null, '', url);
            } else {
                window.history.pushState(null, '', url);
            }
        }
        await this.handleRoute();
    }

    // Replace current path without creating history entry
    async Replace(targetUrl) {
        return this.Navigate(targetUrl, true);
    }

    // Execute route match and trigger navigation guards
    async handleRoute() {
        if (this.isNavigating) return;
        this.isNavigating = true;

        try {
            const { path, query } = this.ParseUrl();

            for (const hook of this.beforeHooks) {
                const redirect = await hook(path, query);
                if (redirect && redirect !== path) {
                    this.isNavigating = false;
                    return this.Navigate(redirect);
                }
            }

            this.currentPath = path;

            let matched = false;
            for (const route of this.routes) {
                const match = path.match(route.regex);
                if (match) {
                    matched = true;
                    const params = {};
                    route.paramNames.forEach((name, idx) => {
                        params[name] = decodeURIComponent(match[idx + 1] || '');
                    });
                    await route.handler({ params, query, path });
                    break;
                }
            }

            if (!matched && path !== '/drive') {
                return this.Navigate('/drive', true);
            }
        } finally {
            this.isNavigating = false;
        }
    }

    // Start router on initial page load
    Init() {
        return this.handleRoute();
    }
}

// Global router singleton instance
export const AppRouter = new Router();
