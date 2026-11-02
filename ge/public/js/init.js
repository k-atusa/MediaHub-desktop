// Inline scripts (CSP configure)
(function () {
    const saved = localStorage.getItem('theme') || 'system';
    if (saved === 'dark' || saved === 'light') {
        document.documentElement.setAttribute('data-theme', saved);
    } else {
        document.documentElement.removeAttribute('data-theme');
    }
})();