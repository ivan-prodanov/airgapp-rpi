const api = {
    async request(method, url, body) {
        const opts = {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin'
        };
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(url, opts);
        if (res.status === 401) {
            window.location = '/login';
            throw new Error('unauthorized');
        }
        // Tolerate an empty body (204 No Content, e.g. DELETE/logout/reboot):
        // calling res.json() on it throws "Unexpected end of JSON input", which
        // used to blow up the caller — a successful DELETE then looked like a
        // no-op because loadTokens() never ran. Parse only when there's a body.
        const text = await res.text();
        let data = null;
        if (text) {
            try { data = JSON.parse(text); } catch { data = null; }
        }
        if (!res.ok) {
            notify((data && data.error) || 'Request failed', 'error');
            throw new Error((data && data.error) || 'Request failed');
        }
        return data;
    },
    get:    (url)       => api.request('GET', url),
    post:   (url, data) => api.request('POST', url, data),
    put:    (url, data) => api.request('PUT', url, data),
    delete: (url)       => api.request('DELETE', url),
};

// One toast at a time, bottom centre. opts.undo adds an Undo button; the toast
// stays 7s with Undo and 4s without (opts.ms overrides), then leaves through a
// 150ms exit animation (.out) instead of vanishing.
let toastTimer = 0;
function notify(msg, type = 'info', opts = {}) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    clearTimeout(toastTimer);
    container.replaceChildren();

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    const text = document.createElement('span');
    text.className = 'toast-t';
    text.textContent = msg;
    toast.append(text);

    const dismiss = () => {
        if (toast.classList.contains('out')) return;
        toast.classList.add('out');
        setTimeout(() => toast.remove(), 150);
    };
    if (typeof opts.undo === 'function') {
        const undo = document.createElement('button');
        undo.type = 'button';
        undo.textContent = 'Undo';
        undo.addEventListener('click', () => {
            clearTimeout(toastTimer);
            opts.undo();
            dismiss();
        });
        toast.append(undo);
    }
    container.append(toast);
    toastTimer = setTimeout(dismiss, opts.ms ?? (opts.undo ? 7000 : 4000));
}

async function logout() {
    await api.post('/api/logout');
    window.location = '/login';
}

function formatBytes(bytes) {
    bytes = parseInt(bytes) || 0;
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatUptime(seconds) {
    seconds = parseFloat(seconds) || 0;
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
}
