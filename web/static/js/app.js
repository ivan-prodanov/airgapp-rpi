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

// One page. The top bar never reloads: following a link to another console page
// fetches that page, runs its script, and swaps only the content under the bar,
// once the new page has its first data (or after READY_MS), with a short
// cross-fade where the browser has view transitions. Every page is still served
// at its own address, so reload, bookmarks, a new tab and Back/Forward work as
// before; anything unexpected (signed out, a server error) falls back to a full load.
const nav = (() => {
    const PAGES = new Set(['/', '/devices', '/traffic', '/filters', '/system']);
    const READY_MS = 600, PREFETCH_MS = 10000;
    const prefetched = new Map();   // url -> { at, page: Promise<Document> }
    let current = 0;                // the newest navigation; older ones give way to it

    // API calls in flight, so a swap can wait for the new page's first answers.
    let inflight = 0;
    const plainFetch = window.fetch.bind(window);
    window.fetch = (u, ...rest) => {
        const path = new URL(String(u instanceof Request ? u.url : u), location.href).pathname;
        if (!path.startsWith('/api/')) return plainFetch(u, ...rest);
        inflight++;
        return plainFetch(u, ...rest).finally(() => { inflight--; });
    };
    const sleep = ms => new Promise(r => setTimeout(r, ms));
    async function settled(ms) {
        const end = Date.now() + ms;
        await sleep(0); // the new page's init starts its requests first
        while (inflight > 0 && Date.now() < end) await sleep(16);
    }

    const target = a => {
        const u = new URL(a.href, location.href);
        return u.origin === location.origin && PAGES.has(u.pathname) ? u : null;
    };
    // The link a pointer event is on. While a view transition runs, the browser sends every
    // tap to the page root, so a second tap on the bar would be lost; the bar never moves
    // during a transition, so the tap's position still names the link.
    const linkOf = e => {
        if (e.target !== document.documentElement) return e.target.closest ? e.target.closest('a[href]') : null;
        return [...document.querySelectorAll('.topbar a[href]')].find(a => {
            const r = a.getBoundingClientRect();
            return e.clientX >= r.left && e.clientX <= r.right && e.clientY >= r.top && e.clientY <= r.bottom;
        }) || null;
    };

    async function load(url) {
        const res = await plainFetch(url, { credentials: 'same-origin' });
        if (!res.ok || !PAGES.has(new URL(res.url).pathname)) throw new Error('not a console page'); // e.g. sent to /login
        const doc = new DOMParser().parseFromString(await res.text(), 'text/html');
        if (!doc.querySelector('main.content') || !doc.querySelector('.topbar')) throw new Error('not a console page');
        return doc;
    }
    function page(url) {
        const hit = prefetched.get(url);
        prefetched.delete(url);
        return hit && Date.now() - hit.at < PREFETCH_MS ? hit.page : load(url);
    }
    function prefetch(url) {
        const hit = prefetched.get(url);
        if (hit && Date.now() - hit.at < PREFETCH_MS) return;
        const p = load(url);
        p.catch(() => prefetched.delete(url));
        prefetched.set(url, { at: Date.now(), page: p });
    }

    // The new page's own scripts, in order: a library it needs once (the QR code
    // library), then its inline script, which defines its Alpine component.
    async function runScripts(doc) {
        for (const s of doc.body.querySelectorAll('script')) {
            const src = s.getAttribute('src');
            if (src) {
                if (/\/static\/js\/(alpine\.min|app)\.js$/.test(src) || [...document.scripts].some(x => x.getAttribute('src') === src)) continue;
                await new Promise((ok, fail) => {
                    const el = document.createElement('script');
                    el.src = src; el.onload = ok; el.onerror = fail;
                    document.body.append(el);
                });
            } else {
                const el = document.createElement('script');
                el.textContent = s.textContent;
                document.body.append(el);
                el.remove();
            }
        }
    }

    function markTab(path) {
        for (const a of document.querySelectorAll('.topnav .navlink')) {
            const on = new URL(a.href, location.href).pathname === path;
            a.classList.toggle('active', on);
            if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
        }
    }

    async function go(url, { push = true, y = 0 } = {}) {
        const id = ++current;
        const path = new URL(url, location.href).pathname;
        markTab(path); // the tab answers the tap at once
        let doc;
        try { doc = await page(url); } catch (e) { location.assign(url); return; }
        if (id !== current) return;
        const swap = async () => {
            await runScripts(doc);
            if (id !== current) return; // a newer tap took over while a script loaded
            if (push) {
                history.replaceState(Object.assign({}, history.state, { y: scrollY }), '');
                history.pushState({ gap: 1, y: 0 }, '', url);
            }
            document.title = doc.title;
            // Swap what is inside <main>, not <main> itself: Alpine tears down only elements it
            // marked, and on a first load it marks the page's component, not the <main> around it.
            const main = document.querySelector('main.content'), next = doc.querySelector('main.content');
            main.className = next.className;
            main.replaceChildren(...[...next.childNodes].map(n => document.adoptNode(n)));
            main.tabIndex = -1;
            main.focus({ preventScroll: true });
            scrollTo(0, y);
            await settled(READY_MS);
        };
        document.documentElement.classList.add('gap-swapped'); // pages after the first don't rise in
        try {
            if (document.startViewTransition) {
                const t = document.startViewTransition(swap);
                t.ready.catch(() => {}); // a newer tap skipped this one's animation: expected
                await t.finished;
            } else await swap();
        } catch (e) {
            if (id === current) location.assign(url);
            return;
        }
        if (id === current) dispatchEvent(new Event('gap:navigated'));
    }

    function start() {
        if (!document.querySelector('.topbar') || !document.querySelector('main.content')) return; // the login page
        history.scrollRestoration = 'manual';
        history.replaceState(Object.assign({ gap: 1, y: 0 }, history.state), '');
        document.addEventListener('click', e => {
            if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
            const a = linkOf(e);
            if (!a || (a.target && a.target !== '_self') || a.hasAttribute('download')) return;
            const u = target(a);
            if (!u) return;
            e.preventDefault();
            if (u.pathname + u.search === location.pathname + location.search) return; // already here
            go(u.href);
        });
        // Fetch the page while the finger or pointer is still on its way down.
        const warm = e => {
            const a = linkOf(e);
            const u = a && target(a);
            if (u && u.pathname + u.search !== location.pathname + location.search) prefetch(u.href);
        };
        document.addEventListener('pointerover', warm);
        document.addEventListener('pointerdown', warm);
        document.addEventListener('focusin', warm);
        addEventListener('popstate', e => {
            if (!PAGES.has(location.pathname)) { location.reload(); return; }
            go(location.href, { push: false, y: (e.state && e.state.y) || 0 });
        });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
    return { go };
})();

function formatUptime(seconds) {
    seconds = parseFloat(seconds) || 0;
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'm';
    if (h > 0) return h + 'h ' + m + 'm';
    return m + 'm';
}
