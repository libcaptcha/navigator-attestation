function safe(fn, fallback) {
    try {
        return fn();
    } catch {
        return fallback;
    }
}

// MurmurHash3 x86 128-bit
function fmix(input) {
    input ^= input >>> 16;
    input = Math.imul(input, 0x85ebca6b);
    input ^= input >>> 13;
    input = Math.imul(input, 0xc2b2ae35);
    input ^= input >>> 16;
    return input >>> 0;
}

const HASH_C = new Uint32Array([0x239b961b, 0xab0e9789, 0x38b34ae5, 0xa1e38b93]);

function rotl(m, n) {
    return (m << n) | (m >>> (32 - n));
}

function hashBody(key, hash) {
    const blocks = (key.byteLength / 16) | 0;
    const view32 = new Uint32Array(key, 0, blocks * 4);
    for (let i = 0; i < blocks; i++) {
        const k = view32.subarray(i * 4, (i + 1) * 4);
        k[0] = Math.imul(k[0], HASH_C[0]);
        k[0] = rotl(k[0], 15);
        k[0] = Math.imul(k[0], HASH_C[1]);
        hash[0] = hash[0] ^ k[0];
        hash[0] = rotl(hash[0], 19);
        hash[0] = hash[0] + hash[1];
        hash[0] = Math.imul(hash[0], 5) + 0x561ccd1b;

        k[1] = Math.imul(k[1], HASH_C[1]);
        k[1] = rotl(k[1], 16);
        k[1] = Math.imul(k[1], HASH_C[2]);
        hash[1] = hash[1] ^ k[1];
        hash[1] = rotl(hash[1], 17);
        hash[1] = hash[1] + hash[2];
        hash[1] = Math.imul(hash[1], 5) + 0x0bcaa747;

        k[2] = Math.imul(k[2], HASH_C[2]);
        k[2] = rotl(k[2], 17);
        k[2] = Math.imul(k[2], HASH_C[3]);
        hash[2] = hash[2] ^ k[2];
        hash[2] = rotl(hash[2], 15);
        hash[2] = hash[2] + hash[3];
        hash[2] = Math.imul(hash[2], 5) + 0x96cd1c35;

        k[3] = Math.imul(k[3], HASH_C[3]);
        k[3] = rotl(k[3], 18);
        k[3] = Math.imul(k[3], HASH_C[0]);
        hash[3] = hash[3] ^ k[3];
        hash[3] = rotl(hash[3], 13);
        hash[3] = hash[3] + hash[0];
        hash[3] = Math.imul(hash[3], 5) + 0x32ac3b17;
    }
}

function hashTail(key, hash) {
    const blocks = (key.byteLength / 16) | 0;
    const reminder = key.byteLength % 16;
    const k = new Uint32Array(4);
    const tail = new Uint8Array(key, blocks * 16, reminder);
    /* eslint-disable no-fallthrough */
    switch (reminder) {
        case 15:
            k[3] = k[3] ^ (tail[14] << 16);
        case 14:
            k[3] = k[3] ^ (tail[13] << 8);
        case 13:
            k[3] = k[3] ^ (tail[12] << 0);
            k[3] = Math.imul(k[3], HASH_C[3]);
            k[3] = rotl(k[3], 18);
            k[3] = Math.imul(k[3], HASH_C[0]);
            hash[3] = hash[3] ^ k[3];
        case 12:
            k[2] = k[2] ^ (tail[11] << 24);
        case 11:
            k[2] = k[2] ^ (tail[10] << 16);
        case 10:
            k[2] = k[2] ^ (tail[9] << 8);
        case 9:
            k[2] = k[2] ^ (tail[8] << 0);
            k[2] = Math.imul(k[2], HASH_C[2]);
            k[2] = rotl(k[2], 17);
            k[2] = Math.imul(k[2], HASH_C[3]);
            hash[2] = hash[2] ^ k[2];
        case 8:
            k[1] = k[1] ^ (tail[7] << 24);
        case 7:
            k[1] = k[1] ^ (tail[6] << 16);
        case 6:
            k[1] = k[1] ^ (tail[5] << 8);
        case 5:
            k[1] = k[1] ^ (tail[4] << 0);
            k[1] = Math.imul(k[1], HASH_C[1]);
            k[1] = rotl(k[1], 16);
            k[1] = Math.imul(k[1], HASH_C[2]);
            hash[1] = hash[1] ^ k[1];
        case 4:
            k[0] = k[0] ^ (tail[3] << 24);
        case 3:
            k[0] = k[0] ^ (tail[2] << 16);
        case 2:
            k[0] = k[0] ^ (tail[1] << 8);
        case 1:
            k[0] = k[0] ^ (tail[0] << 0);
            k[0] = Math.imul(k[0], HASH_C[0]);
            k[0] = rotl(k[0], 15);
            k[0] = Math.imul(k[0], HASH_C[1]);
            hash[0] = hash[0] ^ k[0];
    }
    /* eslint-enable no-fallthrough */
}

function hashFinalize(key, hash) {
    hash[0] = hash[0] ^ key.byteLength;
    hash[1] = hash[1] ^ key.byteLength;
    hash[2] = hash[2] ^ key.byteLength;
    hash[3] = hash[3] ^ key.byteLength;
    hash[0] = (hash[0] + hash[1]) | 0;
    hash[0] = (hash[0] + hash[2]) | 0;
    hash[0] = (hash[0] + hash[3]) | 0;
    hash[1] = (hash[1] + hash[0]) | 0;
    hash[2] = (hash[2] + hash[0]) | 0;
    hash[3] = (hash[3] + hash[0]) | 0;
    hash[0] = fmix(hash[0]);
    hash[1] = fmix(hash[1]);
    hash[2] = fmix(hash[2]);
    hash[3] = fmix(hash[3]);
    hash[0] = (hash[0] + hash[1]) | 0;
    hash[0] = (hash[0] + hash[2]) | 0;
    hash[0] = (hash[0] + hash[3]) | 0;
    hash[1] = (hash[1] + hash[0]) | 0;
    hash[2] = (hash[2] + hash[0]) | 0;
    hash[3] = (hash[3] + hash[0]) | 0;
}

function murmurHash128(input, seed = 0) {
    seed = seed | 0;
    let key = input;
    if (typeof key === 'string') {
        key = new TextEncoder().encode(key).buffer;
    }
    const hash = new Uint32Array([seed, seed, seed, seed]);
    hashBody(key, hash);
    hashTail(key, hash);
    hashFinalize(key, hash);
    return Array.from(new Uint8Array(hash.buffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

function stableStringify(node) {
    if (node === undefined) return;
    if (typeof node === 'number') {
        return isFinite(node) ? '' + node : 'null';
    }
    if (typeof node !== 'object') return JSON.stringify(node);
    if (node === null) return 'null';
    if (Array.isArray(node)) {
        let out = '[';
        for (let i = 0; i < node.length; i++) {
            if (i) out += ',';
            out += stableStringify(node[i]) || 'null';
        }
        return out + ']';
    }
    const keys = Object.keys(node).sort();
    let out = '';
    for (const key of keys) {
        const value = stableStringify(node[key]);
        if (!value) continue;
        if (out) out += ',';
        out += JSON.stringify(key) + ':' + value;
    }
    return '{' + out + '}';
}

// --- Component collectors ---

function collectPlatform() {
    const nav = globalThis.navigator || {};
    return {
        platform: safe(() => nav.platform || '', ''),
        vendor: safe(() => nav.vendor || '', ''),
        productSub: safe(() => nav.productSub || '', ''),
        oscpu: safe(() => nav.oscpu, undefined),
    };
}

function collectHardware() {
    const nav = globalThis.navigator || {};
    return {
        concurrency: safe(() => nav.hardwareConcurrency || 0, 0),
        deviceMemory: safe(() => nav.deviceMemory, undefined),
        maxTouchPoints: safe(() => nav.maxTouchPoints || 0, 0),
        architecture: collectArchitecture(),
    };
}

function collectArchitecture() {
    try {
        const float = new Float32Array(1);
        const bytes = new Uint8Array(float.buffer);
        float[0] = Infinity;
        float[0] = float[0] - float[0];
        return bytes[3];
    } catch {
        return -1;
    }
}

function collectScreen() {
    const screen = globalThis.screen || {};
    return {
        colorDepth: safe(() => screen.colorDepth || 0, 0),
        pixelDepth: safe(() => screen.pixelDepth || 0, 0),
        devicePixelRatio: safe(() => globalThis.window?.devicePixelRatio || 0, 0),
    };
}

function collectTimezone() {
    return {
        offset: safe(() => new Date().getTimezoneOffset(), 0),
        name: safe(() => Intl.DateTimeFormat().resolvedOptions().timeZone || '', ''),
    };
}

function collectLanguages() {
    const nav = globalThis.navigator || {};
    return {
        language: safe(() => nav.language || '', ''),
        languages: safe(() => (nav.languages ? Array.from(nav.languages) : []), []),
    };
}

function collectMath() {
    const m = Math;
    return {
        acos: safe(() => m.acos(0.123456789), 0),
        acosh: safe(() => m.acosh(1e308), 0),
        asin: safe(() => m.asin(0.123456789), 0),
        atan: safe(() => m.atan(2), 0),
        atanh: safe(() => m.atanh(0.5), 0),
        cbrt: safe(() => m.cbrt(100.123456789), 0),
        cos: safe(() => m.cos(21 * m.LN2), 0),
        cosh: safe(() => m.cosh(1), 0),
        expm1: safe(() => m.expm1(1), 0),
        log1p: safe(() => m.log1p(0.5), 0),
        sin: safe(() => m.sin(-1e90), 0),
        sinh: safe(() => m.sinh(1), 0),
        tan: safe(() => m.tan(-1e308), 0),
        tanh: safe(() => m.tanh(1), 0),
    };
}

function collectWebGL() {
    const doc = globalThis.document;
    if (!doc) return null;
    try {
        const canvas = doc.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) return null;
        const result = {
            vendor: '',
            renderer: '',
            shadingVersion: safe(() => gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '', ''),
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
            extensions: (gl.getSupportedExtensions() || []).sort(),
        };
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbg) {
            result.vendor = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || '';
            result.renderer = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '';
        }
        return result;
    } catch {
        return null;
    }
}

const CANVAS_TEXT = 'Cwm fjordbank gly \u{1F603}';

function renderCanvas() {
    const doc = globalThis.document;
    if (!doc) return null;
    try {
        const canvas = doc.createElement('canvas');
        canvas.width = 280;
        canvas.height = 60;
        const ctx = canvas.getContext('2d');
        if (!ctx) return null;
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f60';
        ctx.fillRect(100, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.font = '11pt Arial';
        ctx.fillText(CANVAS_TEXT, 2, 15);
        ctx.fillStyle = 'rgba(102,204,0,0.7)';
        ctx.font = '18pt Arial';
        ctx.fillText(CANVAS_TEXT, 4, 45);
        ctx.globalCompositeOperation = 'multiply';
        ctx.fillStyle = 'rgb(255,0,255)';
        ctx.beginPath();
        ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();
        ctx.fillStyle = 'rgb(0,255,255)';
        ctx.beginPath();
        ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();
        ctx.fillStyle = 'rgb(255,255,0)';
        ctx.beginPath();
        ctx.arc(75, 100, 50, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fill();
        return canvas.toDataURL();
    } catch {
        return null;
    }
}

function collectCanvas() {
    const renders = [];
    for (let i = 0; i < 3; i++) {
        renders.push(renderCanvas());
    }
    const stable = mostFrequent(renders);
    if (!stable) return { hash: null, stable: false };
    let h = 0;
    for (let i = 0; i < stable.length; i++) {
        h = ((h << 5) - h + stable.charCodeAt(i)) | 0;
    }
    return {
        hash: h.toString(16),
        stable: renders.every((r) => r === renders[0]),
    };
}

function mostFrequent(items) {
    const counts = new Map();
    for (const item of items) {
        counts.set(item, (counts.get(item) || 0) + 1);
    }
    let best = null;
    let bestCount = 0;
    for (const [item, count] of counts) {
        if (count > bestCount) {
            best = item;
            bestCount = count;
        }
    }
    return best;
}

const FONT_LIST = [
    'Arial',
    'Verdana',
    'Times New Roman',
    'Courier New',
    'Georgia',
    'Palatino',
    'Garamond',
    'Comic Sans MS',
    'Impact',
    'Lucida Console',
    'Tahoma',
    'Trebuchet MS',
    'Helvetica',
    'Segoe UI',
    'Roboto',
    'Ubuntu',
    'Consolas',
    'Menlo',
    'Monaco',
    'Liberation Mono',
    'Lucida Sans',
    'Lucida Grande',
    'Candara',
    'Calibri',
    'Cambria',
    'Franklin Gothic Medium',
    'Gill Sans',
    'Century Gothic',
    'Book Antiqua',
    'Copperplate',
    'Optima',
    'Futura',
    'Didot',
    'American Typewriter',
    'Andale Mono',
    'DejaVu Sans',
    'Droid Sans',
    'Liberation Sans',
    'Noto Sans',
    'Open Sans',
    'Source Sans Pro',
    'PT Sans',
    'Lato',
    'Montserrat',
    'Raleway',
    'Playfair Display',
    'Merriweather',
    'Oswald',
    'Fira Sans',
    'Inter',
    'Noto Serif',
    'IBM Plex Sans',
];

function collectFonts() {
    const doc = globalThis.document;
    if (!doc) return [];
    try {
        const canvas = doc.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) return [];
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testString = 'mmmmmmmmlli';
        const size = '72px';
        const baseWidths = {};
        for (const base of baseFonts) {
            ctx.font = `${size} ${base}`;
            baseWidths[base] = ctx.measureText(testString).width;
        }
        const detected = [];
        for (const font of FONT_LIST) {
            for (const base of baseFonts) {
                ctx.font = `${size} "${font}",${base}`;
                const width = ctx.measureText(testString).width;
                if (width !== baseWidths[base]) {
                    detected.push(font);
                    break;
                }
            }
        }
        return detected;
    } catch {
        return [];
    }
}

function collectAudio() {
    try {
        const AudioCtx = globalThis.AudioContext || globalThis.webkitAudioContext;
        if (!AudioCtx) return null;
        const ctx = new AudioCtx();
        const oscillator = ctx.createOscillator();
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, ctx.currentTime);
        const compressor = ctx.createDynamicsCompressor();
        compressor.threshold.setValueAtTime(-50, ctx.currentTime);
        compressor.knee.setValueAtTime(40, ctx.currentTime);
        compressor.ratio.setValueAtTime(12, ctx.currentTime);
        compressor.attack.setValueAtTime(0, ctx.currentTime);
        compressor.release.setValueAtTime(0.25, ctx.currentTime);
        oscillator.connect(compressor);
        compressor.connect(ctx.destination);
        oscillator.start(0);
        const baseLatency = safe(() => ctx.baseLatency, undefined);
        const maxChannels = ctx.destination.maxChannelCount;
        oscillator.disconnect();
        compressor.disconnect();
        ctx.close().catch(() => {});
        return { baseLatency, maxChannels };
    } catch {
        return null;
    }
}

function collectPlugins() {
    const nav = globalThis.navigator || {};
    try {
        if (!nav.plugins) return [];
        return Array.from(nav.plugins).map((p) => ({
            name: p.name || '',
            filename: p.filename || '',
        }));
    } catch {
        return [];
    }
}

function collectMediaQueries() {
    const mm = globalThis.window?.matchMedia;
    if (!mm) return null;
    function query(q) {
        try {
            return mm(q).matches;
        } catch {
            return false;
        }
    }
    return {
        colorGamutP3: query('(color-gamut: p3)'),
        colorGamutSrgb: query('(color-gamut: srgb)'),
        hdr: query('(dynamic-range: high)'),
        invertedColors: query('(inverted-colors: inverted)'),
        forcedColors: query('(forced-colors: active)'),
        monochrome: query('(monochrome)'),
        reducedMotion: query('(prefers-reduced-motion: reduce)'),
        reducedTransparency: query('(prefers-reduced-transparency: reduce)'),
        hover: query('(hover: hover)'),
        pointer: query('(pointer: fine)'),
    };
}

function collectStorage() {
    const w = globalThis.window || {};
    return {
        localStorage: safe(() => !!w.localStorage, false),
        sessionStorage: safe(() => !!w.sessionStorage, false),
        indexedDB: safe(() => !!w.indexedDB, false),
        openDatabase: safe(() => typeof w.openDatabase === 'function', false),
    };
}

function collectEngine() {
    let evalLength = -1;
    try {
        evalLength = eval.toString().length;
    } catch {}
    let stackStyle = 'unknown';
    try {
        throw new Error('detect');
    } catch (error) {
        const stack = error.stack || '';
        if (stack.includes(' at ')) stackStyle = 'v8';
        else if (stack.includes('@')) {
            stackStyle = 'spidermonkey';
        } else if (stack.includes('global code')) {
            stackStyle = 'jsc';
        }
    }
    return { evalLength, stackStyle };
}

function collectVendorFlavors() {
    const w = globalThis.window || {};
    const flavors = [];
    const checks = [
        'chrome',
        'safari',
        '__crWeb',
        '__gCrWeb',
        '__firefox__',
        '__edgeTrackingPreventionStatistics',
        'opr',
        'opera',
    ];
    for (const key of checks) {
        if (safe(() => key in w, false)) {
            flavors.push(key);
        }
    }
    return flavors;
}

function collectCSSVersion() {
    const w = globalThis.window || {};
    if (!w.CSS?.supports) return 0;
    const checks = [
        [115, 'scroll-timeline-axis:block'],
        [105, ':has(*)'],
        [100, 'text-emphasis-color:initial'],
        [95, 'accent-color:initial'],
        [89, 'border-end-end-radius:initial'],
        [88, 'aspect-ratio:initial'],
        [84, 'appearance:initial'],
        [81, 'color-scheme:initial'],
    ];
    for (const [version, rule] of checks) {
        try {
            if (w.CSS.supports(rule)) return version;
        } catch {}
    }
    return 0;
}

function collectPdfViewer() {
    return safe(() => globalThis.navigator?.pdfViewerEnabled, undefined);
}

function collectCookies() {
    return safe(() => globalThis.navigator?.cookieEnabled, undefined);
}

function collectScreenResolution() {
    const screen = globalThis.screen || {};
    const width = safe(() => screen.width || 0, 0);
    const height = safe(() => screen.height || 0, 0);
    return [Math.max(width, height), Math.min(width, height)];
}

function collectScreenFrame() {
    const screen = globalThis.screen || {};
    try {
        const width = screen.width || 0;
        const height = screen.height || 0;
        const availWidth = screen.availWidth || 0;
        const availHeight = screen.availHeight || 0;
        const availTop = screen.availTop || 0;
        const availLeft = screen.availLeft || 0;
        const roundTo10 = (v) => Math.round(v / 10) * 10;
        return [
            roundTo10(availTop),
            roundTo10(width - availWidth - availLeft),
            roundTo10(height - availHeight - availTop),
            roundTo10(availLeft),
        ];
    } catch {
        return null;
    }
}

function collectFontPreferences() {
    const doc = globalThis.document;
    if (!doc) return null;
    try {
        const testText = 'mmMwWLliI0fiflO&1';
        const presets = {
            default: '',
            apple: '-apple-system-body',
            serif: 'serif',
            sansSerif: 'sans-serif',
            mono: 'monospace',
            systemUi: 'system-ui',
            min: '1px',
        };
        const canvas = doc.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) return null;
        const result = {};
        for (const [name, font] of Object.entries(presets)) {
            ctx.font = font ? `16px ${font}` : '16px serif';
            result[name] = ctx.measureText(testText).width;
        }
        return result;
    } catch {
        return null;
    }
}

function collectContrast() {
    const mm = globalThis.window?.matchMedia;
    if (!mm) return undefined;
    function query(q) {
        try {
            return mm(q).matches;
        } catch {
            return false;
        }
    }
    if (query('(forced-colors: active)')) return 10;
    if (query('(prefers-contrast: high)') || query('(prefers-contrast: more)')) return 1;
    if (query('(prefers-contrast: low)') || query('(prefers-contrast: less)')) return -1;
    if (query('(prefers-contrast: no-preference)')) {
        return 0;
    }
    return undefined;
}

function collectApplePay() {
    try {
        const w = globalThis.window || {};
        if (!w.ApplePaySession) return -1;
        if (typeof w.ApplePaySession.canMakePayments !== 'function') return -1;
        try {
            if (w.ApplePaySession.canMakePayments()) {
                return 1;
            }
            return 0;
        } catch {
            return -2;
        }
    } catch {
        return -1;
    }
}

function collectMonochrome() {
    const mm = globalThis.window?.matchMedia;
    if (!mm) return 0;
    try {
        if (!mm('(monochrome)').matches) return 0;
        let low = 0;
        let high = 100;
        while (high - low > 1) {
            const mid = Math.floor((low + high) / 2);
            if (mm(`(min-monochrome: ${mid})`).matches) {
                low = mid;
            } else {
                high = mid;
            }
        }
        return low;
    } catch {
        return 0;
    }
}

function collectDateTimeLocale() {
    return safe(() => Intl.DateTimeFormat().resolvedOptions().locale || '', '');
}

const BLOCKER_SELECTORS = [
    '#ad-banner',
    '.ad-wrapper',
    '.ad-slot',
    '.adsbygoogle',
    '#google_ads_iframe',
    '.afs_ads',
    '#carbonads',
    '.carbon-wrap',
    '#_carbonads_js',
    '.ad-container',
    '.ad-placeholder',
    '.sponsorText',
    'div[id^="div-gpt-ad"]',
    'ins.adsbygoogle',
    'div[data-ad-slot]',
];

function collectDomBlockers() {
    const doc = globalThis.document;
    if (!doc) return null;
    try {
        const container = doc.createElement('div');
        container.style.cssText =
            'position:absolute;left:-9999px;' + 'visibility:hidden;display:block';
        doc.body.appendChild(container);
        const blocked = [];
        for (const selector of BLOCKER_SELECTORS) {
            const el = doc.createElement('div');
            if (selector.startsWith('#')) {
                el.id = selector.slice(1);
            } else if (selector.startsWith('.')) {
                el.className = selector.slice(1);
            } else {
                const id = selector.match(/id="([^"]+)"/);
                if (id) el.id = id[1];
                const cls = selector.match(/class="([^"]+)"/);
                if (cls) el.className = cls[1];
            }
            el.style.cssText = 'display:block!important;' + 'visibility:hidden!important';
            container.appendChild(el);
            if (el.offsetParent === null && el.offsetHeight === 0) {
                blocked.push(selector);
            }
        }
        container.remove();
        return blocked.length > 0 ? blocked : null;
    } catch {
        return null;
    }
}

// --- Component registry ---

const COMPONENTS = {
    platform: collectPlatform,
    hardware: collectHardware,
    screen: collectScreen,
    screenResolution: collectScreenResolution,
    screenFrame: collectScreenFrame,
    timezone: collectTimezone,
    languages: collectLanguages,
    math: collectMath,
    webgl: collectWebGL,
    canvas: collectCanvas,
    fonts: collectFonts,
    fontPreferences: collectFontPreferences,
    audio: collectAudio,
    plugins: collectPlugins,
    mediaQueries: collectMediaQueries,
    contrast: collectContrast,
    monochrome: collectMonochrome,
    storage: collectStorage,
    engine: collectEngine,
    vendorFlavors: collectVendorFlavors,
    cssVersion: collectCSSVersion,
    pdfViewer: collectPdfViewer,
    cookies: collectCookies,
    applePay: collectApplePay,
    dateTimeLocale: collectDateTimeLocale,
    domBlockers: collectDomBlockers,
};

const COMPONENT_NAMES = Object.keys(COMPONENTS);

// --- Stabilization ---

function detectBrowser() {
    const ua = safe(() => globalThis.navigator?.userAgent || '', '');
    if (/Brave/.test(ua) || safe(() => !!globalThis.navigator?.brave, false)) return 'brave';
    if (/SamsungBrowser/.test(ua)) return 'samsung';
    if (/Firefox/.test(ua)) return 'firefox';
    if (/Safari/.test(ua) && !/Chrome/.test(ua)) {
        return 'safari';
    }
    if (/Chrome/.test(ua)) return 'chrome';
    return 'unknown';
}

function getSafariVersion() {
    const ua = safe(() => globalThis.navigator?.userAgent || '', '');
    const match = ua.match(/Version\/(\d+)/);
    return match ? parseInt(match[1], 10) : 0;
}

const EXCLUSION_RULES = {
    brave: [
        'canvas',
        'audio',
        'fonts',
        'hardware.deviceMemory',
        'hardware.concurrency',
        'plugins',
        'domBlockers',
    ],
    firefox: ['canvas', 'fonts', 'screenFrame'],
    safari: [],
    samsung: ['audio'],
    chrome: [],
    unknown: [],
};

function getExclusions() {
    const browser = detectBrowser();
    const exclusions = [...(EXCLUSION_RULES[browser] || [])];
    if (browser === 'safari' && getSafariVersion() >= 17) {
        exclusions.push('canvas', 'audio');
    }
    return exclusions;
}

function applyExclusions(components, exclusions) {
    const result = {};
    for (const [key, value] of Object.entries(components)) {
        if (exclusions.includes(key)) continue;
        if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
            const filtered = {};
            let hasKeys = false;
            for (const [subKey, subValue] of Object.entries(value)) {
                const path = `${key}.${subKey}`;
                if (exclusions.includes(path)) continue;
                filtered[subKey] = subValue;
                hasKeys = true;
            }
            if (hasKeys) result[key] = filtered;
        } else {
            result[key] = value;
        }
    }
    return result;
}

// --- Main API ---

function collectComponents(options = {}) {
    const include = options.include || COMPONENT_NAMES;
    const exclude = options.exclude || [];
    const components = {};
    for (const name of include) {
        if (exclude.includes(name)) continue;
        const collector = COMPONENTS[name];
        if (!collector) continue;
        try {
            components[name] = collector();
        } catch {
            components[name] = { error: true };
        }
    }
    return components;
}

function getFingerprint(options = {}) {
    const components = collectComponents(options);
    const stabilize = options.stabilize !== false;
    const processed = stabilize ? applyExclusions(components, getExclusions()) : components;
    const canonical = stableStringify(processed);
    const id = murmurHash128(canonical);
    return {
        id,
        components: processed,
        browser: detectBrowser(),
    };
}

async function getFingerprintAsync(options = {}) {
    const { components, stabilize, ...rest } = resolveOptions(options);
    const collected = collectComponents(rest);
    const [voicesResult, audioFpResult, permissionsResult, webrtcResult] = await Promise.all([
        collectVoices(),
        collectAudioFingerprint(),
        collectPermissions(),
        collectWebRTC(),
    ]);
    if (voicesResult) collected.voices = voicesResult;
    if (audioFpResult !== null) {
        collected.audioFingerprint = audioFpResult;
    }
    if (permissionsResult) {
        collected.permissions = permissionsResult;
    }
    if (webrtcResult) collected.webrtc = webrtcResult;
    const processed = stabilize !== false ? applyExclusions(collected, getExclusions()) : collected;
    const canonical = stableStringify(processed);
    const id = murmurHash128(canonical);
    return {
        id,
        components: processed,
        browser: detectBrowser(),
    };
}

function resolveOptions(options) {
    const { include, exclude, stabilize, ...rest } = options;
    return {
        include,
        exclude,
        stabilize,
        components: null,
        ...rest,
    };
}

function collectVoices() {
    return new Promise((resolve) => {
        try {
            const synth = globalThis.speechSynthesis;
            if (!synth) return resolve(null);
            const voices = synth.getVoices();
            if (voices.length > 0) {
                return resolve(formatVoices(voices));
            }
            synth.onvoiceschanged = () => {
                resolve(formatVoices(synth.getVoices()));
            };
            setTimeout(() => resolve(null), 1000);
        } catch {
            resolve(null);
        }
    });
}

function formatVoices(voices) {
    return voices.map((v) => ({
        name: v.name,
        lang: v.lang,
        uri: v.voiceURI,
        local: v.localService,
    }));
}

function collectAudioFingerprint() {
    return new Promise((resolve) => {
        try {
            const AudioCtx = globalThis.OfflineAudioContext || globalThis.webkitOfflineAudioContext;
            if (!AudioCtx) return resolve(null);
            const sampleRate = 44100;
            const length = 5000;
            const ctx = new AudioCtx(1, length, sampleRate);
            const oscillator = ctx.createOscillator();
            oscillator.type = 'triangle';
            oscillator.frequency.value = 10000;
            const compressor = ctx.createDynamicsCompressor();
            compressor.threshold.value = -50;
            compressor.knee.value = 40;
            compressor.ratio.value = 12;
            compressor.attack.value = 0;
            compressor.release.value = 0.25;
            oscillator.connect(compressor);
            compressor.connect(ctx.destination);
            oscillator.start(0);
            ctx.oncomplete = (event) => {
                const samples = event.renderedBuffer.getChannelData(0);
                let hash = 0;
                for (let i = 4500; i < samples.length; i++) {
                    hash += Math.abs(samples[i]);
                }
                resolve(hash);
            };
            ctx.startRendering();
            setTimeout(() => resolve(null), 3000);
        } catch {
            resolve(null);
        }
    });
}

const PERMISSION_NAMES = [
    'accelerometer',
    'ambient-light-sensor',
    'camera',
    'clipboard-read',
    'clipboard-write',
    'geolocation',
    'gyroscope',
    'magnetometer',
    'microphone',
    'midi',
    'notifications',
    'persistent-storage',
    'push',
    'display-capture',
    'local-fonts',
    'storage-access',
    'bluetooth',
    'background-sync',
    'background-fetch',
    'payment-handler',
    'window-management',
    'nfc',
    'device-info',
];

function collectPermissions() {
    return new Promise((resolve) => {
        try {
            const nav = globalThis.navigator;
            if (!nav?.permissions?.query) {
                return resolve(null);
            }
            const queries = PERMISSION_NAMES.map((name) =>
                nav.permissions.query({ name }).then(
                    (s) => [name, s.state],
                    () => null
                )
            );
            Promise.all(queries).then((results) => {
                const perms = {};
                for (const r of results) {
                    if (r) perms[r[0]] = r[1];
                }
                resolve(Object.keys(perms).length > 0 ? perms : null);
            });
            setTimeout(() => resolve(null), 3000);
        } catch {
            resolve(null);
        }
    });
}

function collectWebRTC() {
    return new Promise((resolve) => {
        try {
            const RTC =
                globalThis.RTCPeerConnection ||
                globalThis.webkitRTCPeerConnection ||
                globalThis.mozRTCPeerConnection;
            if (!RTC) return resolve(null);
            const conn = new RTC({
                iceServers: [],
                iceCandidatePoolSize: 0,
            });
            conn.createDataChannel('');
            conn.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: true,
            })
                .then((offer) => {
                    const sdp = offer.sdp || '';
                    const extensions = [
                        ...new Set(
                            (sdp.match(/extmap:\d+ [^\n\r]+/g) || []).map((x) =>
                                x.replace(/extmap:\d+ /, '')
                            )
                        ),
                    ].sort();
                    const extractCodecs = (type) => {
                        const m = sdp.match(new RegExp(`m=${type} \\S+ \\S+ ([^\\n\\r]+)`));
                        if (!m) return [];
                        return m[1]
                            .split(' ')
                            .map((id) => {
                                const rtp = sdp.match(new RegExp(`rtpmap:${id} ([^\\n\\r]+)`));
                                return rtp ? rtp[1] : null;
                            })
                            .filter(Boolean);
                    };
                    const audio = extractCodecs('audio');
                    const video = extractCodecs('video');
                    conn.close();
                    resolve({
                        audioCodecs: audio.length,
                        videoCodecs: video.length,
                        extensions: extensions.length,
                    });
                })
                .catch(() => {
                    conn.close();
                    resolve(null);
                });
            setTimeout(() => {
                try {
                    conn.close();
                } catch {}
                resolve(null);
            }, 3000);
        } catch {
            resolve(null);
        }
    });
}

export {
    getFingerprint,
    getFingerprintAsync,
    collectComponents,
    murmurHash128,
    stableStringify,
    COMPONENTS,
    COMPONENT_NAMES,
};
