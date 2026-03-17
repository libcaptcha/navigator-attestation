import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = 3456;
const URL = `http://localhost:${PORT}`;
const SANDBOX_ARGS = ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'];

async function waitForServer(maxWait = 15000) {
    const start = Date.now();
    while (Date.now() - start < maxWait) {
        try {
            const res = await fetch(`${URL}/health`);
            if (res.ok) return;
        } catch {}
        await new Promise((r) => setTimeout(r, 300));
    }
    throw new Error('test server did not start');
}

async function runAttestation(browser) {
    const page = await browser.newPage();
    await page.goto(URL, { waitUntil: 'networkidle0' });
    await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
    const result = await page.evaluate(() => window.__attestResult);
    await page.close();
    return result;
}

function assertDetected(result, name, maxScore = 0.85) {
    assert.ok(result, `${name}: no result returned`);
    assert.ok(!result.error, `${name}: error: ${result.error}`);
    assert.ok(result.score < maxScore, `${name}: score ${result.score} >= ${maxScore}`);
    assert.notEqual(result.verdict, 'trusted', `${name}: verdict should not be trusted`);
    assert.ok(result.flags.length > 0, `${name}: should have at least one flag`);
    console.log(
        `    ${name}: score=${result.score} ` +
            `verdict=${result.verdict} ` +
            `flags=${result.flags.length}`
    );
}

describe('Puppeteer Detection', { timeout: 120000 }, () => {
    let serverProcess;

    before(async () => {
        serverProcess = spawn('node', [join(__dirname, 'server.js')], {
            env: { ...process.env, PORT: String(PORT) },
            stdio: 'pipe',
        });
        serverProcess.stderr.on('data', (data) => {
            console.error(`server: ${data}`);
        });
        await waitForServer();
    });

    after(() => {
        serverProcess?.kill('SIGTERM');
    });

    it('headless: default (new)', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: SANDBOX_ARGS,
        });
        try {
            const result = await runAttestation(browser);
            assertDetected(result, 'headless-new', 0.7);
        } finally {
            await browser.close();
        }
    });

    it('headless: shell (old)', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'shell',
            args: SANDBOX_ARGS,
        });
        try {
            const result = await runAttestation(browser);
            assertDetected(result, 'headless-shell', 0.6);
        } finally {
            await browser.close();
        }
    });

    it('headless: disable-blink-features arg', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: [...SANDBOX_ARGS, '--disable-blink-features=AutomationControlled'],
        });
        try {
            const result = await runAttestation(browser);
            assertDetected(result, 'disable-automation-controlled', 0.75);
        } finally {
            await browser.close();
        }
    });

    it('headless: custom user agent', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: [
                ...SANDBOX_ARGS,
                '--user-agent=Mozilla/5.0 (X11; Linux x86_64)' +
                    ' AppleWebKit/537.36 (KHTML, like Gecko)' +
                    ' Chrome/120.0.0.0 Safari/537.36',
            ],
        });
        try {
            const result = await runAttestation(browser);
            assertDetected(result, 'custom-ua', 0.75);
        } finally {
            await browser.close();
        }
    });

    it('headless: mobile viewport emulation', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: SANDBOX_ARGS,
        });
        try {
            const page = await browser.newPage();
            await page.setViewport({
                width: 375,
                height: 812,
                isMobile: true,
                hasTouch: true,
                deviceScaleFactor: 3,
            });
            await page.setUserAgent(
                'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0' +
                    ' like Mac OS X) AppleWebKit/605.1.15' +
                    ' (KHTML, like Gecko) Version/16.0' +
                    ' Mobile/15E148 Safari/604.1'
            );
            await page.goto(URL, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'mobile-emulation', 0.8);
        } finally {
            await browser.close();
        }
    });

    it('headless: all anti-detection args combined', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: [
                ...SANDBOX_ARGS,
                '--disable-blink-features=' + 'AutomationControlled',
                '--disable-infobars',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
                '--window-size=1920,1080',
            ],
            ignoreDefaultArgs: ['--enable-automation'],
        });
        try {
            const result = await runAttestation(browser);
            assertDetected(result, 'all-anti-detection-args', 0.8);
        } finally {
            await browser.close();
        }
    });

    it('headless: webdriver property removed via CDP', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: SANDBOX_ARGS,
        });
        try {
            const page = await browser.newPage();
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => false,
                });
            });
            await page.goto(URL, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'webdriver-removed', 0.8);
        } finally {
            await browser.close();
        }
    });

    it('headless: navigator props spoofed via CDP', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: SANDBOX_ARGS,
        });
        try {
            const page = await browser.newPage();
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => false,
                });
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5],
                });
                Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
            });
            await page.goto(URL, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'navigator-props-spoofed', 0.8);
        } finally {
            await browser.close();
        }
    });

    it('headless: chrome runtime faked via CDP', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: [...SANDBOX_ARGS, '--disable-blink-features=' + 'AutomationControlled'],
            ignoreDefaultArgs: ['--enable-automation'],
        });
        try {
            const page = await browser.newPage();
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                window.chrome = {
                    runtime: {
                        sendMessage: function () {},
                        connect: function () {},
                    },
                    csi: function () {
                        return {};
                    },
                    loadTimes: function () {
                        return {};
                    },
                };
            });
            await page.goto(URL, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'chrome-runtime-faked', 0.85);
        } finally {
            await browser.close();
        }
    });

    it('headless: full environment spoofing via CDP', { timeout: 30000 }, async () => {
        const puppeteer = await import('puppeteer');
        const browser = await puppeteer.default.launch({
            headless: 'new',
            args: [
                ...SANDBOX_ARGS,
                '--disable-blink-features=' + 'AutomationControlled',
                '--window-size=1920,1080',
            ],
            ignoreDefaultArgs: ['--enable-automation'],
        });
        try {
            const page = await browser.newPage();
            await page.setViewport({
                width: 1920,
                height: 1080,
            });
            await page.evaluateOnNewDocument(() => {
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined,
                });
                Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
                Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en'],
                });
                Object.defineProperty(navigator, 'platform', { get: () => 'Linux x86_64' });
                window.chrome = {
                    runtime: {
                        sendMessage: function () {},
                        connect: function () {},
                    },
                    csi: function () {
                        return {};
                    },
                    loadTimes: function () {
                        return {};
                    },
                    app: { isInstalled: false },
                };
            });
            await page.goto(URL, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'full-env-spoof', 0.85);
        } finally {
            await browser.close();
        }
    });
});

describe('Puppeteer Extra + Stealth', { timeout: 120000 }, () => {
    let serverProcess;
    let stealthPuppeteer;

    before(async () => {
        serverProcess = spawn('node', [join(__dirname, 'server.js')], {
            env: { ...process.env, PORT: String(PORT + 1) },
            stdio: 'pipe',
        });
        const stealthUrl = `http://localhost:${PORT + 1}`;
        const start = Date.now();
        while (Date.now() - start < 15000) {
            try {
                const res = await fetch(`${stealthUrl}/health`);
                if (res.ok) break;
            } catch {}
            await new Promise((r) => setTimeout(r, 300));
        }

        try {
            const pExtra = await import('puppeteer-extra');
            const { default: StealthPlugin } = await import('puppeteer-extra-plugin-stealth');
            stealthPuppeteer = pExtra.default;
            stealthPuppeteer.use(StealthPlugin());
        } catch (error) {
            console.log('    puppeteer-extra not installed, ' + 'skipping stealth tests');
        }
    });

    after(() => {
        serverProcess?.kill('SIGTERM');
    });

    it('stealth: headless default', { timeout: 30000 }, async (t) => {
        if (!stealthPuppeteer) return t.skip();
        const stealthUrl = `http://localhost:${PORT + 1}`;
        const browser = await stealthPuppeteer.launch({
            headless: 'new',
            args: SANDBOX_ARGS,
        });
        try {
            const page = await browser.newPage();
            await page.goto(stealthUrl, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'stealth-headless', 0.85);
        } finally {
            await browser.close();
        }
    });

    it('stealth: headless with custom viewport', { timeout: 30000 }, async (t) => {
        if (!stealthPuppeteer) return t.skip();
        const stealthUrl = `http://localhost:${PORT + 1}`;
        const browser = await stealthPuppeteer.launch({
            headless: 'new',
            args: [...SANDBOX_ARGS, '--window-size=1920,1080'],
        });
        try {
            const page = await browser.newPage();
            await page.setViewport({
                width: 1920,
                height: 1080,
            });
            await page.goto(stealthUrl, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'stealth-viewport', 0.85);
        } finally {
            await browser.close();
        }
    });

    it('stealth: headless + all anti-detection', { timeout: 30000 }, async (t) => {
        if (!stealthPuppeteer) return t.skip();
        const stealthUrl = `http://localhost:${PORT + 1}`;
        const browser = await stealthPuppeteer.launch({
            headless: 'new',
            args: [
                ...SANDBOX_ARGS,
                '--disable-blink-features=' + 'AutomationControlled',
                '--window-size=1920,1080',
            ],
            ignoreDefaultArgs: ['--enable-automation'],
        });
        try {
            const page = await browser.newPage();
            await page.setViewport({
                width: 1920,
                height: 1080,
            });
            await page.goto(stealthUrl, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'stealth-all-args', 0.85);
        } finally {
            await browser.close();
        }
    });

    it('stealth: shell mode', { timeout: 30000 }, async (t) => {
        if (!stealthPuppeteer) return t.skip();
        const stealthUrl = `http://localhost:${PORT + 1}`;
        const browser = await stealthPuppeteer.launch({
            headless: 'shell',
            args: SANDBOX_ARGS,
        });
        try {
            const page = await browser.newPage();
            await page.goto(stealthUrl, {
                waitUntil: 'networkidle0',
            });
            await page.waitForFunction('window.__attestResult !== undefined', { timeout: 15000 });
            const result = await page.evaluate(() => window.__attestResult);
            await page.close();
            assertDetected(result, 'stealth-shell', 0.7);
        } finally {
            await browser.close();
        }
    });
});
