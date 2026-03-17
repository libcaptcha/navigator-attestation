import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateSignals, classifyScore, countBits } from '../src/validator.js';

describe('countBits', () => {
    it('counts zero', () => {
        assert.equal(countBits(0), 0);
    });

    it('counts single bits', () => {
        assert.equal(countBits(1), 1);
        assert.equal(countBits(2), 1);
        assert.equal(countBits(4), 1);
    });

    it('counts multiple bits', () => {
        assert.equal(countBits(0b1111), 4);
        assert.equal(countBits(0xff), 8);
        assert.equal(countBits(0xfff), 12);
    });
});

describe('classifyScore', () => {
    it('classifies trusted', () => {
        assert.equal(classifyScore(1.0), 'trusted');
        assert.equal(classifyScore(0.85), 'trusted');
    });

    it('classifies suspicious', () => {
        assert.equal(classifyScore(0.7), 'suspicious');
        assert.equal(classifyScore(0.6), 'suspicious');
    });

    it('classifies likely_automated', () => {
        assert.equal(classifyScore(0.5), 'likely_automated');
        assert.equal(classifyScore(0.3), 'likely_automated');
    });

    it('classifies automated', () => {
        assert.equal(classifyScore(0.2), 'automated');
        assert.equal(classifyScore(0), 'automated');
    });
});

describe('validateSignals', () => {
    it('returns perfect score for clean signals', () => {
        const signals = buildCleanSignals();
        const result = validateSignals(signals);
        assert.equal(result.score, 1.0);
        assert.equal(result.verdict, 'trusted');
        assert.equal(result.flags.length, 0);
    });

    it('penalizes automation globals', () => {
        const signals = buildCleanSignals();
        signals.automation.globals = 0b111;
        const result = validateSignals(signals);
        assert.ok(result.score < 1.0);
        assert.ok(result.flags.some((f) => f.includes('automation')));
    });

    it('penalizes headless chrome signals', () => {
        const signals = buildCleanSignals();
        signals.headless.pdfOff = 1;
        signals.headless.uadBlank = 1;
        signals.headless.mesa = 1;
        const result = validateSignals(signals);
        assert.ok(result.score < 0.7);
    });

    it('detects puppeteer stealth signals', () => {
        const signals = buildCleanSignals();
        signals.browser.stealth = 0b110;
        signals.automation.enhanced = 1 << 15;
        const result = validateSignals(signals);
        assert.ok(result.score < 1.0);
        assert.ok(result.flags.some((f) => f.includes('stealth')));
    });

    it('penalizes software renderer', () => {
        const signals = buildCleanSignals();
        signals.webgl = {
            vendor: 'Google Inc.',
            renderer: 'Google SwiftShader',
            maxTextureSize: 8192,
            maxVertexAttribs: 16,
            extensionCount: 20,
        };
        const result = validateSignals(signals);
        assert.ok(result.score < 0.7);
    });

    it('penalizes canvas randomization', () => {
        const signals = buildCleanSignals();
        signals.canvas.tampering = {
            random: 1,
            error: 0,
            inconsistent: 0,
            dataLength: 500,
        };
        const result = validateSignals(signals);
        assert.ok(result.flags.some((f) => f.includes('canvas')));
    });

    it('detects engine/UA mismatch', () => {
        const signals = buildCleanSignals();
        signals.engine.stackStyle = 'spidermonkey';
        const result = validateSignals(signals);
        assert.ok(result.flags.some((f) => f.includes('SpiderMonkey')));
    });

    it('checks headers', () => {
        const signals = buildCleanSignals();
        const headers = {
            'user-agent': 'HeadlessChrome/120',
        };
        const result = validateSignals(signals, headers);
        assert.ok(result.flags.some((f) => f.includes('headers')));
    });

    it('returns category scores', () => {
        const signals = buildCleanSignals();
        signals.automation.globals = 1;
        const result = validateSignals(signals);
        assert.ok(result.categoryScores);
        assert.ok(result.categoryScores.automation);
        assert.ok(result.categoryScores.automation.score < 1.0);
        assert.equal(result.categoryScores.navigator.score, 1.0);
    });

    it('penalizes VM indicators', () => {
        const signals = buildCleanSignals();
        signals.vm = {
            softwareGL: 1,
            lowHardware: 1,
            vmResolution: 1,
            vmAudio: 1,
        };
        const result = validateSignals(signals);
        assert.ok(result.score < 0.5);
        assert.ok(result.flags.some((f) => f.includes('vm:')));
    });

    it('detects property tampering', () => {
        const signals = buildCleanSignals();
        signals.properties.integrity = 0;
        signals.properties.overrides = 3;
        const result = validateSignals(signals);
        assert.ok(result.flags.some((f) => f.includes('properties')));
    });

    it('penalizes zero screen dimensions', () => {
        const signals = buildCleanSignals();
        signals.screen.width = 0;
        signals.screen.height = 0;
        const result = validateSignals(signals);
        assert.ok(result.flags.some((f) => f.includes('screen:zero')));
    });

    it('handles missing signal categories gracefully', () => {
        const result = validateSignals({});
        assert.equal(result.score, 1.0);
        assert.equal(result.flags.length, 0);
    });
});

function buildCleanSignals() {
    return {
        automation: { globals: 0, enhanced: 0, extra: 0 },
        browser: {
            apis: 0b11111111,
            selenium: 0,
            stealth: 0,
            advanced: 0,
        },
        properties: {
            integrity: 0b111,
            overrides: 0,
            protoInconsistency: 0,
        },
        natives: 0xfff,
        features: 0xffff,
        navigator: {
            ua:
                'Mozilla/5.0 (X11; Linux x86_64) ' +
                'AppleWebKit/537.36 (KHTML, like Gecko) ' +
                'Chrome/120.0.0.0 Safari/537.36',
            platform: 'Linux x86_64',
            pluginCount: 5,
            languageCount: 2,
            languages: ['en-US', 'en'],
            cookieEnabled: true,
            doNotTrack: '',
            hardwareConcurrency: 8,
            deviceMemory: 8,
            rtt: 50,
            downlink: 10,
            effectiveType: '4g',
            maxTouchPoints: 0,
            pdfViewerEnabled: true,
            vendor: 'Google Inc.',
            productSub: '20030107',
            appVersion: '5.0',
            uadBrands: ['Chromium/120'],
            uadMobile: false,
            uadPlatform: 'Linux',
        },
        screen: {
            width: 1920,
            height: 1080,
            availWidth: 1920,
            availHeight: 1048,
            colorDepth: 24,
            pixelDepth: 24,
            devicePixelRatio: 1,
            orientation: 'landscape-primary',
        },
        engine: {
            evalLength: 33,
            stackStyle: 'v8',
            mathTan: -1.3527613587015907e-7,
            mathAcosh: Infinity,
            bindNative: 1,
            externalType: 'undefined',
        },
        mediaQueries: {
            hover: true,
            anyHover: true,
            pointerFine: true,
            pointerCoarse: false,
            darkMode: false,
            reducedMotion: false,
            highContrast: false,
            forcedColors: false,
            colorGamutP3: true,
            colorGamutSrgb: true,
            touch: false,
        },
        environment: {
            timezoneOffset: -120,
            timezoneName: 'Europe/Berlin',
            touch: 0,
            document: 0b110,
            online: true,
            batteryApi: 1,
        },
        timing: { perfNowIdentical: false },
        webgl: {
            vendor: 'Google Inc. (NVIDIA)',
            renderer: 'ANGLE (NVIDIA, NVIDIA GeForce ...)',
            maxTextureSize: 16384,
            maxVertexAttribs: 16,
            extensionCount: 40,
        },
        canvas: {
            hash: 'a1b2c3d4',
            tampering: {
                random: 0,
                error: 0,
                inconsistent: 0,
                dataLength: 500,
            },
        },
        fonts: { widths: [100, 102, 98], count: 12 },
        headless: {
            pdfOff: 0,
            noTaskbar: 0,
            viewportMatch: 0,
            noShare: 0,
            activeTextRed: 0,
            uadBlank: 0,
            chromeKeyPosition: 0,
            runtimeConstructable: 0,
            iframeProxy: 0,
            pluginsNotArray: 0,
            mesa: 0,
        },
        vm: {
            softwareGL: 0,
            lowHardware: 0,
            vmResolution: 0,
            vmAudio: 0,
        },
        consistency: {
            clientHints: {
                hasUAData: true,
                mobileMismatch: false,
                platformMismatch: false,
            },
            screen: { dimensionLie: 0, alwaysLight: 0 },
            locale: { languagePrefix: 0, localeLie: 0 },
        },
        devtools: {
            sizeAnomaly: 0,
            widthDiff: 0,
            heightDiff: 0,
        },
        cdp: 0,
        cssVersion: 115,
        voices: {
            voiceCount: 10,
            mediaDevices: 1,
            webrtc: 1,
        },
        performance: {
            jsHeapSizeLimit: 2172649472,
            totalJSHeapSize: 50000000,
            usedJSHeapSize: 30000000,
        },
        prototype: { lieCount: 0, mimeTypeProto: 0 },
        drawing: {
            emojiWidth: 48,
            emojiHeight: 20,
            textWidth: 60,
            textAscent: 12,
            textDescent: 3,
        },
        meta: { collectedAt: Date.now(), elapsed: 50 },
    };
}
