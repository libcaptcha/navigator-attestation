function countBits(n) {
    let count = 0;
    let value = n >>> 0;
    while (value) {
        count += value & 1;
        value >>>= 1;
    }
    return count;
}

function penalty(state, amount, reason) {
    state.score = Math.max(0, state.score - amount);
    state.flags.push(reason);
}

function checkAutomation(signals, state) {
    const { automation } = signals;
    if (!automation) return;

    const globalBits = countBits(automation.globals);
    if (globalBits > 0) {
        penalty(
            state,
            Math.min(0.5, globalBits * 0.15),
            `automation:${globalBits} globals detected`
        );
    }

    const enhancedBits = countBits(automation.enhanced);
    if (enhancedBits > 0) {
        penalty(
            state,
            Math.min(0.5, enhancedBits * 0.12),
            `automation:${enhancedBits} enhanced signals`
        );
    }

    const extraBits = countBits(automation.extra);
    if (extraBits > 0) {
        penalty(state, Math.min(0.5, extraBits * 0.12), `automation:${extraBits} extra globals`);
    }
}

function checkBrowserAPIs(signals, state) {
    const { browser } = signals;
    if (!browser) return;
    const ua = signals.navigator?.ua || '';
    const isChrome = /Chrome/.test(ua);

    if (isChrome) {
        if (!(browser.apis & 1)) penalty(state, 0.08, 'browser:chrome missing');
        if (!(browser.apis & 2)) penalty(state, 0.05, 'browser:permissions missing');
    }
    if (!(browser.apis & 4)) penalty(state, 0.1, 'browser:no languages');

    const seleniumBits = countBits(browser.selenium);
    if (seleniumBits > 0) {
        penalty(
            state,
            Math.min(0.5, seleniumBits * 0.08),
            `browser:${seleniumBits} selenium artifacts`
        );
    }

    const stealthBits = countBits(browser.stealth & ~128);
    if (stealthBits > 0) {
        penalty(state, Math.min(0.5, stealthBits * 0.08), `browser:${stealthBits} stealth signals`);
    }

    const advancedBits = countBits(browser.advanced);
    if (advancedBits >= 3) {
        penalty(state, 0.35, `browser:${advancedBits} advanced detection`);
    } else if (advancedBits > 0) {
        penalty(state, advancedBits * 0.08, `browser:${advancedBits} advanced detection`);
    }
}

function checkProperties(signals, state) {
    const { properties } = signals;
    if (!properties) return;

    const { integrity } = properties;
    if (!(integrity & 1)) penalty(state, 0.1, 'properties:defineProperty tampered');
    if (!(integrity & 2)) penalty(state, 0.1, 'properties:getOwnPropDesc tampered');
    if (!(integrity & 4)) penalty(state, 0.08, 'properties:Reflect.get tampered');
    if (integrity & (1 << 10)) penalty(state, 0.1, 'properties:navigator.toString wrong');
    if (integrity & (1 << 11)) penalty(state, 0.15, 'properties:navigator.toString throws');
    if (integrity & (1 << 13)) penalty(state, 0.1, 'properties:toStringTag wrong');
    if (integrity & (1 << 14)) penalty(state, 0.15, 'properties:proto getter not native');
    if (integrity & (1 << 15)) penalty(state, 0.1, 'properties:Reflect.get tampered v2');

    if (properties.overrides > 0) {
        penalty(
            state,
            Math.min(0.3, properties.overrides * 0.1),
            `properties:${properties.overrides} overrides`
        );
    }

    if (properties.protoInconsistency > 0) penalty(state, 0.15, 'properties:proto inconsistency');
}

function checkNatives(signals, state) {
    if (signals.natives === undefined) return;
    const expected = 0xfff;
    const tampered = ~signals.natives & expected;
    const bits = countBits(tampered);
    if (bits > 0) {
        penalty(state, Math.min(0.4, bits * 0.08), `natives:${bits} tampered functions`);
    }
}

function checkFeatures(signals, state) {
    if (signals.features === undefined) return;
    const missing = ~signals.features & 0x7ff;
    const bits = countBits(missing);
    if (bits > 3) penalty(state, 0.15, `features:${bits} missing`);

    const hasAdvanced = (signals.features & 0x30) === 0x30;
    const missingBasic = !(signals.features & 1) || !(signals.features & 4);
    if (hasAdvanced && missingBasic) penalty(state, 0.2, 'features:inconsistent');
}

function checkNavigator(signals, state) {
    const nav = signals.navigator;
    if (!nav) return;

    if (nav.hardwareConcurrency === 1) penalty(state, 0.08, 'navigator:1 core');
    if (nav.hardwareConcurrency === 0) penalty(state, 0.15, 'navigator:0 cores');
    if (nav.languageCount === 0 && !/mobile|android/i.test(nav.ua))
        penalty(state, 0.12, 'navigator:no languages');

    if (nav.deviceMemory !== undefined && nav.deviceMemory !== null) {
        const valid = [0.25, 0.5, 1, 2, 4, 8, 16, 32, 64];
        if (!valid.includes(nav.deviceMemory))
            penalty(state, 0.1, 'navigator:invalid deviceMemory');
    }

    if (nav.rtt === 0) penalty(state, 0.05, 'navigator:rtt=0');

    const ua = nav.ua;
    if (/Chrome/.test(ua) && nav.productSub !== '20030107')
        penalty(state, 0.08, 'navigator:wrong productSub');
    if (/Firefox/.test(ua) && nav.productSub !== '20100101')
        penalty(state, 0.08, 'navigator:wrong productSub');
    if (/Chrome/.test(ua) && nav.vendor !== 'Google Inc.')
        penalty(state, 0.08, 'navigator:wrong vendor');
}

function checkScreen(signals, state) {
    const scr = signals.screen;
    if (!scr) return;

    if (scr.width === 0 || scr.height === 0) penalty(state, 0.15, 'screen:zero dimensions');
    if ((scr.width === 800 && scr.height === 600) || (scr.width === 1024 && scr.height === 768))
        penalty(state, 0.1, 'screen:VM-typical resolution');
    if (scr.colorDepth > 0 && scr.colorDepth < 24) penalty(state, 0.1, 'screen:low colorDepth');
    if (scr.devicePixelRatio === 0) penalty(state, 0.1, 'screen:zero DPR');
}

function checkEngine(signals, state) {
    const eng = signals.engine;
    if (!eng) return;
    const ua = signals.navigator?.ua || '';

    if (/Chrome/.test(ua) && eng.evalLength !== 33)
        penalty(state, 0.1, 'engine:wrong eval length Chrome');
    if (/Firefox/.test(ua) && eng.evalLength !== 37)
        penalty(state, 0.1, 'engine:wrong eval length Firefox');
    if (eng.stackStyle === 'v8' && /Firefox/.test(ua))
        penalty(state, 0.15, 'engine:V8 stack in Firefox UA');
    if (eng.stackStyle === 'spidermonkey' && /Chrome/.test(ua))
        penalty(state, 0.15, 'engine:SpiderMonkey stack in Chrome UA');
    if (eng.mathTan === 0) penalty(state, 0.05, 'engine:math fingerprint zero');
}

function checkMediaQueries(signals, state) {
    const mq = signals.mediaQueries;
    if (!mq) return;
    const ua = signals.navigator?.ua || '';

    if (!mq.pointerFine && !mq.touch) penalty(state, 0.1, 'mediaQueries:no pointer no touch');
    if (!/mobile|android/i.test(ua) && !mq.hover)
        penalty(state, 0.05, 'mediaQueries:no hover on desktop');
}

function checkEnvironment(signals, state) {
    const env = signals.environment;
    if (!env) return;

    if (env.timezoneOffset < -720 || env.timezoneOffset > 840)
        penalty(state, 0.1, 'environment:impossible timezone');
    if (env.timezoneName === 'UTC' && env.timezoneOffset !== 0)
        penalty(state, 0.1, 'environment:UTC name non-zero offset');
    if (env.timezoneName === '') penalty(state, 0.08, 'environment:empty timezone name');
    if ((env.touch & 1) !== ((env.touch >> 1) & 1))
        penalty(state, 0.05, 'environment:touch inconsistency');
    if (env.document & 1 && env.document & 2) penalty(state, 0.08, 'environment:hidden+focused');
}

function checkTiming(signals, state) {
    if (!signals.timing) return;
    if (signals.timing.perfNowIdentical) penalty(state, 0.1, 'timing:identical perf.now diffs');
}

function checkWebGL(signals, state) {
    const gl = signals.webgl;
    if (!gl) return;

    if (gl.vendor === 'Google Inc.' && /SwiftShader/.test(gl.renderer))
        penalty(state, 0.2, 'webgl:Google+SwiftShader');
    if (gl.maxTextureSize === 0) penalty(state, 0.1, 'webgl:zero maxTextureSize');
    if (/SwiftShader|llvmpipe|softpipe/i.test(gl.renderer))
        penalty(state, 0.2, 'webgl:software renderer');
}

function checkCanvas(signals, state) {
    const cv = signals.canvas;
    if (!cv) return;

    if (cv.hash === 'err') penalty(state, 0.1, 'canvas:error');
    if (cv.tampering) {
        if (cv.tampering.random) penalty(state, 0.25, 'canvas:randomization');
        if (cv.tampering.error) penalty(state, 0.05, 'canvas:tampering error');
        if (cv.tampering.inconsistent) penalty(state, 0.15, 'canvas:data/pixel mismatch');
    }
}

function checkFonts(signals, state) {
    if (!signals.fonts) return;
    if (signals.fonts.count === 0 && signals.fonts.widths?.length > 0)
        penalty(state, 0.1, 'fonts:zero detected');
}

function checkHeadless(signals, state) {
    const h = signals.headless;
    if (!h) return;
    const ua = signals.navigator?.ua || '';
    const isChrome = /Chrome/.test(ua);
    const isLinux = /Linux/.test(ua) && !/Android/.test(ua);

    if (isChrome && h.pdfOff) penalty(state, 0.1, 'headless:pdf viewer disabled');
    if (h.noTaskbar) penalty(state, 0.03, 'headless:no taskbar');
    if (h.viewportMatch) penalty(state, 0.04, 'headless:viewport matches screen');
    if (isChrome && !isLinux && h.noShare) penalty(state, 0.02, 'headless:no Web Share API');
    if (!isLinux && h.activeTextRed) penalty(state, 0.05, 'headless:ActiveText red');
    if (h.uadBlank) penalty(state, 0.12, 'headless:blank UAData platform');
    if (h.runtimeConstructable) penalty(state, 0.12, 'headless:runtime constructable');
    if (h.iframeProxy) penalty(state, 0.15, 'headless:iframe proxy detected');
    if (h.pluginsNotArray) penalty(state, 0.1, 'headless:plugins not PluginArray');
    if (h.mesa) penalty(state, 0.2, 'headless:Mesa OffScreen renderer');
}

function checkVM(signals, state) {
    const vmd = signals.vm;
    if (!vmd) return;

    if (vmd.softwareGL) penalty(state, 0.2, 'vm:software/VM GL renderer');
    if (vmd.lowHardware) penalty(state, 0.06, 'vm:low hardware specs');
    if (vmd.vmResolution) penalty(state, 0.08, 'vm:VM-typical resolution');
    if (vmd.vmAudio) penalty(state, 0.1, 'vm:zero audio channels');

    const vmHits =
        (vmd.softwareGL || 0) +
        (vmd.lowHardware || 0) +
        (vmd.vmResolution || 0) +
        (vmd.vmAudio || 0);
    if (vmHits >= 3) penalty(state, 0.15, 'vm:multiple indicators');
}

function checkConsistency(signals, state) {
    const ch = signals.consistency?.clientHints;
    const sc = signals.consistency?.screen;
    const lc = signals.consistency?.locale;
    const ua = signals.navigator?.ua || '';
    const isLinux = /Linux/.test(ua) && !/Android/.test(ua);

    if (ch) {
        if (/Chrome/.test(ua) && !ch.hasUAData)
            penalty(state, 0.08, 'consistency:no UAData Chrome');
        if (ch.mobileMismatch) penalty(state, 0.1, 'consistency:mobile mismatch');
        if (ch.platformMismatch) penalty(state, 0.1, 'consistency:platform mismatch');
    }

    if (sc) {
        if (sc.dimensionLie) penalty(state, 0.15, 'consistency:screen dimensions spoofed');
        if (sc.alwaysLight) penalty(state, 0.04, 'consistency:always light scheme');
    }

    if (lc) {
        if (lc.languagePrefix) penalty(state, 0.1, 'consistency:language prefix mismatch');
        if (lc.localeLie && !isLinux)
            penalty(state, 0.02, 'consistency:locale formatting mismatch');
    }
}

function checkDevtools(signals, state) {
    if (!signals.devtools) return;
    if (signals.devtools.sizeAnomaly) penalty(state, 0.05, 'devtools:large size difference');
}

function checkCDP(signals, state) {
    if (signals.cdp) penalty(state, 0.15, 'cdp:console side-effect');
}

function checkCSSVersion(signals, state) {
    if (!signals.cssVersion || !signals.navigator) return;
    const ua = signals.navigator.ua || '';
    const match = ua.match(/Chrome\/(\d+)/);
    if (!match) return;

    const uaVersion = parseInt(match[1], 10);
    const cssVersion = signals.cssVersion;
    if (uaVersion < cssVersion || (cssVersion < 115 && uaVersion - cssVersion > 5))
        penalty(state, 0.15, 'cssVersion:UA version mismatch');
}

function checkVoices(signals, state) {
    const vms = signals.voices;
    if (!vms) return;
    const ua = signals.navigator?.ua || '';

    if (/Chrome/.test(ua) && !/Android/.test(ua)) {
        if (vms.voiceCount === -1) penalty(state, 0.08, 'voices:no speechSynthesis');
        if (!vms.mediaDevices) penalty(state, 0.1, 'voices:no mediaDevices');
    }
    if (/Chrome/.test(ua) && !vms.webrtc) penalty(state, 0.05, 'voices:no WebRTC Chrome');
}

function checkPerformance(signals, state) {
    const perf = signals.performance;
    if (!perf) return;

    if (perf.jsHeapSizeLimit && perf.totalJSHeapSize) {
        if (perf.totalJSHeapSize > perf.jsHeapSizeLimit)
            penalty(state, 0.1, 'performance:heap exceeds limit');
    }
}

function checkPrototype(signals, state) {
    const pf = signals.prototype;
    if (!pf) return;

    if (pf.lieCount > 2) {
        penalty(state, Math.min(0.4, pf.lieCount * 0.06), `prototype:${pf.lieCount} API lies`);
    } else if (pf.lieCount > 0) {
        penalty(state, pf.lieCount * 0.05, `prototype:${pf.lieCount} API lies`);
    }
    if (pf.mimeTypeProto) penalty(state, 0.1, 'prototype:MimeType proto tampered');
}

function checkDrawing(signals, state) {
    if (!signals.drawing) return;
    if (signals.drawing.emojiWidth === 0 && signals.drawing.emojiHeight === 0)
        penalty(state, 0.08, 'drawing:zero emoji dimensions');
}

function checkCrossValidation(signals, state) {
    const nav = signals.navigator;
    const gl = signals.webgl;
    const cv = signals.canvas;
    const eng = signals.engine;
    const scr = signals.screen;
    if (!nav) return;

    const ua = nav.ua || '';
    const isChromeUA = /Chrome/.test(ua) && !/Edge/.test(ua);
    const isFirefoxUA = /Firefox/.test(ua);
    const isSafariUA = /Safari/.test(ua) && !isChromeUA;
    const isLinux = /Linux/.test(ua) && !/Android/.test(ua);
    const isMac = /Mac/.test(ua);
    const renderer = gl?.renderer || '';

    if (isChromeUA && /Gecko\/\d/.test(ua) && !/like Gecko/.test(ua))
        penalty(state, 0.2, 'crossValidation:Chrome UA with Gecko engine');

    if (isFirefoxUA && /ANGLE/.test(renderer))
        penalty(state, 0.15, 'crossValidation:Firefox UA with ANGLE');

    if (isSafariUA && isLinux) penalty(state, 0.2, 'crossValidation:Safari UA on Linux');

    if (isMac && /NVIDIA|GeForce/i.test(renderer) && /Mac OS X 1[1-9]|macOS 1[2-9]/.test(ua))
        penalty(state, 0.1, 'crossValidation:NVIDIA on modern macOS');

    if (scr && isMac && scr.devicePixelRatio === 1 && scr.width > 1920)
        penalty(state, 0.08, 'crossValidation:Mac non-retina high-res');

    if (eng) {
        if (isChromeUA && eng.stackStyle === 'spidermonkey')
            penalty(state, 0.2, 'crossValidation:Chrome UA SpiderMonkey');
        if (isFirefoxUA && eng.stackStyle === 'v8')
            penalty(state, 0.2, 'crossValidation:Firefox UA V8 stack');
    }
}

function checkHeaders(headers, state) {
    if (!headers) return;

    if (!headers['accept']) penalty(state, 0.05, 'headers:no Accept');
    if (!headers['accept-language']) penalty(state, 0.05, 'headers:no Accept-Language');
    if (!headers['accept-encoding']) penalty(state, 0.05, 'headers:no Accept-Encoding');

    const ua = headers['user-agent'] || '';
    if (/HeadlessChrome|PhantomJS|SlimerJS/i.test(ua))
        penalty(state, 0.2, 'headers:headless UA string');
    if (ua && !/Mozilla\//.test(ua)) penalty(state, 0.08, 'headers:non-standard UA');
}

const CHECKS = [
    checkAutomation,
    checkBrowserAPIs,
    checkProperties,
    checkNatives,
    checkFeatures,
    checkNavigator,
    checkScreen,
    checkEngine,
    checkMediaQueries,
    checkEnvironment,
    checkTiming,
    checkWebGL,
    checkCanvas,
    checkFonts,
    checkHeadless,
    checkVM,
    checkConsistency,
    checkDevtools,
    checkCDP,
    checkCSSVersion,
    checkVoices,
    checkPerformance,
    checkPrototype,
    checkDrawing,
    checkCrossValidation,
];

function validateSignals(signals, headers) {
    const state = { score: 1.0, flags: [] };

    for (const check of CHECKS) {
        check(signals, state);
    }

    if (headers) checkHeaders(headers, state);

    return {
        score: Math.round(state.score * 10000) / 10000,
        flags: state.flags,
        verdict: classifyScore(state.score),
        categoryScores: computeCategoryScores(signals, headers),
    };
}

function classifyScore(score) {
    if (score >= 0.85) return 'trusted';
    if (score >= 0.6) return 'suspicious';
    if (score >= 0.3) return 'likely_automated';
    return 'automated';
}

function computeCategoryScores(signals, headers) {
    const categories = {};
    const categoryChecks = {
        automation: [checkAutomation],
        browser: [checkBrowserAPIs],
        properties: [checkProperties],
        natives: [checkNatives],
        features: [checkFeatures],
        navigator: [checkNavigator],
        screen: [checkScreen],
        engine: [checkEngine],
        mediaQueries: [checkMediaQueries],
        environment: [checkEnvironment],
        timing: [checkTiming],
        webgl: [checkWebGL],
        canvas: [checkCanvas],
        fonts: [checkFonts],
        headless: [checkHeadless],
        vm: [checkVM],
        consistency: [checkConsistency],
        devtools: [checkDevtools],
        cdp: [checkCDP],
        cssVersion: [checkCSSVersion],
        voices: [checkVoices],
        performance: [checkPerformance],
        prototype: [checkPrototype],
        drawing: [checkDrawing],
        crossValidation: [checkCrossValidation],
        headers: headers ? [(s, st) => checkHeaders(headers, st)] : [],
    };

    for (const [name, checks] of Object.entries(categoryChecks)) {
        const state = { score: 1.0, flags: [] };
        for (const check of checks) check(signals, state);
        categories[name] = {
            score: Math.round(state.score * 10000) / 10000,
            flags: state.flags,
        };
    }

    return categories;
}

export { validateSignals, classifyScore, computeCategoryScores, countBits };
