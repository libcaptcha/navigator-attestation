import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    getFingerprint,
    collectComponents,
    murmurHash128,
    stableStringify,
    COMPONENTS,
    COMPONENT_NAMES,
} from '../src/fingerprint.js';

describe('murmurHash128', () => {
    it('returns 32-char hex string', () => {
        const hash = murmurHash128('hello world');
        assert.equal(hash.length, 32);
        assert.match(hash, /^[0-9a-f]{32}$/);
    });

    it('is deterministic', () => {
        const a = murmurHash128('test input');
        const b = murmurHash128('test input');
        assert.equal(a, b);
    });

    it('different inputs produce different hashes', () => {
        const a = murmurHash128('input a');
        const b = murmurHash128('input b');
        assert.notEqual(a, b);
    });

    it('supports seed parameter', () => {
        const a = murmurHash128('data', 0);
        const b = murmurHash128('data', 42);
        assert.notEqual(a, b);
    });

    it('handles empty string', () => {
        const hash = murmurHash128('');
        assert.equal(hash.length, 32);
    });

    it('handles unicode input', () => {
        const hash = murmurHash128('\u{1F603} emoji test \u4e16\u754c');
        assert.equal(hash.length, 32);
    });
});

describe('stableStringify', () => {
    it('sorts object keys', () => {
        const result = stableStringify({ b: 2, a: 1, c: 3 });
        assert.equal(result, '{"a":1,"b":2,"c":3}');
    });

    it('handles nested objects', () => {
        const result = stableStringify({ z: { b: 2, a: 1 }, a: 0 });
        assert.equal(result, '{"a":0,"z":{"a":1,"b":2}}');
    });

    it('handles arrays', () => {
        const result = stableStringify([3, 1, 2]);
        assert.equal(result, '[3,1,2]');
    });

    it('handles null', () => {
        assert.equal(stableStringify(null), 'null');
    });

    it('handles strings', () => {
        assert.equal(stableStringify('hello'), '"hello"');
    });

    it('handles booleans', () => {
        assert.equal(stableStringify(true), 'true');
    });

    it('handles Infinity as null', () => {
        assert.equal(stableStringify(Infinity), 'null');
    });
});

describe('COMPONENTS', () => {
    it('has all component names', () => {
        for (const name of COMPONENT_NAMES) {
            assert.ok(typeof COMPONENTS[name] === 'function', `missing ${name}`);
        }
    });

    it('has expected components', () => {
        const expected = [
            'platform',
            'hardware',
            'screen',
            'screenResolution',
            'screenFrame',
            'timezone',
            'languages',
            'math',
            'webgl',
            'canvas',
            'fonts',
            'fontPreferences',
            'audio',
            'plugins',
            'mediaQueries',
            'contrast',
            'monochrome',
            'storage',
            'engine',
            'vendorFlavors',
            'cssVersion',
            'pdfViewer',
            'cookies',
            'applePay',
            'dateTimeLocale',
            'domBlockers',
        ];
        for (const name of expected) {
            assert.ok(COMPONENT_NAMES.includes(name), `missing ${name}`);
        }
    });

    it('new sync components are functions', () => {
        const names = [
            'screenResolution',
            'screenFrame',
            'fontPreferences',
            'contrast',
            'monochrome',
            'applePay',
            'dateTimeLocale',
            'domBlockers',
        ];
        for (const name of names) {
            assert.equal(typeof COMPONENTS[name], 'function', `${name} not a function`);
        }
    });
});

describe('collectComponents', () => {
    it('collects math components in Node', () => {
        const components = collectComponents({
            include: ['math'],
        });
        assert.ok(components.math);
        assert.equal(typeof components.math.acos, 'number');
        assert.equal(typeof components.math.sin, 'number');
    });

    it('respects exclude option', () => {
        const components = collectComponents({
            exclude: ['math', 'canvas'],
        });
        assert.equal(components.math, undefined);
        assert.equal(components.canvas, undefined);
    });

    it('respects include option', () => {
        const components = collectComponents({
            include: ['timezone', 'languages'],
        });
        assert.ok(components.timezone);
        assert.ok(components.languages);
        assert.equal(components.math, undefined);
    });
});

describe('getFingerprint', () => {
    it('returns id and components', () => {
        const result = getFingerprint();
        assert.equal(typeof result.id, 'string');
        assert.equal(result.id.length, 32);
        assert.match(result.id, /^[0-9a-f]{32}$/);
        assert.ok(result.components);
        assert.equal(typeof result.browser, 'string');
    });

    it('is deterministic', () => {
        const a = getFingerprint();
        const b = getFingerprint();
        assert.equal(a.id, b.id);
    });

    it('respects include option', () => {
        const result = getFingerprint({
            include: ['math', 'timezone'],
        });
        assert.ok(result.components.math);
        assert.ok(result.components.timezone);
        assert.equal(result.components.webgl, undefined);
    });

    it('can disable stabilization', () => {
        const stable = getFingerprint({
            stabilize: true,
        });
        const raw = getFingerprint({
            stabilize: false,
        });
        assert.equal(typeof stable.id, 'string');
        assert.equal(typeof raw.id, 'string');
    });
});

describe('new sync collectors in Node', () => {
    it('collectScreenResolution returns array', () => {
        const result = collectComponents({
            include: ['screenResolution'],
        });
        assert.ok(Array.isArray(result.screenResolution));
        assert.equal(result.screenResolution.length, 2);
    });

    it('collectContrast returns value', () => {
        const result = collectComponents({
            include: ['contrast'],
        });
        assert.ok(result.contrast === undefined || typeof result.contrast === 'number');
    });

    it('collectMonochrome returns number', () => {
        const result = collectComponents({
            include: ['monochrome'],
        });
        assert.equal(typeof result.monochrome, 'number');
    });

    it('collectDateTimeLocale returns string', () => {
        const result = collectComponents({
            include: ['dateTimeLocale'],
        });
        assert.equal(typeof result.dateTimeLocale, 'string');
    });

    it('collectApplePay returns number', () => {
        const result = collectComponents({
            include: ['applePay'],
        });
        assert.equal(typeof result.applePay, 'number');
    });

    it('total component count is 26', () => {
        assert.equal(COMPONENT_NAMES.length, 26);
    });
});
