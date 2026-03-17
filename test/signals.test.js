import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    SIGNAL_CATEGORIES,
    collectors,
    serializeSignals,
    deserializeSignals,
} from '../src/signals.js';

describe('SIGNAL_CATEGORIES', () => {
    it('contains all expected categories', () => {
        assert.ok(SIGNAL_CATEGORIES.includes('automation'));
        assert.ok(SIGNAL_CATEGORIES.includes('browser'));
        assert.ok(SIGNAL_CATEGORIES.includes('navigator'));
        assert.ok(SIGNAL_CATEGORIES.includes('webgl'));
        assert.ok(SIGNAL_CATEGORIES.includes('canvas'));
        assert.ok(SIGNAL_CATEGORIES.includes('headless'));
        assert.ok(SIGNAL_CATEGORIES.includes('vm'));
        assert.equal(SIGNAL_CATEGORIES.length, 24);
    });
});

describe('collectors', () => {
    it('has a collector for each category', () => {
        for (const category of SIGNAL_CATEGORIES) {
            assert.equal(typeof collectors[category], 'function', `missing collector: ${category}`);
        }
    });

    it('collectors return without throwing in Node', () => {
        for (const category of SIGNAL_CATEGORIES) {
            const result = collectors[category]();
            assert.ok(result !== undefined, `${category} returned undefined`);
        }
    });
});

describe('serialization', () => {
    it('round-trips signals', () => {
        const signals = {
            automation: { globals: 5, enhanced: 0, extra: 0 },
            navigator: { ua: 'test', platform: 'test' },
            meta: { collectedAt: 1234567890, elapsed: 42 },
        };
        const json = serializeSignals(signals);
        const parsed = deserializeSignals(json);
        assert.deepEqual(parsed, signals);
    });

    it('handles empty signals', () => {
        const json = serializeSignals({});
        assert.deepEqual(deserializeSignals(json), {});
    });
});
