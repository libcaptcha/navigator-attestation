import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    sign,
    verify,
    generateNonce,
    generateKey,
    createSimpleServer,
    createSecureServer,
} from '../src/protocol.js';

describe('crypto utilities', () => {
    it('generates unique nonces', () => {
        const a = generateNonce();
        const b = generateNonce();
        assert.notEqual(a, b);
        assert.equal(a.length, 32);
    });

    it('generates unique keys', () => {
        const a = generateKey();
        const b = generateKey();
        assert.notEqual(a, b);
        assert.equal(a.length, 64);
    });

    it('signs and verifies payload', () => {
        const key = generateKey();
        const payload = { score: 0.95, flags: [] };
        const token = sign(payload, key);
        const result = verify(token, key);
        assert.deepEqual(result, payload);
    });

    it('rejects tampered token', () => {
        const key = generateKey();
        const token = sign({ test: true }, key);
        const tampered = 'x' + token.slice(1);
        assert.equal(verify(tampered, key), null);
    });

    it('rejects wrong key', () => {
        const token = sign({ test: true }, generateKey());
        assert.equal(verify(token, generateKey()), null);
    });

    it('rejects token without dot', () => {
        assert.equal(verify('nodot', generateKey()), null);
    });
});

describe('SimpleServer', () => {
    it('creates server with secret key', () => {
        const server = createSimpleServer();
        assert.ok(server.secretKey);
        assert.ok(server.handler);
        assert.ok(server.verifyToken);
    });

    it('verifies its own tokens', () => {
        const server = createSimpleServer();
        const token = sign({ score: 1.0 }, server.secretKey);
        const result = server.verifyToken(token);
        assert.deepEqual(result, { score: 1.0 });
    });
});

describe('SecureServer', () => {
    it('creates sessions and challenges', () => {
        const server = createSecureServer({
            roundCount: 3,
        });
        const session = server.createSession('test-1');
        const challenge = server.nextChallenge(session);

        assert.equal(challenge.type, 'challenge');
        assert.equal(challenge.round, 1);
        assert.equal(challenge.totalRounds, 3);
        assert.ok(challenge.nonce);
        assert.ok(challenge.checks.length > 0);
    });

    it('processes rounds and finalizes', () => {
        const server = createSecureServer({
            roundCount: 2,
            categories: ['automation', 'navigator'],
        });
        const session = server.createSession('test-2');

        const c1 = server.nextChallenge(session);
        const r1 = server.processResponse(session, {
            nonce: c1.nonce,
            round: c1.round,
            signals: {
                automation: {
                    globals: 0,
                    enhanced: 0,
                    extra: 0,
                },
            },
        });

        if (r1.type === 'challenge') {
            const r2 = server.processResponse(session, {
                nonce: r1.nonce,
                round: r1.round,
                signals: {
                    navigator: {
                        ua: 'Mozilla/5.0 Chrome/120',
                        platform: 'Linux',
                        pluginCount: 5,
                        languageCount: 2,
                        languages: ['en'],
                        cookieEnabled: true,
                        doNotTrack: '',
                        hardwareConcurrency: 8,
                        deviceMemory: 8,
                        maxTouchPoints: 0,
                        pdfViewerEnabled: true,
                        vendor: 'Google Inc.',
                        productSub: '20030107',
                        appVersion: '5.0',
                        uadBrands: [],
                    },
                },
            });
            assert.equal(r2.type, 'result');
            assert.ok(r2.token);
            assert.ok(typeof r2.score === 'number');
        }
    });

    it('rejects invalid nonce', () => {
        const server = createSecureServer({
            roundCount: 1,
            categories: ['automation'],
        });
        const session = server.createSession('test-3');
        server.nextChallenge(session);

        const result = server.processResponse(session, {
            nonce: 'wrong-nonce',
            round: 1,
            signals: {},
        });
        assert.equal(result.type, 'error');
        assert.equal(result.reason, 'invalid nonce');
    });

    it('rejects wrong round number', () => {
        const server = createSecureServer({
            roundCount: 1,
            categories: ['automation'],
        });
        const session = server.createSession('test-4');
        const challenge = server.nextChallenge(session);

        const result = server.processResponse(session, {
            nonce: challenge.nonce,
            round: 5,
            signals: {},
        });
        assert.equal(result.type, 'error');
        assert.equal(result.reason, 'wrong round');
    });

    it('verifies finalized tokens', () => {
        const server = createSecureServer({
            roundCount: 1,
            categories: ['automation'],
        });
        const session = server.createSession('test-5');
        const challenge = server.nextChallenge(session);

        const result = server.processResponse(session, {
            nonce: challenge.nonce,
            round: 1,
            signals: {
                automation: {
                    globals: 0,
                    enhanced: 0,
                    extra: 0,
                },
            },
        });

        assert.equal(result.type, 'result');
        const verified = server.verifyToken(result.token);
        assert.ok(verified);
        assert.ok(typeof verified.score === 'number');
    });
});
