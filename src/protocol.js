import { createHmac, randomBytes } from 'node:crypto';
import { collectSignals, SIGNAL_CATEGORIES } from './signals.js';
import { validateSignals } from './validator.js';

function generateNonce() {
    return randomBytes(16).toString('hex');
}

function generateKey() {
    return randomBytes(32).toString('hex');
}

function sign(payload, secretKey) {
    const json = typeof payload === 'string' ? payload : JSON.stringify(payload);
    const signature = createHmac('sha256', secretKey).update(json).digest('base64url');
    return `${Buffer.from(json).toString('base64url')}.${signature}`;
}

function verify(token, secretKey) {
    const dotIndex = token.indexOf('.');
    if (dotIndex === -1) return null;

    const payloadB64 = token.slice(0, dotIndex);
    const receivedSig = token.slice(dotIndex + 1);
    const json = Buffer.from(payloadB64, 'base64url').toString();
    const expectedSig = createHmac('sha256', secretKey).update(json).digest('base64url');

    if (receivedSig !== expectedSig) return null;

    try {
        return JSON.parse(json);
    } catch {
        return null;
    }
}

function createSimpleClient(options = {}) {
    const { endpoint = '/attest', fetchFn = globalThis.fetch } = options;

    async function attest(extraHeaders = {}) {
        const signals = collectSignals();
        const response = await fetchFn(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...extraHeaders,
            },
            body: JSON.stringify({ signals, ts: Date.now() }),
        });

        if (!response.ok) {
            throw new Error(`Attestation failed: ${response.status}`);
        }

        return response.json();
    }

    return { attest };
}

function createSimpleServer(options = {}) {
    const { secretKey = generateKey() } = options;

    function handler() {
        return (request, response) => {
            if (request.method !== 'POST') {
                response.writeHead(405);
                response.end('{"error":"method not allowed"}');
                return;
            }

            let body = '';
            request.on('data', (chunk) => {
                body += chunk;
            });
            request.on('end', () => {
                try {
                    const { signals } = JSON.parse(body);
                    const headers = request.headers || {};
                    const result = validateSignals(signals, headers);
                    const token = sign(result, secretKey);

                    response.writeHead(200, {
                        'Content-Type': 'application/json',
                    });
                    response.end(
                        JSON.stringify({
                            ...result,
                            token,
                        })
                    );
                } catch (error) {
                    response.writeHead(400);
                    response.end(JSON.stringify({ error: error.message }));
                }
            });
        };
    }

    function verifyToken(token) {
        return verify(token, secretKey);
    }

    return { handler, verifyToken, secretKey };
}

function shuffleArray(array) {
    const shuffled = [...array];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
}

function splitIntoRounds(categories, roundCount) {
    const shuffled = shuffleArray(categories);
    const rounds = Array.from({ length: roundCount }, () => []);
    for (let i = 0; i < shuffled.length; i++) {
        rounds[i % roundCount].push(shuffled[i]);
    }
    return rounds;
}

function createSecureServer(options = {}) {
    const {
        secretKey = generateKey(),
        roundCount = 3,
        roundTimeoutMs = 15000,
        categories = [...SIGNAL_CATEGORIES],
    } = options;

    const sessions = new Map();

    function createSession(connectionId) {
        const rounds = splitIntoRounds(categories, roundCount);
        const session = {
            id: connectionId,
            currentRound: 0,
            rounds,
            nonces: [],
            allSignals: {},
            allFlags: [],
            startedAt: Date.now(),
        };
        sessions.set(connectionId, session);
        return session;
    }

    function nextChallenge(session) {
        if (session.currentRound >= session.rounds.length) {
            return null;
        }

        const nonce = generateNonce();
        session.nonces.push(nonce);

        return {
            type: 'challenge',
            round: session.currentRound + 1,
            totalRounds: session.rounds.length,
            nonce,
            checks: session.rounds[session.currentRound],
        };
    }

    function processResponse(session, message) {
        const { nonce, round, signals } = message;
        const expectedNonce = session.nonces[session.currentRound];

        if (nonce !== expectedNonce) {
            return { type: 'error', reason: 'invalid nonce' };
        }
        if (round !== session.currentRound + 1) {
            return { type: 'error', reason: 'wrong round' };
        }

        Object.assign(session.allSignals, signals);

        const roundResult = validateSignals(signals);
        session.allFlags.push(...roundResult.flags);

        session.currentRound++;

        const challenge = nextChallenge(session);
        if (challenge) return challenge;

        return finalize(session);
    }

    function finalize(session) {
        const fullResult = validateSignals(session.allSignals);
        const token = sign(
            {
                score: fullResult.score,
                flags: fullResult.flags,
                rounds: session.rounds.length,
                sessionId: session.id,
                ts: Date.now(),
            },
            secretKey
        );

        sessions.delete(session.id);

        return {
            type: 'result',
            score: fullResult.score,
            verdict: fullResult.verdict,
            flags: fullResult.flags,
            categoryScores: fullResult.categoryScores,
            rounds: session.rounds.length,
            token,
        };
    }

    function attach(httpServer) {
        return importWS().then((WebSocketServer) => {
            const wss = new WebSocketServer({ server: httpServer });

            wss.on('connection', (ws) => {
                const connectionId = generateNonce();
                const session = createSession(connectionId);
                const challenge = nextChallenge(session);

                ws.send(JSON.stringify(challenge));

                const timeout = setTimeout(() => {
                    sessions.delete(connectionId);
                    ws.close(4001, 'timeout');
                }, roundTimeoutMs * roundCount);

                ws.on('message', (data) => {
                    try {
                        const message = JSON.parse(String(data));
                        const response = processResponse(session, message);
                        ws.send(JSON.stringify(response));

                        if (response.type === 'result' || response.type === 'error') {
                            clearTimeout(timeout);
                            if (response.type === 'error') ws.close(4002);
                        }
                    } catch {
                        ws.send(
                            JSON.stringify({
                                type: 'error',
                                reason: 'invalid message',
                            })
                        );
                        ws.close(4003);
                        clearTimeout(timeout);
                    }
                });

                ws.on('close', () => {
                    clearTimeout(timeout);
                    sessions.delete(connectionId);
                });
            });

            return wss;
        });
    }

    function verifyToken(token) {
        return verify(token, secretKey);
    }

    return {
        attach,
        createSession,
        nextChallenge,
        processResponse,
        verifyToken,
        secretKey,
    };
}

async function importWS() {
    const ws = await import('ws');
    return ws.WebSocketServer || ws.default.WebSocketServer;
}

function createSecureClient(options = {}) {
    const {
        url = 'ws://localhost:3000',
        WebSocketImpl = globalThis.WebSocket,
        timeout = 30000,
    } = options;

    function attest() {
        return new Promise((resolve, reject) => {
            const ws = new WebSocketImpl(url);
            const timer = setTimeout(() => {
                ws.close();
                reject(new Error('attestation timeout'));
            }, timeout);

            ws.onmessage = (event) => {
                try {
                    const message = JSON.parse(
                        typeof event.data === 'string' ? event.data : event.data.toString()
                    );
                    handleMessage(ws, message, timer, resolve);
                } catch (error) {
                    clearTimeout(timer);
                    reject(error);
                }
            };

            ws.onerror = (error) => {
                clearTimeout(timer);
                reject(error);
            };

            ws.onclose = (event) => {
                clearTimeout(timer);
                if (event.code >= 4000) {
                    reject(new Error(`server closed: ${event.reason || event.code}`));
                }
            };
        });
    }

    function handleMessage(ws, message, timer, resolve) {
        if (message.type === 'challenge') {
            const signals = collectSignals(message.checks);
            ws.send(
                JSON.stringify({
                    nonce: message.nonce,
                    round: message.round,
                    signals,
                })
            );
            return;
        }

        if (message.type === 'result') {
            clearTimeout(timer);
            ws.close();
            resolve(message);
            return;
        }

        if (message.type === 'error') {
            clearTimeout(timer);
            ws.close();
            throw new Error(`attestation error: ${message.reason}`);
        }
    }

    return { attest };
}

export {
    createSimpleClient,
    createSimpleServer,
    createSecureClient,
    createSecureServer,
    sign,
    verify,
    generateNonce,
    generateKey,
};
