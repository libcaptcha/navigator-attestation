import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateSignals } from '../../src/validator.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..', '..');
const PORT = parseInt(process.env.PORT || '3456');

const signalsJS = readFileSync(join(root, 'src/signals.js'), 'utf-8');
const pageHTML = readFileSync(join(__dirname, 'page.html'), 'utf-8');

const routes = {
    'GET /': (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(pageHTML);
    },
    'GET /signals.js': (req, res) => {
        res.writeHead(200, {
            'Content-Type': 'application/javascript',
        });
        res.end(signalsJS);
    },
    'GET /health': (req, res) => {
        res.writeHead(200);
        res.end('ok');
    },
    'POST /attest': (req, res) => {
        let body = '';
        req.on('data', (chunk) => {
            body += chunk;
        });
        req.on('end', () => {
            try {
                const { signals } = JSON.parse(body);
                const result = validateSignals(signals, req.headers);
                res.writeHead(200, {
                    'Content-Type': 'application/json',
                });
                res.end(JSON.stringify(result));
            } catch (error) {
                res.writeHead(400);
                res.end(JSON.stringify({ error: error.message }));
            }
        });
    },
};

const server = createServer((req, res) => {
    const key = `${req.method} ${req.url}`;
    const handler = routes[key];
    if (handler) return handler(req, res);
    res.writeHead(404);
    res.end('not found');
});

server.listen(PORT, () => {
    console.log(`READY:${PORT}`);
});
