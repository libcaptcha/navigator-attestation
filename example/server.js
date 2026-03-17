import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSimpleServer, createSecureServer } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const simpleServer = createSimpleServer();
const secureServer = createSecureServer({ roundCount: 3 });

const httpServer = createServer((request, response) => {
    if (request.url === '/' || request.url === '/index.html') {
        const html = readFileSync(join(__dirname, 'public/index.html'), 'utf-8');
        response.writeHead(200, {
            'Content-Type': 'text/html',
        });
        response.end(html);
        return;
    }

    if (request.url === '/attest') {
        simpleServer.handler()(request, response);
        return;
    }

    if (request.url?.startsWith('/src/')) {
        try {
            const file = readFileSync(join(__dirname, '..', request.url), 'utf-8');
            response.writeHead(200, { 'Content-Type': 'application/javascript' });
            response.end(file);
            return;
        } catch {
            response.writeHead(404);
            response.end('not found');
            return;
        }
    }

    response.writeHead(404);
    response.end('not found');
});

secureServer.attach(httpServer).then(() => {
    httpServer.listen(PORT, () => {
        console.log(`http://localhost:${PORT}`);
        console.log(`ws://localhost:${PORT} (secure)`);
    });
});
