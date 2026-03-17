# navigator-attestation

Browser environment attestation via signal collection and validation. Detects automation frameworks, headless browsers, prototype tampering, renderer spoofing, and virtualization artifacts. Returns integrity score and anomaly flags. Single runtime dependency (`ws`).

## Install

```bash
npm install navigator-attestation
```

## Usage

### Collect Signals (Browser)

```js
import { collectSignals } from 'navigator-attestation';

const signals = collectSignals();
// 24 signal categories: automation, browser, properties,
// natives, features, navigator, screen, engine,
// mediaQueries, environment, timing, webgl, canvas,
// fonts, headless, vm, consistency, devtools, cdp,
// cssVersion, voices, performance, prototype, drawing
```

### Validate Signals (Server)

```js
import { validateSignals, classifyScore } from 'navigator-attestation';

const { score, verdict, flags, categoryScores } = validateSignals(
    signals,
    headers // optional request headers for cross-validation
);
// score: 0.0-1.0
// verdict: "trusted" | "suspicious" | "likely_automated" | "automated"
// flags: ["automation:1 globals", "headless:pdf disabled"]
// categoryScores: per-category { score, flags }
```

### Simple HTTP Protocol

```js
// Server
import { createServer } from 'node:http';
import { createSimpleServer } from 'navigator-attestation';

const attestation = createSimpleServer({
    secretKey: process.env.ATTEST_SECRET, // optional
});
const server = createServer(attestation.handler());
server.listen(3000);

// Verify tokens later
const result = attestation.verifyToken(token);
```

```js
// Client (browser)
import { collectSignals } from 'navigator-attestation';

const signals = collectSignals();
const response = await fetch('/attest', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ signals, ts: Date.now() }),
});
const { score, verdict, flags, token } = await response.json();
```

### Secure WebSocket Protocol

Multi-round attestation with nonce-based replay prevention.

```js
// Server
import { createServer } from 'node:http';
import { createSecureServer } from 'navigator-attestation';

const httpServer = createServer();
const secureServer = createSecureServer({
    roundCount: 3, // signal collection rounds
    roundTimeoutMs: 15000,
    categories: undefined, // all 24 by default
});
await secureServer.attach(httpServer);
httpServer.listen(3000);
```

```js
// Client (browser)
import { createSecureClient } from 'navigator-attestation';

const client = createSecureClient({
    url: 'ws://localhost:3000',
    timeout: 30000,
});
const { score, verdict, flags, token } = await client.attest();
```

### Token Signing

```js
import { sign, verify, generateKey } from 'navigator-attestation';

const key = generateKey();
const token = sign({ score: 0.95, verdict: 'trusted' }, key);
const payload = verify(token, key); // null if invalid
```

## Protocol

```
Client                              Server
  |  POST /attest                     |
  |  { signals, ts }                  |
  |----------------------------------►|
  |  { score, verdict, flags, token } |
  |◄----------------------------------|
```

```
Client                              Server
  |  WebSocket connect                |
  |----------------------------------►|
  |  { type: "challenge", round,      |
  |    totalRounds, nonce, checks }   |
  |◄----------------------------------|
  |                                   |
  |  collectSignals(checks)           |
  |                                   |
  |  { nonce, round, signals }        |
  |----------------------------------►|
  |  ... repeat for each round ...    |
  |                                   |
  |  { type: "result", score,         |
  |    verdict, flags, token }        |
  |◄----------------------------------|
```

## Scoring

| Range       | Verdict            | Meaning                   |
| ----------- | ------------------ | ------------------------- |
| >= 0.85     | `trusted`          | Genuine browser           |
| 0.60 - 0.84 | `suspicious`       | Some anomalies detected   |
| 0.30 - 0.59 | `likely_automated` | Strong automation signals |
| < 0.30      | `automated`        | Definite automation       |

## Signal Categories

| Category       | Detects                                           |
| -------------- | ------------------------------------------------- |
| `automation`   | WebDriver, Phantom, Selenium, Cypress, Playwright |
| `browser`      | Selenium artifacts, stealth plugin bypasses       |
| `properties`   | Prototype tampering, descriptor integrity         |
| `natives`      | toString/setTimeout/Math tampering                |
| `features`     | localStorage, WebSocket, WebGL availability       |
| `navigator`    | UA, platform, hardware, plugins, languages        |
| `screen`       | Dimensions, color depth, DPI, orientation         |
| `engine`       | V8/SpiderMonkey/JSC fingerprinting                |
| `mediaQueries` | Hover, touch, dark mode, contrast                 |
| `environment`  | Timezone, touch, focus, battery, online           |
| `timing`       | performance.now() consistency                     |
| `webgl`        | GPU vendor, renderer, capabilities                |
| `canvas`       | Fingerprint hash, tampering detection             |
| `fonts`        | Font availability probing                         |
| `headless`     | Headless-specific artifacts                       |
| `vm`           | Software GL, low hardware, VM resolutions         |
| `consistency`  | Client Hints/UA/screen/locale alignment           |
| `devtools`     | DevTools open detection                           |
| `cdp`          | Chrome DevTools Protocol markers                  |
| `cssVersion`   | CSS feature version detection                     |
| `voices`       | Speech synthesis, media devices, WebRTC           |
| `performance`  | Heap size metrics                                 |
| `prototype`    | API prototype lie detection                       |
| `drawing`      | Text/emoji rendering dimensions                   |

## Example

```bash
npm run example
# http://localhost:3000
```

## Test

```bash
npm test                  # unit tests
npm run test:e2e          # puppeteer detection
npm run test:e2e:python   # selenium/playwright detection
```


## Formatting

```bash
npx prtfm
```

## License

[MIT](LICENSE)
