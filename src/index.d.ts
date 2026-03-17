export type SignalCategory =
  | "automation"
  | "browser"
  | "properties"
  | "natives"
  | "features"
  | "navigator"
  | "screen"
  | "engine"
  | "mediaQueries"
  | "environment"
  | "timing"
  | "webgl"
  | "canvas"
  | "fonts"
  | "headless"
  | "vm"
  | "consistency"
  | "devtools"
  | "cdp"
  | "cssVersion"
  | "voices"
  | "performance"
  | "prototype"
  | "drawing";

export interface AutomationSignals {
  globals: number;
  enhanced: number;
  extra: number;
}

export interface BrowserSignals {
  apis: number;
  selenium: number;
  stealth: number;
  advanced: number;
}

export interface PropertySignals {
  integrity: number;
  overrides: number;
  protoInconsistency: number;
}

export interface NavigatorSignals {
  ua: string;
  platform: string;
  pluginCount: number;
  languageCount: number;
  languages: string[];
  cookieEnabled: boolean;
  doNotTrack: string;
  hardwareConcurrency: number;
  deviceMemory?: number;
  rtt?: number;
  downlink?: number;
  effectiveType?: string;
  maxTouchPoints: number;
  pdfViewerEnabled: boolean;
  vendor: string;
  productSub: string;
  appVersion: string;
  uadBrands: string[];
  uadMobile?: boolean;
  uadPlatform?: string;
}

export interface ScreenSignals {
  width: number;
  height: number;
  availWidth: number;
  availHeight: number;
  colorDepth: number;
  pixelDepth: number;
  devicePixelRatio: number;
  orientation: string;
  isExtended?: boolean;
}

export interface EngineSignals {
  evalLength: number;
  stackStyle: "v8" | "spidermonkey" | "jsc" | "unknown";
  mathTan: number;
  mathAcosh: number;
  bindNative: number;
  externalType?: string;
}

export interface MediaQuerySignals {
  hover: boolean;
  anyHover: boolean;
  pointerFine: boolean;
  pointerCoarse: boolean;
  darkMode: boolean;
  reducedMotion: boolean;
  highContrast: boolean;
  forcedColors: boolean;
  colorGamutP3: boolean;
  colorGamutSrgb: boolean;
  touch: boolean;
}

export interface EnvironmentSignals {
  timezoneOffset: number;
  timezoneName: string;
  touch: number;
  document: number;
  online?: boolean;
  batteryApi: number;
}

export interface TimingSignals {
  perfNowIdentical: boolean;
}

export interface WebGLSignals {
  vendor: string;
  renderer: string;
  maxTextureSize: number;
  maxVertexAttribs: number;
  extensionCount: number;
}

export interface CanvasTampering {
  random: number;
  error: number;
  inconsistent: number;
  dataLength: number;
}

export interface CanvasSignals {
  hash: string;
  tampering: CanvasTampering | null;
}

export interface FontSignals {
  widths: number[];
  count: number;
}

export interface HeadlessSignals {
  pdfOff: number;
  noTaskbar: number;
  viewportMatch: number;
  noShare: number;
  activeTextRed: number;
  uadBlank: number;
  chromeKeyPosition: number;
  runtimeConstructable: number;
  iframeProxy: number;
  pluginsNotArray: number;
  mesa: number;
}

export interface VMSignals {
  softwareGL: number;
  lowHardware: number;
  vmResolution: number;
  vmAudio: number;
}

export interface ClientHintsConsistency {
  hasUAData: boolean;
  mobileMismatch: boolean;
  platformMismatch: boolean;
}

export interface ScreenConsistency {
  dimensionLie: number;
  alwaysLight: number;
}

export interface LocaleConsistency {
  languagePrefix: number;
  localeLie: number;
}

export interface ConsistencySignals {
  clientHints: ClientHintsConsistency;
  screen: ScreenConsistency;
  locale: LocaleConsistency;
}

export interface DevtoolsSignals {
  sizeAnomaly: number;
  widthDiff: number;
  heightDiff: number;
}

export interface VoiceSignals {
  voiceCount: number;
  mediaDevices: number;
  webrtc: number;
}

export interface PerformanceSignals {
  jsHeapSizeLimit?: number;
  totalJSHeapSize?: number;
  usedJSHeapSize?: number;
}

export interface PrototypeSignals {
  lieCount: number;
  mimeTypeProto: number;
}

export interface DrawingSignals {
  emojiWidth: number;
  emojiHeight: number;
  textWidth: number;
  textAscent: number;
  textDescent: number;
}

export interface MetaSignals {
  collectedAt: number;
  elapsed: number;
}

export interface Signals {
  automation?: AutomationSignals;
  browser?: BrowserSignals;
  properties?: PropertySignals;
  natives?: number;
  features?: number;
  navigator?: NavigatorSignals;
  screen?: ScreenSignals;
  engine?: EngineSignals;
  mediaQueries?: MediaQuerySignals | null;
  environment?: EnvironmentSignals;
  timing?: TimingSignals;
  webgl?: WebGLSignals | null;
  canvas?: CanvasSignals;
  fonts?: FontSignals;
  headless?: HeadlessSignals;
  vm?: VMSignals;
  consistency?: ConsistencySignals;
  devtools?: DevtoolsSignals;
  cdp?: number;
  cssVersion?: number;
  voices?: VoiceSignals;
  performance?: PerformanceSignals;
  prototype?: PrototypeSignals;
  drawing?: DrawingSignals;
  meta?: MetaSignals;
}

export type Verdict =
  | "trusted"
  | "suspicious"
  | "likely_automated"
  | "automated";

export interface CategoryScore {
  score: number;
  flags: string[];
}

export interface ValidationResult {
  score: number;
  flags: string[];
  verdict: Verdict;
  categoryScores: Record<string, CategoryScore>;
}

export interface Challenge {
  type: "challenge";
  round: number;
  totalRounds: number;
  nonce: string;
  checks: string[];
}

export interface SecureResult {
  type: "result";
  score: number;
  verdict: Verdict;
  flags: string[];
  categoryScores: Record<string, CategoryScore>;
  rounds: number;
  token: string;
}

export interface SecureError {
  type: "error";
  reason: string;
}

export declare const SIGNAL_CATEGORIES: SignalCategory[];

export declare function collectSignals(
  categories?: SignalCategory[]
): Signals;

export declare function serializeSignals(
  signals: Signals
): string;

export declare function deserializeSignals(
  json: string
): Signals;

export declare const collectors: Record<
  SignalCategory,
  () => unknown
>;

export declare function validateSignals(
  signals: Signals,
  headers?: Record<string, string>
): ValidationResult;

export declare function classifyScore(
  score: number
): Verdict;

export declare function computeCategoryScores(
  signals: Signals,
  headers?: Record<string, string>
): Record<string, CategoryScore>;

export declare function countBits(n: number): number;

export interface SimpleClientOptions {
  endpoint?: string;
  fetchFn?: typeof fetch;
}

export interface SimpleClient {
  attest(
    extraHeaders?: Record<string, string>
  ): Promise<ValidationResult & { token: string }>;
}

export declare function createSimpleClient(
  options?: SimpleClientOptions
): SimpleClient;

export interface SimpleServerOptions {
  secretKey?: string;
}

export interface SimpleServer {
  handler(): (
    request: import("node:http").IncomingMessage,
    response: import("node:http").ServerResponse
  ) => void;
  verifyToken(
    token: string
  ): ValidationResult | null;
  secretKey: string;
}

export declare function createSimpleServer(
  options?: SimpleServerOptions
): SimpleServer;

export interface SecureClientOptions {
  url?: string;
  WebSocketImpl?: new (url: string) => WebSocket;
  timeout?: number;
}

export interface SecureClient {
  attest(): Promise<SecureResult>;
}

export declare function createSecureClient(
  options?: SecureClientOptions
): SecureClient;

export interface SecureServerOptions {
  secretKey?: string;
  roundCount?: number;
  roundTimeoutMs?: number;
  categories?: SignalCategory[];
}

export interface SecureServer {
  attach(
    httpServer: import("node:http").Server
  ): Promise<import("ws").WebSocketServer>;
  createSession(connectionId: string): unknown;
  nextChallenge(session: unknown): Challenge | null;
  processResponse(
    session: unknown,
    message: {
      nonce: string;
      round: number;
      signals: Signals;
    }
  ): Challenge | SecureResult | SecureError;
  verifyToken(
    token: string
  ): Record<string, unknown> | null;
  secretKey: string;
}

export declare function createSecureServer(
  options?: SecureServerOptions
): SecureServer;

export declare function sign(
  payload: unknown,
  secretKey: string
): string;

export declare function verify(
  token: string,
  secretKey: string
): unknown | null;

export declare function generateNonce(): string;

export declare function generateKey(): string;
