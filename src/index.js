export {
    collectSignals,
    serializeSignals,
    deserializeSignals,
    collectors,
    SIGNAL_CATEGORIES,
} from './signals.js';

export { validateSignals, classifyScore, computeCategoryScores, countBits } from './validator.js';

export {
    createSimpleClient,
    createSimpleServer,
    createSecureClient,
    createSecureServer,
    sign,
    verify,
    generateNonce,
    generateKey,
} from './protocol.js';
