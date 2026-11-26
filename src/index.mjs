// secretsweep public API. Zero runtime dependencies.

export { VERSION, fingerprint, maskValue, shannonEntropy, isPlaceholder, analyzePattern } from './util.mjs';
export { detectors, listDetectors, getDetector, registerDetector, createPatternDetector } from './detectors/index.mjs';
export { scanText } from './finder.mjs';
export { scanPath, scanDiff, looksBinary, isBinaryPath, DEFAULT_MAX_FILE_BYTES } from './scanner.mjs';
export { readBaseline, applyBaseline, writeBaseline, baselineKey } from './baseline.mjs';
export { formatText, formatJson, formatSarif, format, sortFindings } from './output.mjs';
