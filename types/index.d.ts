/** Potential secret reported by secretsweep. Raw values are never included. */
export interface Finding {
  detector: string;
  provider: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  line: number;
  column: number;
  redacted: string;
  fingerprint: string;
  file?: string;
}

export interface DetectorInfo {
  id: string;
  provider: string;
  name: string;
  severity: Finding['severity'];
}

export interface DetectorDescriptor {
  id: string;
  provider?: string;
  name?: string;
  severity?: Finding['severity'];
  pattern?: RegExp;
  check: (text: string) => Array<{ value: string; index?: number }>;
}

export interface ScanOptions {
  detectors?: string[];
  minSeverity?: Finding['severity'];
  allowPlaceholder?: boolean;
  maxFileBytes?: number;
  exclude?: string[];
  ignoreRules?: unknown[];
}

export interface ScanResult {
  findings: Finding[];
  skipped: Array<{ path: string; reason: string }>;
  root: string;
}

export declare const VERSION: string;
export declare const detectors: readonly DetectorInfo[];

export declare function fingerprint(value: string): string;
export declare function maskValue(value: string): string;
export declare function shannonEntropy(value: string): number;
export declare function isPlaceholder(value: string): boolean;
export declare function analyzePattern(pattern: RegExp | string): { safe: boolean; reasons: string[] };

export declare function registerDetector(descriptor: DetectorDescriptor): DetectorInfo;
export declare function createPatternDetector(descriptor: DetectorDescriptor & { pattern: RegExp }): DetectorInfo;
export declare function listDetectors(): DetectorInfo[];
export declare function getDetector(id: string): DetectorInfo | null;

export declare function scanText(text: string, options?: ScanOptions): Finding[];
export declare function scanPath(target: string, options?: ScanOptions): ScanResult;
export declare function scanDiff(diff: string, options?: ScanOptions): Finding[];
export declare function looksBinary(buffer: Uint8Array): boolean;
export declare function isBinaryPath(path: string): boolean;

export declare const DEFAULT_MAX_FILE_BYTES: number;

export declare function baselineKey(finding: Finding): string;
export declare function readBaseline(path: string): Set<string>;
export declare function applyBaseline<T extends Finding>(findings: T[], keys: Set<string> | null): T[];
export declare function writeBaseline(path: string, findings: Finding[]): number;

export declare function formatText(findings: Finding[], options?: { cleanMessage?: string }): string;
export declare function formatJson(findings: Finding[], options?: { skipped?: unknown }): string;
export declare function formatSarif(findings: Finding[], options?: object): string;
export declare function format(findings: Finding[], formatName: 'text' | 'json' | 'sarif', options?: object): string;
export declare function sortFindings<T extends Finding>(findings: T[]): T[];
