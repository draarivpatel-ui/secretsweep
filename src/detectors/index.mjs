// Modular detector registry entry point. Importing this module registers all
// built-in detectors exactly once. Contributors can add a detector by creating
// a file in src/detectors/ and importing it here.

import { registry, registerDetector, createPatternDetector, listDetectors, getDetector } from './registry.mjs';

export const detectors = registry;
export { registerDetector, createPatternDetector, listDetectors, getDetector };

import './builtins.mjs';
