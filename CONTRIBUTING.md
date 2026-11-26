# Contributing

Thanks for helping improve secretsweep. Small, focused pull requests are easiest to review.

## Setup

Nothing to install:

```sh
git clone <your fork>
cd secretsweep
npm test
npm run check:cjs
```

Node.js 18 or newer is required. The project has no dependencies, so there is no lockfile to update.

## Ground rules

- Never commit a real credential or a literal that looks like one. Build fake tokens in code, for example `'ghp_' + 'A'.repeat(36)`.
- Keep detector patterns linear-time. The registry rejects nested repeats, backreferences and stacked quantifiers.
- Reports must never include raw secret values. Emit a masked preview and a fingerprint.
- Add tests for both a positive case and a negative case.
- Run `npm test` and `npm run check:cjs` before opening a pull request.

## Add a Provider Detector in five minutes

1. Open `src/detectors/builtins.mjs`.
2. Add one call to `createPatternDetector` with a unique kebab-case id, a provider name, a severity and a bounded regular expression:

   ```js
   createPatternDetector({
     id: 'example-provider-token',
     provider: 'Example Provider',
     name: 'Example provider API token',
     severity: 'high',
     pattern: /\bexp_[A-Za-z0-9]{32}\b/g,
   });
   ```

3. If the token is captured by a group rather than the whole match, pass a `value` function:

   ```js
   value: (match) => match[1],
   ```

4. Add tests in `tests/detectors.test.mjs`. Construct the fake token at runtime:

   ```js
   test('example-provider-token detects a synthetic token', () => {
     const value = 'exp_' + 'A'.repeat(32);
     assert.equal(detect('example-provider-token', value).length, 1);
   });
   ```

5. Run `npm test && npm run build:cjs && npm run check:cjs`, then open the pull request.

That is it. No dependency changes and no build system changes are needed.

## Testing

```sh
npm test              # node:test suite
npm run test:coverage # coverage report
npm run check:cjs     # verify the committed CommonJS artifact
npm run build:cjs     # regenerate cjs/index.cjs after editing src/
```

The ESM sources in `src/` are the single source of truth. Always regenerate `cjs/index.cjs` when you change a source file.

## Commit style

Use a short imperative subject line. Avoid generated attribution trailers. Keep personal information and local paths out of tracked files.
