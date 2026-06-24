// @ts-check
// Flat ESLint config for @zincapp/znvault-sdk.
//
// Written for the toolchain installed in THIS package — ESLint 8.57 and
// @typescript-eslint 6.21 — and scoped to this package's own tsconfig. Having
// a local config here also stops ESLint from climbing to the parent
// `zn-vault/eslint.config.js` (which targets a different major version and a
// tsconfig that does not include this package's files).

import js from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsparser from '@typescript-eslint/parser';

/**
 * Node + ES2022 globals used across the SDK. Declaring them keeps the core
 * `no-undef` rule satisfied for the JS-recommended config; for TS files we turn
 * `no-undef` off entirely (the TypeScript compiler already reports undefined
 * symbols, so running it on typed code is redundant and produces false
 * positives — this is the typescript-eslint recommended posture).
 */
const nodeGlobals = {
  process: 'readonly',
  console: 'readonly',
  Buffer: 'readonly',
  crypto: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  fetch: 'readonly',
};

export default [
  {
    // Global ignores (must be its own object to apply repo-wide).
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'test-types.ts'],
  },
  js.configs.recommended,
  // Type-aware linting for the published source.
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: import.meta.dirname,
      },
      globals: nodeGlobals,
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs['recommended-type-checked'].rules,
      // TypeScript handles undefined-symbol detection; no-undef on typed code
      // is redundant and yields false positives for ambient globals.
      'no-undef': 'off',
      // Allow intentionally-unused identifiers when prefixed with `_`.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    // Fastify preHandler factories return async functions to satisfy the
    // framework's `Promise<void>` preHandler contract even when a particular
    // guard has no `await` — mirroring the parent repo's stance for Fastify
    // plugins.
    files: ['src/sso/middleware.ts'],
    rules: {
      '@typescript-eslint/require-await': 'off',
    },
  },
  // Tests and tooling are not part of the build tsconfig, so lint them WITHOUT
  // type-information (no `project`) to avoid "file not found in project" errors.
  {
    files: ['test/**/*.ts', '*.config.ts', '*.config.js'],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        project: null,
      },
      globals: nodeGlobals,
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      'no-undef': 'off',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
];
