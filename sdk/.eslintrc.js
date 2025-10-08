module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true
  },
  extends: [
    'eslint:recommended'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module'
  },
  rules: {
    // Allow console statements in SDK
    'no-console': 'off',
    // Allow unused vars with underscore prefix
    'no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }],
    // Allow async without await
    'require-await': 'off',
    // Allow undefined globals (for server-side functions)
    'no-undef': 'warn',
    // Allow control characters in regex
    'no-control-regex': 'off',
    // Allow unnecessary escapes
    'no-useless-escape': 'off',
    // Allow extra semicolons
    'no-extra-semi': 'off',
    // Allow prototype methods
    'no-prototype-builtins': 'off',
    // Allow duplicate keys (will be overridden)
    'no-dupe-keys': 'warn'
  },
  globals: {
    // Browser globals
    'window': 'readonly',
    'document': 'readonly',
    'localStorage': 'readonly',
    'sessionStorage': 'readonly',
    // Node.js globals
    'process': 'readonly',
    'Buffer': 'readonly',
    'global': 'readonly'
  }
};
