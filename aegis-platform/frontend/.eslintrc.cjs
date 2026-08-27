module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    ecmaFeatures: { jsx: true },
  },
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  plugins: ['@typescript-eslint', 'react-hooks', 'react-refresh'],
  extends: ['eslint:recommended'],
  rules: {
    'no-unused-vars': 'off',
    '@typescript-eslint/no-unused-vars': ['error', {
      args: 'after-used',
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
      caughtErrors: 'all',
      caughtErrorsIgnorePattern: '^_',
    }],
    'react-hooks/rules-of-hooks': 'error',
    'react-hooks/exhaustive-deps': 'warn',
    'react-refresh/only-export-components': 'warn',
  },
  ignorePatterns: ['dist/', 'node_modules/', 'coverage/'],
}
