module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/__tests__/**/*.test.ts'],
  transform: {
    '^.+\\.(t|j)sx?$': 'babel-jest',
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  moduleNameMapper: {
    // Only remap local ESM-style imports in source files to their TS counterparts
    '^\./oauth2\\.js$': '<rootDir>/src/oauth2.ts',
    '^\./config\\.js$': '<rootDir>/src/config.ts',
  },
};
