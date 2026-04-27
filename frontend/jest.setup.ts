/**
 * Jest setup file
 * This file runs before each test suite
 */

// Mock the global fetch function
global.fetch = jest.fn(() =>
  Promise.resolve({
    json: () => Promise.resolve({ version: '1.0.0-test' }),
  } as Response)
);

// Mock the useDocUrl hook so it never fires a real fetch during tests
jest.mock('./src/helpers/useDocUrl', () => ({
  useDocUrl: (path: string) => `https://vulnscout.readthedocs.io/en/test/${path}`,
}));
