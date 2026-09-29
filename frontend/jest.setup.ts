/**
 * Jest setup file
 * This file runs before each test suite
 */

// jsdom doesn't provide TextEncoder/TextDecoder, but react-router-dom
// references them at import time.
import { TextEncoder, TextDecoder } from 'node:util';
Object.assign(global, { TextEncoder, TextDecoder });

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

beforeEach(() => {
  window.localStorage.clear();
});
