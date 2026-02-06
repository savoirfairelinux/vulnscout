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
