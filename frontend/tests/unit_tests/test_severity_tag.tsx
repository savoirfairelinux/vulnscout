import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';

import SeverityTag from '../../src/components/SeverityTag';

describe('SeverityTag component', () => {

  test('renders mapped color for known severity (case-insensitive)', () => {
     render(<SeverityTag severity="critical" className="extra-class" />);
     const el = screen.getByText(/critical/i);
     expect(el).toBeInTheDocument();
     expect(el.className).toMatch(/\bbg-red-500\b/);
     expect(el.className).toMatch(/\bextra-class\b/);
  });

  test('falls back to gray when severity unknown', () => {
     render(<SeverityTag severity="mystery" />);
     const el = screen.getByText(/mystery/i);
     expect(el).toBeInTheDocument();
     expect(el.className).toMatch(/\bbg-gray-500\b/);
  });

});