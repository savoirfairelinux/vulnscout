import { render, screen, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';
import CustomCvss from '../../src/components/CustomCvss';

describe('CustomCvss component', () => {
  let originalAlert: any;
  beforeAll(() => {
    originalAlert = global.alert;
    // @ts-ignore
    global.alert = jest.fn();
  });

  afterAll(() => {
    global.alert = originalAlert;
  });

  test('renders heading, description, input and buttons', () => {
    const onCancel = jest.fn();
    const onAddCvss = jest.fn();
    render(<CustomCvss onCancel={onCancel} onAddCvss={onAddCvss} />);

    expect(screen.getByRole('heading', { name: /Custom CVSS/i })).toBeInTheDocument();
    expect(screen.getByText(/You can enter a custom CVSS vector/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/CVSS:3\.1/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Cancel/i })).toBeInTheDocument();
  });

  test('shows alert when trying to add empty vector', () => {
    const onCancel = jest.fn();
    const onAddCvss = jest.fn();
    render(<CustomCvss onCancel={onCancel} onAddCvss={onAddCvss} />);

    fireEvent.click(screen.getByRole('button', { name: /Add/i }));

    expect(global.alert).toHaveBeenCalledWith('Please provide a valid CVSS vector string');
    expect(onAddCvss).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });

});