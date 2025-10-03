import { render, screen, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';
import CustomCvss from '../../src/components/CustomCvss';

describe('CustomCvss component', () => {
  test('renders heading, description, input and buttons', () => {
    const onCancel = jest.fn();
    const onAddCvss = jest.fn();
    const triggerBanner = jest.fn();
    render(<CustomCvss onCancel={onCancel} onAddCvss={onAddCvss} triggerBanner={triggerBanner} />);

    expect(screen.getByRole('heading', { name: /Custom CVSS/i })).toBeInTheDocument();
    expect(screen.getByText(/You can enter a custom CVSS vector/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/CVSS:3\.1/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Cancel/i })).toBeInTheDocument();
  });

  test('triggers banner when trying to add empty vector', () => {
    const onCancel = jest.fn();
    const onAddCvss = jest.fn();
    const triggerBanner = jest.fn();
    render(<CustomCvss onCancel={onCancel} onAddCvss={onAddCvss} triggerBanner={triggerBanner} />);

    fireEvent.click(screen.getByRole('button', { name: /Add/i }));

    expect(triggerBanner).toHaveBeenCalledWith('Please provide a valid CVSS vector string', 'error');
    expect(onAddCvss).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });

});