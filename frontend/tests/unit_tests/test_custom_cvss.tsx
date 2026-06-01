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

  test('submits valid vector then closes editor', () => {
    const onCancel = jest.fn();
    const onAddCvss = jest.fn();
    const triggerBanner = jest.fn();
    render(<CustomCvss onCancel={onCancel} onAddCvss={onAddCvss} triggerBanner={triggerBanner} />);

    fireEvent.change(screen.getByPlaceholderText(/CVSS:3\.1/), {
      target: { value: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }
    });
    fireEvent.click(screen.getByRole('button', { name: /^Add$/i }));

    expect(onAddCvss).toHaveBeenCalledWith('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(triggerBanner).not.toHaveBeenCalled();
  });

  test('renders variant selector and updates selection from checkbox changes', () => {
    const onCancel = jest.fn();
    const onAddCvss = jest.fn();
    const triggerBanner = jest.fn();
    const onSelectedVariantIdsChange = jest.fn();
    const variants = [
      { id: 'v1', name: 'Variant A', project_id: 'p1' },
      { id: 'v2', name: 'Variant B', project_id: 'p1' },
    ];

    const { rerender } = render(
      <CustomCvss
        onCancel={onCancel}
        onAddCvss={onAddCvss}
        triggerBanner={triggerBanner}
        variants={variants}
        selectedVariantIds={[]}
        onSelectedVariantIdsChange={onSelectedVariantIdsChange}
      />
    );

    expect(screen.getByText(/select variants/i)).toBeInTheDocument();

    const variantACheckbox = screen.getByLabelText('Variant A');
    fireEvent.click(variantACheckbox);
    expect(onSelectedVariantIdsChange).toHaveBeenCalledWith(['v1']);

    onSelectedVariantIdsChange.mockClear();
    rerender(
      <CustomCvss
        onCancel={onCancel}
        onAddCvss={onAddCvss}
        triggerBanner={triggerBanner}
        variants={variants}
        selectedVariantIds={['v1']}
        onSelectedVariantIdsChange={onSelectedVariantIdsChange}
      />
    );

    fireEvent.click(screen.getByLabelText('Variant A'));
    expect(onSelectedVariantIdsChange).toHaveBeenCalledWith([]);
  });

});