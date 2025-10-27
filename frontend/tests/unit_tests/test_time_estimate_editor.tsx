
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
// @ts-expect-error TS6133
import React from 'react';
import TimeEstimateEditor from '../../src/components/TimeEstimateEditor';

describe('TimeEstimateEditor component', () => {

  const optimisticPh = /shortest estimate \[eg: 5h]/i;
  const likelyPh = /balanced estimate \[eg: 2d 4h, or 2.5d]/i;
  const pessimisticPh = /longest estimate \[eg: 1w]/i;

  function setInputs(vals: { opt?: string; lik?: string; pess?: string }) {
    if (vals.opt !== undefined) {
      fireEvent.input(screen.getByPlaceholderText(optimisticPh), { target: { value: vals.opt }});
    }
    if (vals.lik !== undefined) {
      fireEvent.input(screen.getByPlaceholderText(likelyPh), { target: { value: vals.lik }});
    }
    if (vals.pess !== undefined) {
      fireEvent.input(screen.getByPlaceholderText(pessimisticPh), { target: { value: vals.pess }});
    }
  }

  test('saves a valid estimation', () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} progressBar={0.5} />);

    setInputs({ opt: '1h', lik: '2h', pess: '3h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));

    expect(onSave).toHaveBeenCalledTimes(1);
    const payload = onSave.mock.calls[0][0];
    expect(payload.optimistic.total_seconds).toBe(3600);
    expect(payload.likely.total_seconds).toBe(7200);
    expect(payload.pessimistic.total_seconds).toBe(10800);
    // progress bar branch
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  test('shows help text when toggled', () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);

    // Find the help button by its class
    const helpButton = document.querySelector('button.hover\\:text-blue-400') as HTMLElement;
    expect(helpButton).toBeInTheDocument();
    fireEvent.click(helpButton);

    expect(screen.getByText(/We follow the same time scale as Gitlab/i)).toBeInTheDocument();
  });

  test('hides help text when toggled twice', () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    const btn = document.querySelector('button.hover\\:text-blue-400') as HTMLElement;
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);
    expect(screen.getByText(/Time scale: 1 month = 4 weeks/i)).toBeInTheDocument();
    fireEvent.click(btn);
    expect(screen.queryByText(/Time scale: 1 month = 4 weeks/i)).not.toBeInTheDocument();
  });

  test('rejects non positive optimistic duration', async () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    setInputs({ opt: '0h', lik: '1h', pess: '2h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));
    
    // Check for error banner instead of alert
    const errorBanner = await screen.findByText(/Invalid optimistic duration/i);
    expect(errorBanner).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  test('rejects non positive likely duration', async () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    setInputs({ opt: '1h', lik: '0h', pess: '2h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));
    
    // Check for error banner instead of alert
    const errorBanner = await screen.findByText(/Invalid likely duration/i);
    expect(errorBanner).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  test('rejects non positive pessimistic duration', async () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    setInputs({ opt: '1h', lik: '2h', pess: '0h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));
    
    // Check for error banner instead of alert
    const errorBanner = await screen.findByText(/Invalid pessimistic duration/i);
    expect(errorBanner).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  test('rejects when optimistic > likely', async () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    setInputs({ opt: '3h', lik: '2h', pess: '4h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));
    
    // Check for error banner instead of alert
    const errorBanner = await screen.findByText(/Optimistic duration must be lower/i);
    expect(errorBanner).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  test('rejects when likely > pessimistic', async () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    setInputs({ opt: '1h', lik: '3h', pess: '2h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));
    
    // Check for error banner instead of alert
    const errorBanner = await screen.findByText(/Likely duration must be lower/i);
    expect(errorBanner).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

  test('invalid ISO 8601 string triggers parse error', async () => {
    const onSave = jest.fn();
    render(<TimeEstimateEditor actualEstimate={{}} onSaveTimeEstimation={onSave} />);
    setInputs({ opt: 'PXYZ', lik: '1h', pess: '2h' });
    fireEvent.click(screen.getByRole('button', { name: /Save estimation/i }));
    
    // Check for error banner instead of alert
    const errorBanner = await screen.findByText(/Invalid ISO 8601 duration/i);
    expect(errorBanner).toBeInTheDocument();
    expect(onSave).not.toHaveBeenCalled();
  });

});
