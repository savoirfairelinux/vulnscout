import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';

import TableGeneric from '../../src/components/TableGeneric';

type RowType = {
  id: string;
  value: number;
  descriptions: { content: string }[];
};

const makeData = (n: number): RowType[] =>
  Array.from({ length: n }, (_v, i) => ({
    id: `row${i}`,
    value: i,
    descriptions: [
      { content: `Description ${i} A` },
      { content: `Description ${i} B` }
    ]
  }));

// 600 items -> default 50 per page => 12 pages (indexes 0..11) to exercise ellipsis logic
const DATA = makeData(600);

// Shared columns
const columns = [
  {
    accessorKey: 'id',
    header: 'ID',
    cell: (info: any) => info.getValue(),
    size: 120,
  },
  {
    accessorKey: 'value',
    header: 'Value',
    cell: (info: any) => info.getValue(),
    size: 80,
  },
];

describe('TableGeneric component (direct tests to raise coverage)', () => {

  test('renders non-virtualized rows and hover panel (lines 247-279)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 10)}
        tableHeight="auto"          // disable virtualization branch
        hoverField="descriptions"
        hasPagination={false}
      />
    );

    // First row cell
    const firstIdCell = await screen.findByRole('cell', { name: /row0/ });
    expect(firstIdCell).toBeInTheDocument();

    // Hover panel row (always rendered when hoverField provided in non-virtualized branch)
    const hoverTitle = await screen.findByText(/Description of row0/i);
    expect(hoverTitle).toBeInTheDocument();

    // One of the description contents
    const descA = await screen.findByText(/Description 0 A/);
    expect(descA).toBeInTheDocument();
  });

  test('pagination: page number buttons, next/prev/first/last, and ellipsis generation (lines 130-153, 339-346, 360-376, 146)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA}
        tableHeight="auto"
        hoverField="descriptions"
        hasPagination={true}
      />
    );

    // Initial range text (1-50 / 600)
    expect(await screen.findByText(/1-50 \/ 600/)).toBeInTheDocument();

    const user = userEvent.setup();

    // Click Next (page 2 -> 51-100)
    const nextBtn = await screen.findByRole('button', { name: /next/i });
    await user.click(nextBtn);
    await waitFor(() => {
      expect(screen.getByText(/51-100 \/ 600/)).toBeInTheDocument();
    });

    // Navigate further so that the pagination renders the page "6" button
    await user.click(nextBtn); // move to page index 2
    await user.click(nextBtn); // move to page index 3 (now page 6 button should be visible)
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /^6$/ })).toBeInTheDocument();
    });
    const page6Btn = screen.getByRole('button', { name: /^6$/ });
    await user.click(page6Btn);
    await waitFor(() => {
      expect(screen.getByText(/251-300 \/ 600/)).toBeInTheDocument();
    });
    
    // There should be at least one ellipsis (ideally two) in the pagination bar
    const ellipsisSpans = screen.getAllByText('...');
    expect(ellipsisSpans.length).toBeGreaterThanOrEqual(1);

    // Click Previous (to page 5)
    const prevBtn = await screen.findByRole('button', { name: /previous/i });
    await user.click(prevBtn);
    await waitFor(() => {
      expect(screen.getByText(/201-250 \/ 600/)).toBeInTheDocument();
    });

    // Click First
    const firstBtn = await screen.findByRole('button', { name: /first/i });
    await user.click(firstBtn);
    await waitFor(() => {
      expect(screen.getByText(/1-50 \/ 600/)).toBeInTheDocument();
    });

    // Click Last
    const lastBtn = await screen.findByRole('button', { name: /last/i });
    await user.click(lastBtn);
    await waitFor(() => {
      expect(screen.getByText(/551-600 \/ 600/)).toBeInTheDocument();
    });
  });

  test('changing items per page resets page index (lines 322-323)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA}
        tableHeight="auto"
        hoverField="descriptions"
        hasPagination={true}
      />
    );

    const user = userEvent.setup();

    // Move to page 3 (index 2) to later verify reset
    const nextBtn = await screen.findByRole('button', { name: /next/i });
    await user.click(nextBtn);
    await user.click(nextBtn);
    await waitFor(() => {
      expect(screen.getByText(/101-150 \/ 600/)).toBeInTheDocument();
    });

    // Change items per page to 100 (option value 100 should exist from paginationSizes)
    const select = await screen.findByRole('combobox');
    await user.selectOptions(select, '100');

    // Page should reset to start
    await waitFor(() => {
      expect(screen.getByText(/1-100 \/ 600/)).toBeInTheDocument();
    });

    // Change to "All" (value 600) to exercise another onChange
    await user.selectOptions(select, '600');
    await waitFor(() => {
      expect(screen.getByText(/1-600 \/ 600/)).toBeInTheDocument();
    });
  }, 10000);
});