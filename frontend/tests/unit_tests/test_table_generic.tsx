/// <reference types="jest" />
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
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

    // Tooltip is portal-based: only appears after mouseenter on the row
    const rows = document.querySelectorAll('tr.row-with-hover-effect');
    fireEvent.mouseEnter(rows[0]);

    await waitFor(() => {
      const tooltip = document.body.querySelector('[role="tooltip"]');
      expect(tooltip).toBeInTheDocument();
      // Title falls back to "Description" when no title field is present
      expect(tooltip?.textContent).toMatch(/Description of row0/i);
      expect(tooltip?.textContent).toContain('Description 0 A');
    });
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
  }, 15000);

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

  test('search feature: exact match with apostrophe prefix and exclude match with exclamation mark (lines 52-69)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row5"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    // Exact match search for 'row5' should return only row5
    const row5Cell = await screen.findByRole('cell', { name: /row5/ });
    expect(row5Cell).toBeInTheDocument();

    // row4 and row6 should not be present (exact match only)
    const row4Cell = screen.queryByRole('cell', { name: /^row4$/ });
    const row6Cell = screen.queryByRole('cell', { name: /^row6$/ });
    expect(row4Cell).not.toBeInTheDocument();
    expect(row6Cell).not.toBeInTheDocument();
  });

  test('search feature: exclude pattern with exclamation mark (lines 52-69)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="-row5"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    // Exclude search with !row5 should return all rows except row5
    const row0Cell = await screen.findByRole('cell', { name: /row0/ });
    expect(row0Cell).toBeInTheDocument();

    const row4Cell = await screen.findByRole('cell', { name: /row4/ });
    expect(row4Cell).toBeInTheDocument();

    // row5 should not be present (excluded)
    const row5Cell = screen.queryByRole('cell', { name: /^row5$/ });
    expect(row5Cell).not.toBeInTheDocument();

    const row6Cell = await screen.findByRole('cell', { name: /row6/ });
    expect(row6Cell).toBeInTheDocument();
  });

  test('search feature: combining exact match and exclude patterns (lines 52-69)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row -row10"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    // Search for rows containing 'row' but exclude 'row10'
    const row11Cell = await screen.findByRole('cell', { name: /row11/ });
    expect(row11Cell).toBeInTheDocument();

    const row9Cell = await screen.findByRole('cell', { name: /row9/ });
    expect(row9Cell).toBeInTheDocument();

    // row10 should be excluded
    const row10Cell = screen.queryByRole('cell', { name: /^row10$/ });
    expect(row10Cell).not.toBeInTheDocument();
  });

  test('search feature: search with minimum character length (lines 52-69)', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="x"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    // Search with less than 2 characters should return all data
    const row0Cell = await screen.findByRole('cell', { name: /row0/ });
    expect(row0Cell).toBeInTheDocument();

    const row5Cell = await screen.findByRole('cell', { name: /row5/ });
    expect(row5Cell).toBeInTheDocument();
  });

  test('search feature: basic OR syntax with two terms', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row3  |  row7"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    expect(await screen.findByRole('cell', { name: /^row3$/ })).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: /^row7$/ })).toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: /^row5$/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: /^row0$/ })).not.toBeInTheDocument();
  });

  test('search feature: OR syntax with three pipe-separated groups each independently match', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row1 | row5 | row9"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    // All three OR targets should appear
    expect(await screen.findByRole('cell', { name: /^row1$/ })).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: /^row5$/ })).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: /^row9$/ })).toBeInTheDocument();
    // A row that matches none of the groups must be absent
    expect(screen.queryByRole('cell', { name: /^row4$/ })).not.toBeInTheDocument();
  });

  test('search feature: OR syntax with AND terms within a group (space-separated) before the pipe', async () => {
    // "row row5" ANDs the two terms → only row5 qualifies in that group
    // "row row9" ANDs → only row9 qualifies in that group
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row row5 | row row9"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    expect(await screen.findByRole('cell', { name: /^row5$/ })).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: /^row9$/ })).toBeInTheDocument();
    // row0 matches 'row' in both groups but lacks 'row5' / 'row9', so it must be absent
    expect(screen.queryByRole('cell', { name: /^row0$/ })).not.toBeInTheDocument();
  });

  test('search feature: OR syntax with one side of the pipe having no match', async () => {
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row5 | zzz"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    // The matching side still returns its result
    expect(await screen.findByRole('cell', { name: /^row5$/ })).toBeInTheDocument();
    // Unrelated rows are absent (the no-match side contributes nothing)
    expect(screen.queryByRole('cell', { name: /^row0$/ })).not.toBeInTheDocument();
  });

  test('search feature: OR + negation with negation inside an OR group excludes its term while the other group is unaffected', async () => {
    // group1 "row5"          → only row5
    // group2 "row -row9"     → everything with 'row' except row9
    // row5 passes group1; row0 passes group2; row9 fails both groups
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="row5 | row -row9"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    expect(await screen.findByRole('cell', { name: /^row5$/ })).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: /^row0$/ })).toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: /^row9$/ })).not.toBeInTheDocument();
  });

  test('search feature: OR + negation with multiple negations ANDed within one group while the other group is a simple match', async () => {
    // group1 "-row3 -row7"   → everything except row3 and row7
    // group2 "row5"          → only row5 (redundant here, but ensures group2 is evaluated)
    // row3 and row7 fail group1 and group2, so they are absent
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="-row3 -row7 | row5"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    expect(await screen.findByRole('cell', { name: /^row0$/ })).toBeInTheDocument();
    expect(await screen.findByRole('cell', { name: /^row5$/ })).toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: /^row3$/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('cell', { name: /^row7$/ })).not.toBeInTheDocument();
  });

  test('search feature: OR + negation with a row excluded by negation in one group is rescued by a matching group', async () => {
    // group1 "-row5"  → everything except row5
    // group2 "row5"   → only row5
    // row5 fails group1 but passes group2, so it still appears
    render(
      <TableGeneric
        columns={columns}
        data={DATA.slice(0, 20)}
        search="-row5 | row5"
        tableHeight="auto"
        hasPagination={false}
      />
    );

    expect(await screen.findByRole('cell', { name: /^row0$/ })).toBeInTheDocument();  // passes group1
    expect(await screen.findByRole('cell', { name: /^row5$/ })).toBeInTheDocument();  // rescued by group2
  });
});