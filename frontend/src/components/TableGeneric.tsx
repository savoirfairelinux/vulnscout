import { getCoreRowModel, getSortedRowModel, getFilteredRowModel, useReactTable, flexRender, Row, RowSelectionState, OnChangeFn } from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowUpShortWide, faArrowDownWideShort, faSort } from "@fortawesome/free-solid-svg-icons";
import { useMemo, useRef, useState, useEffect } from "react";
import Fuse from 'fuse.js';

/* tslint:disable:no-explicit-any */
type Props<DataType> = {

    columns: any[];
    data: DataType[];
    search?: string;
    fuseKeys?: string[];
    hoverField?: string;
    estimateRowHeight?: number;
    tableHeight?: string;
    selected?: RowSelectionState;
    updateSelected?: OnChangeFn<RowSelectionState>;
    hasPagination?: boolean;
    onFilteredDataChange?: (filteredData: DataType[]) => void;
};
/* tslint:enable:no-explicit-any */

function TableGeneric<DataType> ({
    columns,
    data,
    search,
    fuseKeys = ['id'],
    hoverField = undefined,
    estimateRowHeight = 66,
    tableHeight = 'calc(100dvh - 44px - 64px - 48px - 16px)',
    selected = undefined,
    updateSelected = () => {},
    hasPagination = true,
    onFilteredDataChange
}: Readonly<Props<DataType>>) {
    const [pageIndex, setPageIndex] = useState(0)
    const [itemsPerPage, setItemsPerPage] = useState(50)

    const fuse = useMemo(() => {
        return new Fuse(data as readonly DataType[], {
            keys: fuseKeys,
            includeScore: true,
            ignoreLocation: true,
            useExtendedSearch: true,
            shouldSort: true,
            minMatchCharLength: 2,
        });
    }, [fuseKeys, data]);

    const filteredData = useMemo(() => {
        if (search && search.length > 2) {
            const processedSearch = search
                .trim()
                .split(/\s+/)
                .map(term => `'${term}`)
                .join(' ')

            return fuse.search(processedSearch).map(result => result.item);
        }
        return data;
    }, [search, fuse, data]);

    // Notify parent component when filtered data changes
    useEffect(() => {
        if (onFilteredDataChange) {
            onFilteredDataChange(filteredData);
        }
    }, [filteredData, onFilteredDataChange]);

    const paginatedData = useMemo(() => {
        const start = pageIndex * itemsPerPage
        return filteredData.slice(start, start + itemsPerPage)
    }, [filteredData, pageIndex, itemsPerPage])

    const paginationSizes = useMemo(() => {
        const total = filteredData.length;

        const roundToNearest100 = (n: number) => Math.round(n / 100) * 100;

        const divisions = [
            roundToNearest100(total / 2),
            roundToNearest100(total / 4),
            roundToNearest100(total / 8)
        ].filter(n => n > 0);

        const uniqueSorted = Array.from(new Set([total, ...divisions, 50]))
            .filter(n => n > 0)
            .sort((a, b) => a - b);

        return uniqueSorted;
    }, [filteredData.length]);

    const pageCount = Math.ceil(filteredData.length / itemsPerPage)

    const table = useReactTable({
        columns,
        data: paginatedData,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        enableRowSelection: selected !== undefined,
        enableMultiRowSelection: selected !== undefined,
        // @ts-expect-error: Row ID might not always be present in the data
        getRowId: row => row?.id,
        onRowSelectionChange: updateSelected,
        state: { rowSelection: selected ?? {} }
    });

    const { rows } = table.getRowModel()
    //The virtualizer needs to know the scrollable container element
    const tableContainerRef = useRef<HTMLDivElement>(null)

    // Only use virtualization if tableHeight is not 'auto'
    const useVirtualization = tableHeight !== 'auto'

    const rowVirtualizer = useVirtualizer({
        count: rows.length,
        estimateSize: () => estimateRowHeight, //estimate row height for accurate scrollbar dragging
        getScrollElement: () => tableContainerRef.current,
        //measure dynamic row height, except in firefox because it measures table border height incorrectly
        measureElement:
          typeof window !== 'undefined' &&
          navigator.userAgent.indexOf('Firefox') === -1
            ? element => element?.getBoundingClientRect().height
            : undefined,
        overscan: 5,
        enabled: useVirtualization,
    })

    function ctrl_click (event: React.MouseEvent, row: Row<DataType>) {
        if (event.ctrlKey || event.metaKey) {
            row.getToggleSelectedHandler()(event)
        }
    }

    function getPageNumbers(current: number, total: number): (number | string)[] {
        const delta = 2
        const range: (number | string)[] = []
        const rangeWithDots: (number | string)[] = []
        let left = current - delta
        let right = current + delta + 1

        for (let i = 0; i < total; i++) {
            if (i === 0 || i === total - 1 || (i >= left && i < right)) {
                range.push(i)
            }
        }

        let l: number | null = null
        for (let i of range) {
            if (l !== null && typeof i === 'number' && i - l > 1) {
                rangeWithDots.push('...')
            }
            rangeWithDots.push(i)
            if (typeof i === 'number') l = i
        }

        return rangeWithDots
    }

    return (
        <div className="flex flex-col" style={{ height: tableHeight === 'auto' ? 'auto' : tableHeight }}>
            <div className={`relative ${tableHeight === 'auto' ? '' : 'overflow-auto'}`} ref={tableContainerRef}>
                <table className="rounded-md border-collapse border border-slate-500 w-full text-white grid">
                    <thead className="grid sticky top-0 z-20">
                        {table.getHeaderGroups().map(headerGroup => (
                            <tr key={headerGroup.id} className="bg-slate-700 flex w-full">
                            {headerGroup.headers.map(header => (
                                <th
                                    key={header.id}
                                    className={[
                                        `p-4 border border-slate-600 flex-auto`,
                                        header.column.getCanSort() ? 'cursor-pointer select-none' : ''
                                    ].join(' ')}
                                    style={{width: header.getSize()}}
                                    onClick={header.column.getToggleSortingHandler()}
                                >
                                    <span className="mr-2">
                                        {header.isPlaceholder
                                        ? null
                                        : flexRender(
                                            header.column.columnDef.header,
                                            header.getContext()
                                        )}
                                    </span>
                                    {header.column.getCanSort()
                                        ? (header.column.getIsSorted() === false
                                            ? <FontAwesomeIcon icon={faSort} />
                                            : (header.column.getIsSorted() === 'asc'
                                                ? <FontAwesomeIcon icon={faArrowUpShortWide} />
                                                : <FontAwesomeIcon icon={faArrowDownWideShort} />
                                            )
                                        )
                                        : ''}
                                </th>
                            ))}
                            </tr>
                        ))}
                    </thead>
                    <tbody className={`relative grid ${useVirtualization ? '' : 'auto-rows-auto'}`} style={useVirtualization ? {height: `${rowVirtualizer.getTotalSize()}px`} : {}}>

                        {useVirtualization ? (
                            rowVirtualizer.getVirtualItems().map(virtualRow => {
                                const row: Row<DataType> = rows[virtualRow.index]
                                return [
                                    <tr
                                    data-index={virtualRow.index} //needed for dynamic row height measurement
                                    ref={node => rowVirtualizer.measureElement(node)} //measure dynamic row height
                                    key={row.id}
                                    className={[
                                        "flex absolute w-full row-with-hover-effect",
                                        row.getIsSelected() ? 'selected bg-gray-700' : 'bg-slate-600',
                                        "hover:bg-slate-800"
                                    ].join(' ')}
                                    onClick={(e) => ctrl_click(e, row)}
                                    style={{
                                        transform: `translateY(${virtualRow.start}px)`, //this should always be a `style` as it changes on scroll
                                    }}
                                    >
                                        {row.getVisibleCells().map(cell => {
                                            return (
                                            <td
                                                key={cell.id}
                                                className={cell.column.id === 'id' ? 'border border-slate-500 flex-auto' : 'p-4 border border-slate-500 flex-auto'}
                                                style={{
                                                    width: cell.column.getSize(),
                                                }}
                                            >
                                                {flexRender(
                                                    cell.column.columnDef.cell,
                                                    cell.getContext()
                                                )}
                                            </td>)
                                        })}
                                    </tr>,
                                    hoverField != undefined && <tr
                                        className="show-on-row-hover absolute z-30 overflow-visible w-full px-8 xl:px-32 2xl:px-64 text-center pointer-events-none"
                                        key={`${row.id}_hoverpanel`}
                                        style={{
                                            transform: virtualRow.start > 150 ?  //this should always be a `style` as it changes on scroll
                                                `translateY(calc(${virtualRow.start}px - 100%))` :
                                                `translateY(calc(${virtualRow.end}px))`
                                        }}
                                    >
                                        <td role="tooltip" className="block bg-gray-800/90 whitespace-pre-line p-2">
                                            <b className='mb-2'>Description of {row.id}</b><br/>
                                            {(row.original as any)?.[hoverField]?.map((a: any) => a?.content)?.join('\n---\n') ?? "No description was provided"}
                                        </td>
                                    </tr>
                                ]
                            })
                        ) : (
                            rows.map((row) => [
                                <tr
                                key={row.id}
                                className={[
                                    "flex w-full row-with-hover-effect",
                                    row.getIsSelected() ? 'selected bg-gray-700' : 'bg-slate-600',
                                    "hover:bg-slate-800"
                                ].join(' ')}
                                onClick={(e) => ctrl_click(e, row)}
                                >
                                    {row.getVisibleCells().map(cell => {
                                        return (
                                        <td
                                            key={cell.id}
                                            className={cell.column.id === 'id' ? 'border border-slate-500 flex-auto' : 'p-4 border border-slate-500 flex-auto'}
                                            style={{
                                                width: cell.column.getSize(),
                                            }}
                                        >
                                            {flexRender(
                                                cell.column.columnDef.cell,
                                                cell.getContext()
                                            )}
                                        </td>)
                                    })}
                                </tr>,
                                hoverField != undefined && <tr
                                    className="show-on-row-hover absolute z-30 overflow-visible w-full px-8 xl:px-32 2xl:px-64 text-center pointer-events-none"
                                    key={`${row.id}_hoverpanel`}
                                >
                                    <td role="tooltip" className="block bg-gray-800/90 whitespace-pre-line p-2">
                                        <b className='mb-2'>Description of {row.id}</b><br/>
                                        {(row.original as any)?.[hoverField]?.map((a: any) => a?.content)?.join('\n---\n') ?? "No description was provided"}
                                    </td>
                                </tr>
                            ])
                        )}
                    </tbody>
                    <tfoot className="grid sticky bottom-0 z-10">
                        {table.getFooterGroups().some(group =>
                            group.headers.some(header => header.column.columnDef.footer)
                        ) &&
                            table.getFooterGroups().map(footerGroup => (
                            <tr key={footerGroup.id} className="bg-slate-700 flex w-full">
                                {footerGroup.headers.map(header => (
                                <th
                                    key={header.id}
                                    className="px-4 py-2 border border-slate-600 flex-auto"
                                    style={{width: header.getSize()}}
                                >
                                    {header.isPlaceholder
                                    ? null
                                    : flexRender(
                                        header.column.columnDef.footer,
                                        header.getContext()
                                        )}
                                </th>
                                ))}
                            </tr>
                            ))}
                        </tfoot>
                </table>
            </div>

        {hasPagination &&
            <div className="rounded-b-md flex justify-between items-center py-4 px-4 text-white bg-slate-800 border-t border-slate-600 text-sm">
            <div className="flex items-center gap-2">
                <span>
                {pageIndex * itemsPerPage + 1}-
                {Math.min((pageIndex + 1) * itemsPerPage, filteredData.length)} / {filteredData.length}
                </span>
                <span>- Results per page:</span>
                <select
                value={itemsPerPage}
                onChange={(e) => {
                    setPageIndex(0)
                    setItemsPerPage(Number(e.target.value))
                }}
                className="bg-slate-700 text-white border border-slate-500 rounded px-2 py-1"
                >
                {paginationSizes.map(size => (
                    <option key={size} value={size}>
                    {size === filteredData.length ? `${size} (All)` : size}
                    </option>
                ))}
                </select>
            </div>

            <div className="flex flex-wrap justify-end items-center gap-2">
                <button
                className="px-2 py-1 bg-slate-600 rounded disabled:opacity-50"
                disabled={pageIndex === 0}
                onClick={() => setPageIndex(0)}
                >
                First
                </button>
                <button
                className="px-2 py-1 bg-slate-600 rounded disabled:opacity-50"
                disabled={pageIndex === 0}
                onClick={() => setPageIndex(prev => Math.max(prev - 1, 0))}
                >
                Previous
                </button>
                {getPageNumbers(pageIndex, pageCount).map((p, i) =>
                typeof p === 'string' ? (
                    <span key={i} className="px-2">...</span>
                ) : (
                    <button
                    key={i}
                    className={[
                        'px-2 py-1 rounded',
                        p === pageIndex ? 'bg-blue-600' : 'bg-slate-600'
                    ].join(' ')}
                    onClick={() => setPageIndex(p)}
                    >
                    {p + 1}
                    </button>
                )
                )}
                <button
                className="px-2 py-1 bg-slate-600 rounded disabled:opacity-50"
                disabled={pageIndex + 1 >= pageCount}
                onClick={() => setPageIndex(prev => prev + 1)}
                >
                Next
                </button>
                <button
                className="px-2 py-1 bg-slate-600 rounded disabled:opacity-50"
                disabled={pageIndex + 1 >= pageCount}
                onClick={() => setPageIndex(pageCount - 1)}
                >
                Last
                </button>
            </div>
            </div>
        }

        </div>
    );
}

export default TableGeneric;
