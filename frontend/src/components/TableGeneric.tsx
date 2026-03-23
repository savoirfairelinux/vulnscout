import { createPortal } from 'react-dom'
import { getCoreRowModel, getSortedRowModel, getFilteredRowModel, useReactTable, flexRender, Row, RowSelectionState, OnChangeFn, SortingState } from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowUpShortWide, faArrowDownWideShort, faSort } from "@fortawesome/free-solid-svg-icons";
import { useMemo, useRef, useState, useEffect, useCallback } from "react";
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
    onFocusedRowChange?: (rowIndex: number | null) => void;
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
    onFilteredDataChange,
    onFocusedRowChange
}: Readonly<Props<DataType>>) {
    const [pageIndex, setPageIndex] = useState(0)
    const [itemsPerPage, setItemsPerPage] = useState(50)
    const [sorting, setSorting] = useState<SortingState>([])
    const [focusedRowIndex, setFocusedRowIndex] = useState<number | null>(null)
    const rowRefs = useRef<Map<number, HTMLTableRowElement>>(new Map())
    const [tooltipInfo, setTooltipInfo] = useState<{ original: DataType; id: string; rect: DOMRect } | null>(null)
    const hideTooltipTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

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
            const buildFuseQuery = (raw: string) => {
                const terms = raw.trim().split(/\s+/);
                // FuseJS search query example: https://www.fusejs.io/api/query.html#use-with-extended-searching
                return {
                    $and: terms.map(term => {
                        const isNegated = term.startsWith('-');
                        const raw = isNegated ? term.slice(1) : term;
                        const value = isNegated ? `!${raw}` : `'${raw}`; // exact (non-fuzzy) match

                        if (fuseKeys.length === 1) {
                            return { [fuseKeys[0]]: value };
                        }

                        if (isNegated) {
                            return { $and: fuseKeys.map(key => ({ [key]: value })) };
                        }
                        return { $or: fuseKeys.map(key => ({ [key]: value })) };
                    })
                };
            };

            const processedSearch = buildFuseQuery(search);

            return fuse.search(processedSearch).map(result => result.item);
        }
        return data;
    }, [search, fuse, data, fuseKeys]);

    // Notify parent component when filtered data changes
    useEffect(() => {
        if (onFilteredDataChange) {
            onFilteredDataChange(filteredData);
        }
    }, [filteredData, onFilteredDataChange]);

    const sortedData = useMemo(() => {
        if (sorting.length === 0) return filteredData;
        const sorted = [...filteredData];
        const { id, desc } = sorting[0];
        const column = columns.find(col => col.id === id);
        if (!column) return sorted;
        sorted.sort((a, b) => {
            if (column.sortingFn) {
                const result = column.sortingFn({ original: a } as any, { original: b } as any, id);
                return desc ? -result : result;
            }
            let aVal: any, bVal: any;
            if (typeof column.accessorFn === 'function') {
                aVal = column.accessorFn(a, 0);
                bVal = column.accessorFn(b, 0);
            } else if (column.accessorKey) {
                const keys = String(column.accessorKey).split('.');
                aVal = keys.reduce((obj, key) => obj?.[key], a as any);
                bVal = keys.reduce((obj, key) => obj?.[key], b as any);
            } else return 0;
            if (aVal === bVal) return 0;
            if (aVal == null) return 1;
            if (bVal == null) return -1;
            const result = aVal > bVal ? 1 : -1;
            return desc ? -result : result;
        });
        return sorted;
    }, [filteredData, sorting, columns]);

    const paginatedData = useMemo(() => {
        const start = pageIndex * itemsPerPage
        return sortedData.slice(start, start + itemsPerPage)
    }, [sortedData, pageIndex, itemsPerPage])

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
        onSortingChange: setSorting,
        state: { rowSelection: selected ?? {}, sorting }
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

    // Reset focused row when data changes
    useEffect(() => {
        setFocusedRowIndex(null)
        if (onFocusedRowChange) {
            onFocusedRowChange(null)
        }
    }, [filteredData, onFocusedRowChange])

    // Focus row after scrolling in virtualized mode to make sure the rows are rendered before focus is applied
    useEffect(() => {
        if (focusedRowIndex !== null && useVirtualization) {
            // Use setTimeout to ensure the row is rendered after scroll
            const timer = setTimeout(() => {
                const rowElement = rowRefs.current.get(focusedRowIndex)
                if (rowElement && document.activeElement !== rowElement) {
                    rowElement.focus({ preventScroll: true })
                }
            }, 50)
            return () => clearTimeout(timer)
        }
    }, [focusedRowIndex, useVirtualization])

    useEffect(() => {
        return () => { if (hideTooltipTimer.current) clearTimeout(hideTooltipTimer.current) }
    }, [])

    function showTooltip(e: React.MouseEvent<HTMLTableRowElement>, rowOriginal: DataType, rowId: string) {
        if (hoverField === undefined) return
        if (hideTooltipTimer.current) clearTimeout(hideTooltipTimer.current)
        setTooltipInfo({ original: rowOriginal, id: rowId, rect: e.currentTarget.getBoundingClientRect() })
    }

    function hideTooltip() {
        hideTooltipTimer.current = setTimeout(() => setTooltipInfo(null), 100)
    }

    function ctrl_click (event: React.MouseEvent, row: Row<DataType>) {
        if (event.ctrlKey || event.metaKey) {
            row.getToggleSelectedHandler()(event)
        }
    }

    const handleKeyDown = useCallback((event: React.KeyboardEvent, rowIndex: number) => {
        const focusRow = (targetIndex: number) => {
            setFocusedRowIndex(targetIndex)
            if (onFocusedRowChange) {
                onFocusedRowChange(targetIndex)
            }
            if (useVirtualization) {
                // Scroll to the target row in virtualized mode
                rowVirtualizer.scrollToIndex(targetIndex, { align: 'center' })
            } else {
                // Directly focus in non-virtualized mode
                const rowElement = rowRefs.current.get(targetIndex)
                rowElement?.focus()
                // Scroll into view if needed
                rowElement?.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
            }
        }

        switch (event.key) {
            case 'ArrowDown':
                event.preventDefault()
                if (rowIndex < rows.length - 1) {
                    focusRow(rowIndex + 1)
                }
                break
            case 'ArrowUp':
                event.preventDefault()
                if (rowIndex > 0) {
                    focusRow(rowIndex - 1)
                }
                break
            case 'Home':
                event.preventDefault()
                focusRow(0)
                break
            case 'End':
                event.preventDefault()
                focusRow(rows.length - 1)
                break
        }
    }, [rows.length, useVirtualization, rowVirtualizer, onFocusedRowChange])

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
        <>
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
                                    ref={node => {
                                        rowVirtualizer.measureElement(node)
                                        if (node) {
                                            rowRefs.current.set(virtualRow.index, node)
                                        } else {
                                            rowRefs.current.delete(virtualRow.index)
                                        }
                                    }} //measure dynamic row height
                                    key={row.id}
                                    tabIndex={0}
                                    className={[
                                        "flex absolute w-full row-with-hover-effect",
                                        row.getIsSelected() ? 'selected bg-gray-700' : 'bg-slate-600',
                                        "hover:bg-slate-800",
                                        focusedRowIndex === virtualRow.index ? 'ring-2 ring-blue-600 ring-inset' : ''
                                    ].join(' ')}
                                    onClick={(e) => ctrl_click(e, row)}
                                    onFocus={() => setFocusedRowIndex(virtualRow.index)}
                                    onKeyDown={(e) => handleKeyDown(e, virtualRow.index)}
                                    onMouseEnter={(e) => showTooltip(e, row.original, row.id)}
                                    onMouseLeave={hideTooltip}
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
                                    </tr>
                                ]
                            })
                        ) : (
                            rows.map((row, rowIndex) => [
                                <tr
                                key={row.id}
                                ref={node => {
                                    if (node) {
                                        rowRefs.current.set(rowIndex, node)
                                    } else {
                                        rowRefs.current.delete(rowIndex)
                                    }
                                }}
                                tabIndex={0}
                                className={[
                                    "flex w-full row-with-hover-effect",
                                    row.getIsSelected() ? 'selected bg-gray-700' : 'bg-slate-600',
                                    "hover:bg-slate-800",
                                    focusedRowIndex === rowIndex ? 'ring-2 ring-blue-400 ring-inset' : ''
                                ].join(' ')}
                                onClick={(e) => ctrl_click(e, row)}
                                onFocus={() => setFocusedRowIndex(rowIndex)}
                                onKeyDown={(e) => handleKeyDown(e, rowIndex)}
                                onMouseEnter={(e) => showTooltip(e, row.original, row.id)}
                                onMouseLeave={hideTooltip}
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

        {hoverField && tooltipInfo && createPortal(
            <div
                role="tooltip"
                className="fixed z-50 bg-gray-800 p-2 px-8 xl:px-32 2xl:px-64 text-center pointer-events-none text-white flex flex-col"
                style={{
                    ...(tooltipInfo.rect.top > window.innerHeight / 2
                        ? { bottom: window.innerHeight - tooltipInfo.rect.top }
                        : { top: tooltipInfo.rect.bottom }),
                    left: tooltipInfo.rect.left + tooltipInfo.rect.width / 2,
                    width: tooltipInfo.rect.width,
                    transform: 'translateX(-50%)',
                    maxWidth: '943px',
                    maxHeight: '300px',
                }}
            >
                <div style={{ overflow: 'hidden', whiteSpace: 'pre-line', display: '-webkit-box', WebkitBoxOrient: 'vertical', WebkitLineClamp: 12 }}>
                    {(tooltipInfo.original as any)?.[hoverField]?.length > 0
                        ? (tooltipInfo.original as any)?.[hoverField]?.map((a: any, index: number) => (
                            <span key={index}>
                                <b className='mb-2'>{(((a?.title as string) ?? 'Description').replace(/\b\w/g, (c: string) => c.toUpperCase()))} of {tooltipInfo.id}</b><br/>
                                {a?.content ?? "N/A"}
                                {index < (tooltipInfo.original as any)?.[hoverField]?.length - 1 ? '\n---\n' : ''}
                            </span>
                        ))
                        : "No description was provided"
                    }
                </div>
                <p className="text-xs text-gray-400 mt-1 italic">Click the CVE to see more</p>
            </div>,
            document.body
        )}
        </>
    );
}

export default TableGeneric;
