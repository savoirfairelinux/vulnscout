import { getCoreRowModel, getSortedRowModel, getFilteredRowModel, useReactTable, flexRender, Row } from '@tanstack/react-table'
import { useVirtualizer } from '@tanstack/react-virtual';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faArrowUpShortWide, faArrowDownWideShort, faSort } from "@fortawesome/free-solid-svg-icons";
import { useMemo, useRef } from "react";
import Fuse from 'fuse.js';

/* tslint:disable:no-explicit-any */
type Props<DataType> = {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    columns: any[];
    data: DataType[];
    search?: string;
    fuseKeys?: string[];
    estimateRowHeight?: number;
    tableHeight?: string;
};
/* tslint:enable:no-explicit-any */

function TableGeneric<DataType> ({
    columns,
    data,
    search,
    fuseKeys = ['id'],
    estimateRowHeight = 66,
    tableHeight = 'calc(100dvh - 44px - 64px - 48px - 16px)'
}: Readonly<Props<DataType>>) {

    const fuse = useMemo(() => {
        return new Fuse(data as readonly DataType[], {
            keys: fuseKeys,
            includeScore: true,
            ignoreLocation: true,
            useExtendedSearch: true,
            shouldSort: true,
            minMatchCharLength: 2
        });
    }, [fuseKeys, data]);

    const filteredData = useMemo(() => {
        if (search && search.length > 2) {
            return fuse.search(search).map(result => result.item);
        }
        return data;
    }, [search, fuse, data]);

    const table = useReactTable({
        columns,
        data: filteredData,
        getCoreRowModel: getCoreRowModel(),
        getSortedRowModel: getSortedRowModel(),
        getFilteredRowModel: getFilteredRowModel(),
        // @ts-ignore
        getRowId: row => row?.id,
    });

    const { rows } = table.getRowModel()
    //The virtualizer needs to know the scrollable container element
    const tableContainerRef = useRef<HTMLDivElement>(null)

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
    })

    function ctrl_click (event: React.MouseEvent, row: Row<DataType>) {
        if (event.ctrlKey || event.metaKey) {
            row.getToggleSelectedHandler()(event)
        }
    }



    return (
        <div className="relative overflow-auto" style={{height: tableHeight}} ref={tableContainerRef}>
            <table className="border-collapse border border-slate-500 w-full text-white grid">
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
                <tbody className="relative grid" style={{height: `${rowVirtualizer.getTotalSize()}px`}}>

                    {rowVirtualizer.getVirtualItems().map(virtualRow => {
                        const row: Row<DataType> = rows[virtualRow.index]
                        return (
                            <tr
                            data-index={virtualRow.index} //needed for dynamic row height measurement
                            ref={node => rowVirtualizer.measureElement(node)} //measure dynamic row height
                            key={row.id}
                            className={[
                                "flex absolute w-full",
                                row.getIsSelected() ? 'selected bg-gray-700' : 'bg-slate-600'
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
                                        className="p-4 border border-slate-500 flex-auto"
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
                        )
                    })}
                </tbody>
                <tfoot className="grid sticky bottom-0 z-10">
                    {table.getFooterGroups().map(footerGroup => (
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
    );
}

export default TableGeneric;
