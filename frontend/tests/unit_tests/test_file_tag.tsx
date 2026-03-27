import { render, screen, fireEvent } from '@testing-library/react';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import FileTag from '../../src/components/FileTag';

describe('FileTag', () => {

    test('renders the file name and extension', () => {
        render(<FileTag name="report.adoc" extension="adoc" />);
        expect(screen.getByRole('button')).toHaveTextContent('report.adoc (adoc)');
    });

    test('dropdown is not rendered when opened=false', () => {
        render(<FileTag name="report.adoc" extension="adoc" opened={false} />);
        expect(screen.queryByRole('link')).not.toBeInTheDocument();
    });

    test('dropdown is rendered when opened=true', () => {
        render(<FileTag name="report.adoc" extension="adoc" opened={true} />);
        expect(screen.getByRole('link')).toBeInTheDocument();
    });

    test('calls onOpen when button is clicked', () => {
        const onOpen = jest.fn();
        render(<FileTag name="report.adoc" extension="adoc" onOpen={onOpen} />);
        fireEvent.click(screen.getByRole('button'));
        expect(onOpen).toHaveBeenCalledTimes(1);
    });

    test('button click stops propagation', () => {
        const parentClick = jest.fn();
        render(
            <div onClick={parentClick}>
                <FileTag name="report.adoc" extension="adoc" onOpen={() => {}} />
            </div>
        );
        fireEvent.click(screen.getByRole('button'));
        expect(parentClick).not.toHaveBeenCalled();
    });

    test('renders download links for each format', () => {
        render(<FileTag name="report" extension="PDF | ADOC" opened={true} />);
        expect(screen.getByText(/Download PDF Document/i)).toBeInTheDocument();
        expect(screen.getByText(/Download AsciiDoc/i)).toBeInTheDocument();
    });

    test('renders unknown extension as-is', () => {
        render(<FileTag name="data" extension="csv" opened={true} />);
        expect(screen.getByText(/Download CSV/i)).toBeInTheDocument();
    });
});
