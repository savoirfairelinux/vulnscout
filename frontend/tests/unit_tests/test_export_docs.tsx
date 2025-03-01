import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import Exports from '../../src/pages/Exports';

describe('Exports Page', () => {

    test('render file and allow direct download', async () => {
        fetchMock.resetMocks();
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([
                    {
                        id: "hello.adoc",
                        category: ['misc'],
                        extension: "adoc|pdf"
                    }
                ])
            } as Response)
        );

        // ARRANGE
        render(<Exports />);
        const user = userEvent.setup();

        // ACT
        const misc_cat = await screen.getByText(/miscellaneous/i);

        const is_doc_present = await screen.queryByText(/hello.adoc/i);
        expect(is_doc_present).toBeNull();

        await user.click(misc_cat);
        const doc = await screen.getByText(/hello.adoc/i);
        expect(doc).toBeInTheDocument();

        await user.click(doc);
        const download = await screen.getByRole("link", {name: /download as asciidoc/i}) as HTMLAnchorElement;

        // ASSERT
        expect(download).toBeInTheDocument();
        expect(download.href).toContain("/api/documents/hello.adoc");
        expect(download.href).toContain("ext=adoc");
        expect(thisFetch).toHaveBeenCalledTimes(1);
    })

    test('render file and use customised download', async () => {
        fetchMock.resetMocks();
        const thisFetch = fetchMock.mockImplementationOnce(() =>
            Promise.resolve({
                json: () => Promise.resolve([
                    {
                        id: "hello.adoc",
                        category: ['misc'],
                        extension: "adoc|pdf"
                    }
                ])
            } as Response)
        );

        // ARRANGE
        render(<Exports />);
        const user = userEvent.setup();

        // ACT
        const misc_cat = await screen.getByText(/miscellaneous/i);

        const is_doc_present = await screen.queryByText(/hello.adoc/i);
        expect(is_doc_present).toBeNull();

        await user.click(misc_cat);
        const doc = await screen.getByText(/hello.adoc/i);
        expect(doc).toBeInTheDocument();

        await user.click(doc);
        const download = await screen.getByRole("link", {name: /download as pdf/i});
        expect(download).toBeInTheDocument();
        const options = await within(download).getByRole("button");
        expect(options).toBeInTheDocument();

        await user.click(options);
        const client = await screen.getByLabelText(/client name/i);
        const export_date = await screen.getByLabelText(/export date/i);

        const date_label = await screen.getByText(/vulnerability with assessments more recent than/i);
        const input_date = [...date_label.children].find((el) => el.getAttribute('type') == 'date') as HTMLElement;
        const input_time = [...date_label.children].find((el) => el.getAttribute('type') == 'time') as HTMLElement;

        const filter_epss = await screen.getByLabelText(/vulnerability with EPSS greater/i);
        const download_btn = await screen.getByRole("link", {name: /generate/i}) as HTMLAnchorElement;

        await user.type(client, "CLIENT_COMPANY");
        await user.clear(export_date);
        await user.type(export_date, "2024-01-05");
        await user.type(input_date, "2023-04-06");
        await user.clear(input_time);
        await user.type(input_time, "07:08");
        await user.type(filter_epss, "2.55");


        // ASSERT
        expect(download_btn.href).toContain("/api/documents/hello.adoc");
        expect(download_btn.href).toContain("ext=pdf");
        expect(download_btn.href).toContain("client_name=CLIENT_COMPANY");
        expect(download_btn.href).toContain("author=Savoir-faire%20Linux");
        expect(download_btn.href).toContain("export_date=2024-01-05");
        expect(download_btn.href).toContain("ignore_before=2023-04-06T07%3A08");
        expect(download_btn.href).toContain("only_epss_greater=2.55");
        expect(thisFetch).toHaveBeenCalledTimes(1);
    })
});
