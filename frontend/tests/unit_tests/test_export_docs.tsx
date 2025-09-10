import fetchMock from 'jest-fetch-mock';
fetchMock.enableMocks();

import { render, screen } from '@testing-library/react';
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
        const all_tab = await screen.getByRole("button", {name: /all/i});
        await user.click(all_tab);

        const doc = await screen.getByRole("button", {name: /hello.adoc/i});
        expect(doc).toBeInTheDocument();

        // Open dropdown
        await user.click(doc);
        const download = await screen.getByRole("link", {name: /download adoc\|pdf/i}) as HTMLAnchorElement;

        // ASSERT
        expect(download).toBeInTheDocument();
        expect(download.href).toContain("/api/documents/hello.adoc");
        expect(download.href).toContain("ext=adoc%7Cpdf");
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
        const all_tab = await screen.getByRole("button", {name: /all/i});
        await user.click(all_tab);

        const doc = await screen.getByRole("button", {name: /hello.adoc/i});
        expect(doc).toBeInTheDocument();

        // Open dropdown
        await user.click(doc);
        const download = await screen.getByRole("link", {name: /download adoc\|pdf/i}) as HTMLAnchorElement;
        expect(download).toBeInTheDocument();

        // ASSERT - Test the direct download link
        expect(download.href).toContain("/api/documents/hello.adoc");
        expect(download.href).toContain("ext=adoc%7Cpdf");
        expect(thisFetch).toHaveBeenCalledTimes(1);
    })
});
