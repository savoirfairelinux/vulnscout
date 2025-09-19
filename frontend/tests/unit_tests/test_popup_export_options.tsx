
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import "@testing-library/jest-dom";
// @ts-expect-error TS6133
import React from 'react';

import PopupExportOptions from '../../src/components/PopupExportOptions';

describe('PopupExportOptions component', () => {

   test('renders with default values', async () => {
       render(<PopupExportOptions docName="report.txt" extension="adoc" onClose={() => {}} />);
       const author = await screen.getByPlaceholderText(/enter your name/i) as HTMLInputElement;
       const exportDate = await screen.getByLabelText(/export date/i) as HTMLInputElement;
       expect(author.value).toBe('Savoir-faire Linux');
       const today = (new Date()).toISOString().split('T')[0];
       expect(exportDate.value).toBe(today);
   });

   test('builds link with default filled fields only', async () => {
       render(<PopupExportOptions docName="report.txt" extension="adoc" onClose={() => {}} />);
       const link = await screen.getByRole('link', { name: /generate/i }) as HTMLAnchorElement;

       // base path
       expect(link.href).toContain('/api/documents/report.txt?');

       // ext present
       expect(link.href).toMatch(/(?:\?|&)ext=adoc(?:&|$)/);

       // author present
       expect(link.href).toMatch(/author=Savoir-faire%20Linux/);

       // export_date present
       const today = (new Date()).toISOString().split('T')[0];
       expect(link.href).toMatch(new RegExp(`export_date=${today}`));

       // absent optional params
       expect(link.href).not.toMatch(/client_name=/);
       expect(link.href).not.toMatch(/ignore_before=/);
       expect(link.href).not.toMatch(/only_epss_greater=/);
   });

   test('adds all optional filters and client name', async () => {
       render(<PopupExportOptions docName="report.txt" extension="adoc" onClose={() => {}} />);
       const user = userEvent.setup();

       // Client name input (by placeholder pattern)
       const client = await screen.getByPlaceholderText(/ACME org/i) as HTMLInputElement;
       await user.type(client, 'ACME Corp');

       // Change author
       const author = await screen.getByPlaceholderText(/enter your name/i) as HTMLInputElement;
       await user.clear(author);
       await user.type(author, 'Jane Doe');

               // only more recent date + time
               const dateInput = await screen.getByLabelText(/assessments more recent/i, { selector: 'input[type="date"]' }) as HTMLInputElement;
               const timeInput = await screen.getByLabelText(/assessments more recent/i, { selector: 'input[type="time"]' }) as HTMLInputElement;
               fireEvent.change(dateInput, { target: { value: '2024-01-15' } });
               fireEvent.change(timeInput, { target: { value: '13:45' } });

       // EPSS filter
       const epss = await screen.getByLabelText(/EPSS greater or equal/i) as HTMLInputElement;
       await user.type(epss, '0.5');

       const link = await screen.getByRole('link', { name: /generate/i }) as HTMLAnchorElement;

       const url = new URL(link.href);
       expect(url.pathname).toContain('/api/documents/report.txt');

       const params = url.searchParams;
       expect(params.get('ext')).toBe('adoc');
       expect(params.get('client_name')).toBe('ACME Corp');
       expect(params.get('author')).toBe('Jane Doe');
       expect(params.get('export_date')).toBe((new Date()).toISOString().split('T')[0]); // unchanged
       expect(params.get('ignore_before')).toBe('2024-01-15T13:45');
       expect(params.get('only_epss_greater')).toBe('0.5');
   });

   test('adding only date (no time change) uses T00:00 default', async () => {
       render(<PopupExportOptions docName="report.txt" extension="adoc" onClose={() => {}} />);

        const dateInput = await screen.getByLabelText(/assessments more recent/i, { selector: 'input[type="date"]' }) as HTMLInputElement;
        fireEvent.change(dateInput, { target: { value: '2024-02-20' } });

       const link = await screen.getByRole('link', { name: /generate/i }) as HTMLAnchorElement;
       const url = new URL(link.href);
       expect(url.searchParams.get('ignore_before')).toBe('2024-02-20T00:00');
   });

   test('clearing author removes it from link', async () => {
       render(<PopupExportOptions docName="report.txt" extension="adoc" onClose={() => {}} />);
       const user = userEvent.setup();
       const author = await screen.getByPlaceholderText(/enter your name/i) as HTMLInputElement;
       await user.clear(author);

       const link = await screen.getByRole('link', { name: /generate/i }) as HTMLAnchorElement;
       expect(link.href).not.toMatch(/author=/);
   });

});
