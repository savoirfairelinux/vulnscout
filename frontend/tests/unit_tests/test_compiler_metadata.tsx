import { render, screen, within } from '@testing-library/react';
import CompilerMetadata from '../../src/components/CompilerMetadata';
import type { DependencyDocument } from '../../src/handlers/dependencies';
import CompilerMetadataModal from '../../src/components/CompilerMetadataModal';
import { filterCompilerDocuments, listCompilerMetadata } from '../../src/handlers/dependencies';
import type { CompilerDocument } from '../../src/handlers/dependencies';
import userEvent from '@testing-library/user-event';

jest.mock('../../src/handlers/dependencies', () => ({
    ...jest.requireActual('../../src/handlers/dependencies'),
    listCompilerMetadata: jest.fn(),
}));

const flags = '-Os  -g -Wall -Wextra -Werror -fno-strict-aliasing -ffunction-sections -fdata-sections -m64 -fPIC -std=c17';
const defines = '-DK_HEAP_MEM_POOL_SIZE=0 -DMBEDTLS_CONFIG_FILE="config-mbedtls.h" -DTF_PSA_CRYPTO_CONFIG_FILE="config-tf-psa-crypto.h" -D__ZEPHYR__=1';
const document: DependencyDocument = {
    id: 'build', source_name: 'build.jsonld', variant_id: 'demo', variant_name: 'demo',
    dependencies_recorded: true, packages: [], edges: [],
    build_targets: [
        { id: 'https://example.org/builds/mbedtls', name: 'mbedtls', package_ids: ['mbedtls@4.1.1'], languages: [
            { language: 'C', flags: [flags], defines: [defines] },
            { language: 'C++', flags: ['-std=c++17'], defines: [] },
        ] },
        { id: 'https://example.org/builds/mbedx509', name: 'mbedx509', package_ids: ['mbedtls@4.1.1'], languages: [
            { language: 'C', flags: ['-O0'], defines: ['-DX509'] },
        ] },
        { id: 'https://example.org/builds/kernel', name: 'kernel', package_ids: ['kernel@'], languages: [
            { language: 'C', flags: ['-O2'], defines: [] },
        ] },
    ],
};

test('compiler metadata retains verbatim values by target and language without exposing other packages', () => {
    render(<CompilerMetadata documents={[document]} packageId="mbedtls@4.1.1" />);
    const target = within(screen.getByRole('region', { name: 'Build target mbedtls', hidden: true }));
    const c = within(target.getByRole('region', { name: 'Language C', hidden: true }));
    expect(c.getByText('-Os', { exact: false, selector: 'code' }).textContent).toBe(flags);
    expect(c.getByText('-DK_HEAP_MEM_POOL_SIZE', { exact: false, selector: 'code' }).textContent).toBe(defines);
    expect(target.getByText('Source: build.jsonld · Variant: demo')).toBeTruthy();
    const cpp = within(target.getByRole('region', { name: 'Language C++', hidden: true }));
    expect(cpp.getByText('-std=c++17')).toBeTruthy();
    expect(cpp.getByText('Not recorded')).toBeTruthy();
    expect(c.queryByText('-std=c++17')).toBeNull();
    const x509 = within(screen.getByRole('region', { name: 'Build target mbedx509', hidden: true }));
    expect(x509.getByText('-O0')).toBeTruthy();
    expect(target.queryByText('-O0')).toBeNull();
    expect(screen.queryByText('Build target: kernel')).toBeNull();
});

test('metadata stays separate by source and variant and disappears for missing data or another package', () => {
    const other = { ...document, id: 'other', variant_name: 'other', source_name: 'other.jsonld' };
    const { rerender } = render(<CompilerMetadata documents={[document, other]} packageId="mbedtls@4.1.1" />);
    expect(screen.getAllByRole('region', { name: 'Build target mbedtls', hidden: true })).toHaveLength(2);
    expect(screen.getAllByText('Source: other.jsonld · Variant: other')).toHaveLength(2);
    rerender(<CompilerMetadata documents={[{ ...document, build_targets: undefined }]} packageId="mbedtls@4.1.1" />);
    expect(screen.queryAllByRole('region')).toHaveLength(0);
    rerender(<CompilerMetadata documents={[document]} packageId="unrelated@" />);
    expect(screen.queryAllByRole('region')).toHaveLength(0);
});

const compilerDocument: CompilerDocument = {
    ...document, format: 'spdx3', package_ids: ['mbedtls@4.1.1'],
};

test('compiler source and document filters intersect without mixing evidence', () => {
    const other = { ...compilerDocument, id: 'other', source_name: 'other.jsonld', format: 'spdx' };
    expect(filterCompilerDocuments([compilerDocument, other], [], [])).toHaveLength(2);
    expect(filterCompilerDocuments([compilerDocument, other], ['spdx3'], [])).toEqual([compilerDocument]);
    expect(filterCompilerDocuments([compilerDocument, other], [], ['other.jsonld'])).toEqual([other]);
    expect(filterCompilerDocuments([compilerDocument, other], ['spdx3'], ['other.jsonld'])).toEqual([]);
});

test('dedicated compiler modal loads package details in scope and applies source filters', async () => {
    const load = jest.mocked(listCompilerMetadata).mockResolvedValue([
        compilerDocument, { ...compilerDocument, id: 'other', source_name: 'other.jsonld', variant_name: 'other' },
    ]);
    const { rerender } = render(<CompilerMetadataModal packageId="mbedtls@4.1.1" variantIds={['alpha', 'beta']}
        operation="intersection" sources={[]} sbomDocuments={['build.jsonld']} onClose={() => {}} />);
    expect(await screen.findByText('Build target: mbedtls')).toBeTruthy();
    expect(load).toHaveBeenLastCalledWith(false, undefined, undefined, ['alpha', 'beta'],
        undefined, 'intersection', 'mbedtls@4.1.1');
    expect(screen.queryByText('Source: other.jsonld · Variant: other')).toBeNull();
    rerender(<CompilerMetadataModal packageId="mbedtls@4.1.1" variantIds={['alpha', 'beta']}
        operation="intersection" sources={['spdx']} sbomDocuments={[]} onClose={() => {}} />);
    expect(screen.getByText('No compiler flags or defines recorded for the selected scope.')).toBeTruthy();
});

test('compiler modal reports a failed request and supports retry', async () => {
    jest.mocked(listCompilerMetadata).mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce([compilerDocument]);
    render(<CompilerMetadataModal packageId="mbedtls@4.1.1" variantId="alpha"
        sources={[]} sbomDocuments={[]} onClose={() => {}} />);
    expect((await screen.findByRole('alert')).textContent).toContain('Unable to load compiler flags and defines');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Build target: mbedtls')).toBeTruthy();
});
