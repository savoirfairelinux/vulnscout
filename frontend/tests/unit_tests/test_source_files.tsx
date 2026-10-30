import { act, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import userEvent from '@testing-library/user-event';
import Packages, { hasCompilationEvidence, type Package, type SourceFile } from '../../src/handlers/packages';
import SourceFileModal from '../../src/components/SourceFileModal';
import TablePackages from '../../src/pages/TablePackages';

const file: SourceFile = {
    spdx_id: 'https://example.org/file', path: 'lib/lz4.c',
    document_id: 'document', document_name: 'zephyr.jsonld',
    scan_id: 'scan', variant_id: 'variant', variant_name: 'default',
    properties: { verifiedUsing: [{ algorithm: 'sha256', hashValue: '012345' }] },
    builds: [{ spdx_id: 'compile-lz4', build_type: 'urn:spdx.dev:zephyr-cmake', compiled: true, outputs: ['liblz4.a'] }],
};
const pkg: Package = {
    id: 'lz4@1.0', name: 'lz4', version: '1.0', cpe: [], purl: [], vulnerabilities: {}, maxSeverity: {},
    source: [], variants: [], sbom_documents: [], supplier: '', source_file_count: 1,
};
const response = (value: unknown, ok = true) => ({
    ok, json: async () => value,
}) as Response;

afterEach(() => jest.restoreAllMocks());

test.each([
    ['variant', undefined, undefined, undefined, undefined],
    [undefined, 'project', undefined, undefined, undefined],
    [undefined, 'project', ['one', 'two'], undefined, 'intersection'],
    ['one', undefined, undefined, 'two', 'difference'],
] as const)('file requests preserve package and comparison scope (%s)', async (variant, project, variants, compare, operation) => {
    const fetch = jest.spyOn(global, 'fetch').mockResolvedValue(response([{
        source_files: [file], compiled_sources_complete: true,
    }]));
    expect(await Packages.sourceFiles('lz4@1.0::supplier', variant, project, variants ? [...variants] : undefined,
        compare, operation)).toEqual({ files: [file], complete: true });
    const url = new URL(String(fetch.mock.calls[0][0]));
    expect(url.pathname).toBe('/api/packages');
    expect(url.searchParams.get('package_id')).toBe('lz4@1.0::supplier');
    expect(url.searchParams.get('include_source_files')).toBe('true');
    if (variants) expect(url.searchParams.get('variant_ids')).toBe(variants.join(','));
    else if (variant) expect(url.searchParams.get('variant_id')).toBe(variant);
    else expect(url.searchParams.get('project_id')).toBe(project);
    if (compare) expect(url.searchParams.get('compare_variant_id')).toBe(compare);
    if (operation) expect(url.searchParams.get('operation')).toBe(operation);
});

test.each([
    [[], 'Package is no longer available'],
    [[{ source_files: null }], 'Files were not recorded'],
    [[{ source_files: [{}] }], 'Invalid recorded file response'],
])('invalid or unknown inventory is explicit', async (data, message) => {
    jest.spyOn(global, 'fetch').mockResolvedValue(response(data));
    await expect(Packages.sourceFiles('lib')).rejects.toThrow(String(message));
});

test('HTTP errors are not reported as an empty file inventory', async () => {
    jest.spyOn(global, 'fetch').mockResolvedValue(response({}, false));
    await expect(Packages.sourceFiles('lib')).rejects.toThrow('Unable to load recorded files');
});

test('details expose paths, hashes, source documents, and build evidence with filtering', async () => {
    const load = jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [file, { ...file, spdx_id: 'other', path: 'lib/listed.c', builds: [] }], complete: false,
    });
    const close = jest.fn();
    render(<SourceFileModal packageId={pkg.id} variantId="variant" onClose={close} />);
    expect(await screen.findByText('lib/lz4.c')).toBeTruthy();
    expect(screen.getByText('Build input')).toBeTruthy();
    expect(screen.getByText('Listed only')).toBeTruthy();
    expect(screen.getByText(/compiled-source CVE refinement is disabled/)).toBeTruthy();
    const user = userEvent.setup();
    await user.click(screen.getByText('lib/lz4.c'));
    expect(screen.getAllByText('zephyr.jsonld').length).toBe(2);
    expect(screen.getAllByText(/012345/).length).toBe(2);
    expect(screen.getByText(/compile-lz4/)).toBeTruthy();
    await user.type(screen.getByLabelText('Filter recorded files'), 'lz4');
    expect(screen.queryByText('lib/listed.c')).toBeNull();
    await user.clear(screen.getByLabelText('Filter recorded files'));
    await user.type(screen.getByLabelText('Filter recorded files'), 'missing');
    expect(screen.getByText('No recorded files match this filter.')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Close modal' }));
    expect(close).toHaveBeenCalled();
    expect(load).toHaveBeenCalledWith(pkg.id, 'variant', undefined, undefined, undefined, undefined);
});

test('empty inventory and retry remain distinguishable from failures', async () => {
    const load = jest.spyOn(Packages, 'sourceFiles')
        .mockRejectedValueOnce(new Error('Unavailable'))
        .mockResolvedValueOnce({ files: [], complete: true });
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Unavailable');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText(/No files are recorded/)).toBeTruthy();
    expect(load).toHaveBeenCalledTimes(2);
});

test.each([true, false])('recipe inputs do not claim compilation (explicit flag: %s)', async explicit => {
    const build = {
        build_type: 'http://openembedded.org/bitbake/do_create_spdx/recipe',
        ...(explicit ? { compiled: false } : {}),
    };
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [{ ...file, path: 'fix.patch', builds: [build] }], complete: false,
    });
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    expect(await screen.findByText('fix.patch')).toBeTruthy();
    expect(screen.getByText('Build input (not proven compilation)')).toBeTruthy();
    expect(screen.getByText('Recorded files: 1; compiled source files: 0.')).toBeTruthy();
});

test.each([undefined, false, 'true', 1])('missing or non-boolean compilation proof is not accepted (%s)', compiled => {
    expect(hasCompilationEvidence({ ...file, builds: [{ build_type: 'urn:packaging', compiled }] })).toBe(false);
});

test('packaging inputs are not shown as compiled source files', async () => {
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [{ ...file, path: 'manifest.json', builds: [{ build_type: 'urn:packaging', compiled: false }] }],
        complete: false,
    });
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    expect(await screen.findByText('manifest.json')).toBeTruthy();
    expect(screen.getByText('Build input (not proven compilation)')).toBeTruthy();
    expect(screen.getByText('Recorded files: 1; compiled source files: 0.')).toBeTruthy();
});

test('changing scope ignores a late response from the previous scope', async () => {
    let finish: (value: { files: SourceFile[]; complete: boolean }) => void = () => {};
    jest.spyOn(Packages, 'sourceFiles')
        .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }))
        .mockResolvedValueOnce({ files: [], complete: true });
    const { rerender } = render(<SourceFileModal packageId={pkg.id} variantId="one" onClose={() => {}} />);
    rerender(<SourceFileModal packageId={pkg.id} variantId="two" onClose={() => {}} />);
    expect(await screen.findByText(/No files are recorded/)).toBeTruthy();
    await act(async () => finish({ files: [file], complete: true }));
    expect(screen.queryByText(file.path)).toBeNull();
});

test('SBOM recorded counts explain the inventory and open details with older column preferences', async () => {
    Element.prototype.getBoundingClientRect = () => ({
        width: 1000, height: 1000, top: 0, bottom: 1000, left: 0, right: 1000, x: 0, y: 0, toJSON: () => {},
    });
    localStorage.setItem('vulnscout.tables.packages.source-legacy.visibleColumns', JSON.stringify(['Name']));
    jest.spyOn(global, 'fetch').mockResolvedValue(response({ counts: {}, unrecorded: [] }));
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({ files: [file], complete: true });
    render(<TablePackages packages={[pkg, { ...pkg, id: 'unknown@1', name: 'unknown', source_file_count: null }]}
        preferenceScopeKey="source-legacy" variantId="variant" />);
    await screen.findAllByText('Deps: 0 / Req by: 0');
    const button = await screen.findByRole('button', { name: 'View recorded files for lz4' });
    expect(button).toHaveTextContent('1');
    expect(screen.getByText('Not recorded')).toBeTruthy();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Recorded files helper' }));
    expect(screen.getByRole('tooltip')).toHaveTextContent(
        'Non-binary file records associated with this component in the imported SBOMs. '
        + 'May include source code, patches, licenses, and configuration files; '
        + 'not necessarily a complete source inventory.',
    );
    await user.click(button);
    expect(await screen.findByTestId('source-file-modal')).toBeTruthy();
    await waitFor(() => expect(screen.getByText(file.path)).toBeTruthy());
    expect(screen.getByRole('dialog', { name: `Recorded Files: ${pkg.id}` })).toBeTruthy();
});

test.each([true, false])('renaming saved columns preserves file column visibility (%s)', async visible => {
    const key = 'vulnscout.tables.packages.recorded-migration';
    const columns = visible ? ['Name', 'Source Files'] : ['Name'];
    localStorage.setItem(`${key}.visibleColumns`, JSON.stringify(columns));
    localStorage.setItem(`${key}.sourceFilesColumnDefaulted`, 'true');
    localStorage.setItem(`${key}.revisionColumnDefaulted`, 'true');
    localStorage.setItem(`${key}.dependencyColumnDefaulted`, 'true');
    jest.spyOn(global, 'fetch').mockResolvedValue(response({ counts: {}, unrecorded: [] }));
    render(<TablePackages packages={[]} preferenceScopeKey="recorded-migration" />);
    await waitFor(() => expect(JSON.parse(localStorage.getItem(`${key}.visibleColumns`)!)).toEqual(
        visible ? ['Name', 'Recorded Files'] : ['Name'],
    ));
    expect(screen.queryByRole('button', { name: 'Recorded files helper' }) !== null).toBe(visible);
});
