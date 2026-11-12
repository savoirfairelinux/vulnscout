import { act, render, screen, waitFor, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import userEvent from '@testing-library/user-event';
import Packages, { hasCompilationEvidence, isArtifactFile, type Package, type SourceFile } from '../../src/handlers/packages';
import SourceFileModal from '../../src/components/SourceFileModal';
import TablePackages from '../../src/pages/TablePackages';

const file: SourceFile = {
    spdx_id: 'https://example.org/file', path: 'lib/lz4.c',
    document_id: 'document', document_name: 'zephyr.jsonld',
    scan_id: 'scan', variant_id: 'variant', variant_name: 'default',
    properties: { verifiedUsing: [{ algorithm: 'sha256', hashValue: '012345' }] },
    builds: [{ spdx_id: 'compile-lz4', build_type: 'urn:spdx.dev:zephyr-cmake', compiled: true, outputs: ['liblz4.a'],
        parameters: [{ key: 'compile:flags:C', value: '-O2 -Wall', type: 'DictionaryEntry' }] }],
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
    expect(await screen.findByRole('button', { name: /Inspect lib\/lz4.c/ })).toBeTruthy();
    expect(screen.getByRole('dialog')).toHaveClass('h-[calc(100vh-2rem)]', 'max-w-[calc(100vw-2rem)]');
    expect(screen.getAllByText('Compilation recorded').length).toBeGreaterThan(0);
    expect(within(screen.getByRole('list', { name: 'Recorded files' })).getByText('Listed only')).toBeTruthy();
    expect(screen.queryByText(/dismiss CVEs|CVE matching can skip/)).not.toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /Inspect lib\/lz4.c/ }));
    const details = within(screen.getByRole('region', { name: 'File details' }));
    expect(details.getByText('zephyr.jsonld')).toBeTruthy();
    expect(within(details.getByRole('region', { name: 'File hashes' })).getByText('012345')).toBeVisible();
    expect(within(details.getByRole('region', { name: 'Build evidence' })).getByText('compile-lz4')).toBeVisible();
    expect(details.getByText('-O2 -Wall')).not.toBeVisible();
    await user.click(details.getByText('Build parameters (1)'));
    expect(details.getByText('-O2 -Wall')).toBeVisible();
    expect(details.getByText('liblz4.a')).toBeVisible();
    expect(details.getByText('Technical identifiers and original data').closest('details')).not.toHaveAttribute('open');
    await user.type(screen.getByLabelText('Filter recorded files'), 'lz4');
    expect(screen.queryByText('lib/listed.c')).toBeNull();
    await user.clear(screen.getByLabelText('Filter recorded files'));
    await user.type(screen.getByLabelText('Filter recorded files'), 'missing');
    expect(screen.getByText('No recorded files match these filters.')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Reset filters' }));
    expect(screen.getByRole('button', { name: /Inspect lib\/listed.c/ })).toBeTruthy();
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
    expect(await screen.findByRole('button', { name: /Inspect fix.patch/ })).toBeTruthy();
    expect(screen.getAllByText('Other build input').length).toBeGreaterThan(0);
    expect(screen.getByText(/Compilation is not proven/)).toBeTruthy();
    expect(screen.getByText(/compiled source paths/)).toHaveTextContent('0 compiled source paths');
});

test.each([undefined, false, 'true', 1])('missing or non-boolean compilation proof is not accepted (%s)', compiled => {
    expect(hasCompilationEvidence({ ...file, builds: [{ build_type: 'urn:packaging', compiled }] })).toBe(false);
});

test.each([
    ['bin/busybox.suid', { fileTypes: ['BINARY'] }],
    ['build/output.elf', {}],
    ['firmware', { software_primaryPurpose: 'firmware' }],
    ['exported-binary', { comment: 'VulnScout recorded file evidence v1:\n'
        + JSON.stringify({ properties: { fileTypes: ['BINARY'] }, builds: [] }) }],
])('binary/output records are labeled and filtered without compilation evidence (%s)', async (path, properties) => {
    const artifact: SourceFile = { ...file, spdx_id: 'artifact', path: String(path), properties };
    expect(hasCompilationEvidence(artifact)).toBe(false);
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [artifact, { ...file, builds: [] }], complete: false,
    });
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: new RegExp(`Inspect ${path}`) }));
    expect(screen.getByText(/compiled source paths/)).toHaveTextContent('0 compiled source paths');
    const details = within(screen.getByRole('region', { name: 'File details' }));
    expect(details.getAllByText('Binary / output').length).toBeGreaterThan(0);
    expect(details.getByText(/not evidence of compiled source/)).toBeVisible();
    expect(details.queryByText('Compilation recorded')).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by build evidence' }), 'artifact');
    expect(screen.getByRole('button', { name: new RegExp(`Inspect ${path}`) })).toBeVisible();
    expect(screen.queryByRole('button', { name: /Inspect lib\/lz4.c/ })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by build evidence' }), 'compiled');
    expect(screen.getByText('No recorded files match these filters.')).toBeVisible();
});

test.each(['VulnScout recorded file evidence v1:\ninvalid', 'VulnScout recorded file evidence v1:\nnull'])(
    'malformed exported metadata cannot claim artifact or compilation evidence (%s)', comment => {
        expect(hasCompilationEvidence({ ...file, properties: { comment }, builds: [] })).toBe(false);
    },
);

test.each([{ toString: null }, ['executable'], null, 42])(
    'malformed primary purpose cannot crash or classify source files as artifacts (%j)', primaryPurpose => {
        const nativeProperties = { software_primaryPurpose: primaryPurpose };
        const portableProperties = { comment: 'VulnScout recorded file evidence v1:\n'
            + JSON.stringify({ properties: nativeProperties, builds: [] }) };
        for (const properties of [nativeProperties, portableProperties]) {
            const sourceFile = { ...file, properties };
            expect(isArtifactFile(sourceFile)).toBe(false);
            expect(hasCompilationEvidence(sourceFile)).toBe(true);
        }
    },
);

test('packaging inputs are not shown as compiled source files', async () => {
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [{ ...file, path: 'manifest.json', builds: [{ build_type: 'urn:packaging', compiled: false }] }],
        complete: false,
    });
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    expect(await screen.findByRole('button', { name: /Inspect manifest.json/ })).toBeTruthy();
    expect(screen.getAllByText('Other build input').length).toBeGreaterThan(0);
    expect(screen.getByText(/compiled source paths/)).toHaveTextContent('0 compiled source paths');
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
    expect(within(screen.getByText('unknown').closest('tr')!).queryByText('Not recorded')).not.toBeInTheDocument();
    expect(screen.getByTitle('Reimport the original SPDX SBOMs to record file evidence')).toHaveTextContent('—');
    expect(button.closest('td')).not.toHaveClass('p-4');
    expect(button.closest('td')).toHaveClass('p-0');
    expect(button).toHaveClass('h-full', 'w-full', 'p-4');
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: 'Recorded files helper' }));
    expect(screen.getByRole('tooltip')).toHaveTextContent(
        'File records associated with this component in the imported SBOMs. '
        + 'May include source code, patches, licenses, configuration files, and SPDX 2 binaries/outputs; '
        + 'not necessarily a complete source inventory.',
    );
    await user.click(button);
    expect(await screen.findByTestId('source-file-modal')).toBeTruthy();
    await waitFor(() => expect(screen.getByRole('button', { name: /Inspect lib\/lz4.c/ })).toBeTruthy());
    expect(screen.getByRole('dialog', { name: `Recorded Files: ${pkg.id}` })).toBeTruthy();
});

test('evidence and document filters combine with search and clear without stale details', async () => {
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [
            file,
            { ...file, spdx_id: 'listed', path: 'LICENSE', builds: [] },
            { ...file, spdx_id: 'recipe', path: 'fix.patch', document_id: 'other', document_name: 'recipe.spdx.json',
                builds: [{ build_type: 'recipe', compiled: false }] },
        ], complete: false,
    });
    const user = userEvent.setup();
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    await screen.findByRole('button', { name: /Inspect lib\/lz4.c/ });
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by build evidence' }), 'listed');
    expect(screen.getByRole('status')).toHaveTextContent('Showing 1 of 3');
    expect(screen.getByRole('button', { name: /Inspect LICENSE/ })).toHaveAttribute('aria-pressed', 'true');
    expect(within(screen.getByRole('region', { name: 'File details' })).getByRole('heading', { name: 'LICENSE' })).toBeVisible();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by SBOM document' }), 'other');
    expect(screen.queryByRole('region', { name: 'File details' })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Reset filters' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by build evidence' }), 'build');
    expect(screen.getByRole('button', { name: /Inspect fix.patch/ })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Inspect lib\/lz4.c/ })).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by SBOM document' }), 'other');
    await user.type(screen.getByLabelText('Filter recorded files'), 'recipe.spdx');
    expect(screen.getByRole('status')).toHaveTextContent('Showing 1 of 3');
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by build evidence' }), 'compiled');
    expect(screen.getByRole('status')).toHaveTextContent('Showing 1 of 3');
    expect(screen.getByRole('button', { name: /Inspect lib\/lz4.c/ })).toBeTruthy();
});

test('same-path records stay distinct across variants and compiled counts use unique paths', async () => {
    jest.spyOn(Packages, 'sourceFiles').mockResolvedValue({
        files: [file, { ...file, variant_id: 'second', variant_name: 'second',
            properties: { checksums: [{ algorithm: 'SHA256', checksumValue: 'second-hash' }], licenseConcluded: 'MIT' } }],
        complete: true,
    });
    const user = userEvent.setup();
    render(<SourceFileModal packageId={pkg.id} onClose={() => {}} />);
    const second = await screen.findByRole('button', { name: /Inspect lib\/lz4.c.*\(second\)/ });
    expect(screen.getByText(/compiled source paths/)).toHaveTextContent('1 compiled source paths');
    await user.click(second);
    expect(second).toHaveAttribute('aria-pressed', 'true');
    const details = within(screen.getByRole('region', { name: 'File details' }));
    expect(within(details.getByRole('region', { name: 'File hashes' })).getByText('second-hash')).toBeVisible();
    expect(details.getByText('License Concluded')).toBeTruthy();
    expect(details.getByText('MIT')).toBeVisible();
    await user.type(screen.getByLabelText('Filter recorded files'), 'second');
    expect(screen.getByRole('status')).toHaveTextContent('Showing 1 of 2');
});

test('changing scope resets file selection, search, and evidence filters', async () => {
    jest.spyOn(Packages, 'sourceFiles')
        .mockResolvedValueOnce({ files: [file], complete: true })
        .mockResolvedValueOnce({ files: [{ ...file, path: 'new/file.c', builds: [] }], complete: false });
    const user = userEvent.setup();
    const view = render(<SourceFileModal packageId={pkg.id} variantId="one" onClose={() => {}} />);
    await screen.findByRole('button', { name: /Inspect lib\/lz4.c/ });
    await user.type(screen.getByLabelText('Filter recorded files'), 'lz4');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Filter by build evidence' }), 'compiled');
    view.rerender(<SourceFileModal packageId={pkg.id} variantId="two" onClose={() => {}} />);
    expect(await screen.findByRole('button', { name: /Inspect new\/file.c/ })).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByLabelText('Filter recorded files')).toHaveValue('');
    expect(screen.getByRole('combobox', { name: 'Filter by build evidence' })).toHaveValue('all');
    expect(screen.queryByText('lib/lz4.c')).toBeNull();
});

test.each([true, false])('renaming saved columns preserves file column visibility (%s)', async visible => {
    const key = 'vulnscout.tables.packages.recorded-migration';
    const columns = visible ? ['Name', 'Source Files'] : ['Name'];
    localStorage.setItem(`${key}.visibleColumns`, JSON.stringify(columns));
    localStorage.setItem(`${key}.sourceFilesColumnDefaulted`, 'true');
    localStorage.setItem(`${key}.revisionColumnDefaulted`, 'true');
    localStorage.setItem(`${key}.dependencyColumnDefaulted`, 'true');
    localStorage.setItem(`${key}.maintenanceColumnDefaulted`, 'true');
    jest.spyOn(global, 'fetch').mockResolvedValue(response({ counts: {}, unrecorded: [] }));
    render(<TablePackages packages={[]} preferenceScopeKey="recorded-migration" />);
    await waitFor(() => expect(JSON.parse(localStorage.getItem(`${key}.visibleColumns`)!)).toEqual(
        visible ? ['Name', 'Recorded Files'] : ['Name'],
    ));
    expect(screen.queryByRole('button', { name: 'Recorded files helper' }) !== null).toBe(visible);
});
