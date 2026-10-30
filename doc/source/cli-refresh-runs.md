# Exact refresh-run artifacts

`refresh` persists a distinct run, its initiating project/variant selection,
selected providers, timestamps, coverage and immutable field changes. It prints
`Refresh run: <id>` before contacting providers. For unattended callers, supply
your own **new** identity rather than parsing progress output:

```bash
run_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
./vulnscout refresh -p demo -v x86 --run-id "$run_id"
./vulnscout export refresh-changes --run-id "$run_id" --format json > changes.json
./vulnscout export refresh-changes -p demo -v x86 --run-id "$run_id" --format csv > changes.csv
```

Scope options belong **after** the command. Without `-p`, refresh covers all
stored vulnerabilities; with only `-p`, it covers that project's active scope.
`-v` requires `-p`. Export scope names are resolved to project/variant IDs and
filter the captured package links, not today's mutable findings. A shared CVE's
global metadata change is visible in each captured scope that observed it, but
an export filtered to one scope never exposes other scopes' package links.

An unchanged, successfully checked refresh is a valid `complete` artifact with
zero changes. A field first receiving a value is `first_enrichment`, not a
comparison against a fabricated historical baseline. Missing provider responses,
failed targets, skipped work and cancellation produce explicit coverage and an
`incomplete` artifact; absence from a response is never itself a removal.
Confirmed field clearing has `change_type: removal`. CVSS fields retain metric
ID, version and author, and their before/after values include score and vector.

The explicit refresh command exits nonzero when any provider is incomplete.
Its partial artifact remains exportable. Artifact exports exit nonzero on
selection or output failure; successfully exporting an incomplete run does not
reclassify that refresh as successful. JSON preserves structured values. CSV
has a `run` metadata row even when no fields changed, followed by `change` rows;
`before`, `after`, `packages` and `metadata` cells are JSON-encoded. Multiline
text is CSV-quoted, and formula-like text is never emitted as an executable cell.

## Noninteractive archive-per-run CI example

Keep the caller's exact identity, archive partial results, and propagate the
refresh exit code. Configure the CI artifact uploader to retain this directory
even when the job fails:

```bash
set -eu
run_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
archive="artifacts/refresh-$run_id"
mkdir -p "$archive"
printf '%s\n' "$run_id" > "$archive/run-id.txt"
status=0
./vulnscout refresh -p demo -v x86 --run-id "$run_id" \
  > "$archive/refresh.log" 2>&1 || status=$?
./vulnscout export refresh-changes --run-id "$run_id" --format json > "$archive/changes.json"
./vulnscout export refresh-changes --run-id "$run_id" --format csv > "$archive/changes.csv"
exit "$status"
```

## Retention and direct Flask commands

The default availability window is **90 days**, independent of queue dismissal
or its one-hour process-local retention. Set `FLASK_REFRESH_RUN_RETENTION_DAYS`
to a JSON integer for the application (for example `180`) to change it. Archive
runs externally before expiry. Missing, expired or out-of-scope exact IDs fail
explicitly; they are **never** replaced with another run or “latest”.

For deployments running Python directly:

```bash
flask --app src.bin.webapp refresh-vulnerability-data --project demo --run-id "$run_id"
flask --app src.bin.webapp export-refresh-changes --run-id "$run_id" --format json --output changes.json
flask --app src.bin.webapp prune-refresh-runs
```

Schedule `prune-refresh-runs` to physically delete expired rows and snapshots.
Expiry is enforced by read/export endpoints before physical deletion. Live
vulnerability, package or field-history cleanup does not mutate retained
refresh artifacts. Reads reconcile unfinished runs whose local owner process
has stopped (including PID reuse) to incomplete, without interrupting other
live CLI/server processes. An owner on another host/container is considered
interrupted after 24 hours without a committed target/source heartbeat.
Recovery time is recorded as `finished_at`; the actual interruption time is
unknown. See [the API reference](api.md#refresh-run-artifacts) for
run listing, scope and pagination parameters.
