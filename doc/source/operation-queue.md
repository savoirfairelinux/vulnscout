# Operations and Live Progress

VulnScout tracks long-running work in a server-side operation queue. The navigation bar shows how many operations are active and finished; open **Operation queue** to see individual status, progress, logs, cancellation, and completed export downloads. Closing the window or opening another browser tab does not stop the work. Each tab opens its own server-sent event (SSE) connection to the same operation state.

The initial database import shown when the app first starts is different: its loading screen still checks `/api/scan/status` until the application is ready. Scan History JSON imports and direct downloads are also separate from the queued document-export workflow.

## What Is Queued

| Operation | Started from | Execution and completion |
|-----------|--------------|--------------------------|
| Scanner job | Scan History's **Run Scans** wizard | Grype, NVD, OSV, and sbom-cve-check scans run in that order. Each source/variant pair has its own operation. |
| Vulnerability-data refresh | The Vulnerabilities page, or after scans | NVD, EPSS, GHSA, and EUVD refresh jobs run in that order. The scan wizard resolves newly discovered vulnerabilities after its scans finish. |
| SBOM upload | Settings, in a selected variant | The upload has its own operation; successful completion reloads the affected data. |
| Document export | The Export page | The export runs asynchronously; the requesting tab downloads the ZIP after completion. |
| Boot enrichment | Startup processing | Appears in the queue and updates the loaded data when finished. |

Scans and refreshes share **one serial pipeline**, so a refresh cannot run alongside another pipeline job. Document exports have a separate lane with two workers; SBOM uploads use another lane and can proceed while a scan is running. A submission containing several scans and refreshes is reordered by the server into the source order above. The batch limit is **100 expanded operations**, not 100 variant IDs: for example, scanning 25 variants with four sources and requesting three refreshes would exceed the limit.

The queue records `queued`, `running`, `done`, `error`, and `cancelled` states. Errors and partial progress are available in the operation details; a completed or failed item can be dismissed from all tabs. Cancel a queued operation to prevent it from starting; running work stops at the next cancellation checkpoint, so the request does not mean it has already stopped. Not every operation supports cancellation: check its `cancellable` field. A failed or cancelled scan in a wizard batch prevents its dependent deferred refresh from doing work.

## Restore and Reconnect

Opening a tab starts one `/api/events/stream` connection for the app. A fresh connection receives a full `snapshot`, then `operation` and `operation_removed` updates. Each event ID has an instance-specific `<epoch>:<sequence>` cursor. On interruption, the client reconnects with the complete cursor to replay missed updates. If the gap is too old, the server restarted, or a subscriber overflowed, the server sends a new snapshot instead. A heartbeat keeps an otherwise idle stream alive.

The snapshot restores queued and running operations after a page reload. When a scan, refresh, upload, or enrichment reaches a terminal state, the app refreshes affected Explorer data in every connected tab; Scan History refreshes its list after scan completion. Terminal items stay in the in-memory registry for up to **one hour**, unless dismissed sooner. The registry is process-local and is cleared by a server restart; it is not durable job storage. The stream accepts up to **32 concurrent connections by default**, configurable through `VULNSCOUT_SSE_MAX_STREAMS`; an excess connection receives HTTP 503. A running stream occupies a server thread.

## Export and Upload Results

Document exports return an `op_id` instead of a ZIP immediately. A completed export reports `result.download_ready` and `result.filename`; its ZIP can be downloaded from the **Operation queue** if automatic download was missed, for example after a reload. The archive is retained for up to **one hour**, subject to the server's retention limits, and is **consumed on the first download**. Downloading it automatically leaves no second copy available through the queue; an expired or consumed archive returns HTTP 410. Export operation status is not a guarantee that its ZIP is still retained.

Settings uploads return an `op_id` and `scan_id`. Settings displays the operation's progress and reloads data after success; a server error is shown instead of polling an upload-status endpoint. Leaving Settings does not cancel the upload, and its operation remains visible in the shared queue.

## API Usage

For programmatic scans and refreshes, submit jobs to `POST /api/operations` and retain the returned `queue_id` and operation IDs. `GET /api/operations` gives the current snapshot for diagnostics or clients that cannot keep a stream open. Subscribe to `GET /api/events/stream` **before** submitting work if every update matters, or inspect the snapshot after submission. Reconnect with the full SSE `Last-Event-ID` (or URL-encoded `last_event_id` query parameter). Do not poll the removed per-scan, per-refresh, export-status, or upload-status routes.

Use `POST /api/operations/<op_id>/cancel` for one active operation or `POST /api/operations/queue/<queue_id>/cancel` for an entire batch. `DELETE /api/operations/<op_id>` dismisses a terminal item; it does not delete scan or vulnerability data. The [API reference](api.md) describes the payloads and status codes.