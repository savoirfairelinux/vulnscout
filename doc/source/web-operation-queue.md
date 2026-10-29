(operation-queue)=
# Operation Queue

The navigation bar's **Operation queue** shows the status, progress, and logs for scans, vulnerability-data refreshes, SBOM uploads, document exports, and startup enrichment. Each tab sees the same server-side operations. Closing a tab or reloading the page does not stop them; reopening the queue restores their current state. The initial database import still uses its own loading screen, and Scan History JSON imports and direct downloads are not queued document exports.

Scans and refreshes share one serial pipeline. In a batch, scans run in Grype, NVD, OSV, sbom-cve-check order, followed by NVD, EPSS, GHSA, EUVD refreshes. Each source/variant pair is one operation; a batch accepts at most 100 expanded operations. Document exports run in a separate two-worker lane, and SBOM uploads have their own lane, so they can proceed during scans.

An operation can be `queued`, `running`, `done`, `error`, or `cancelled`. Cancel a queued job to prevent it from starting; running jobs stop at a cancellation checkpoint, not necessarily immediately. Check whether an operation is cancellable before requesting cancellation. Failed or cancelled scans prevent dependent post-scan refreshes from doing work. Finished items can be dismissed from every tab without removing scan results.

The queue keeps terminal operations for up to one hour unless dismissed. This state is process-local: restarting the server clears the queue, not just the browser view. A missed export download can be retried from the queue while its ZIP is retained, but the archive expires and is consumed on its first download. A repeat or expired download normally returns `404`; start a new export instead. Settings uploads also remain visible here when leaving Settings, and successful uploads refresh the affected data.
