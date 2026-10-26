# Container Lifecycle and Configuration

## Container Lifecycle

The `vulnscout` script manages the container automatically (using Docker or Podman, whichever is available). You can also control it explicitly:

```bash
# Start the container (done automatically by most commands)
./vulnscout start

# Stop and remove the container
./vulnscout stop

# Restart the container (useful after changing config)
./vulnscout restart
```

## Updating VulnScout

To pull the configured container image tag and replace a running container when
its image has changed:

```bash
./vulnscout update
```

The default tag is `v0.23`; `update` does not select a newer release tag
automatically. To change releases, set `VULNSCOUT_IMAGE` to the desired published
tag, then run `update` and `restart` (or `start` if no container is running).

Inspect the version label of the configured local image:

```bash
./vulnscout version
```

This reports the image's version, not necessarily the running container's version.
Check the web interface's version after restarting to confirm the active backend.

## Configuration

### Configuration Commands

Persistent configuration is stored in `.vulnscout/cache/config.env` and is automatically loaded on each run.

On a fresh installation, run `./vulnscout start` **before the first `config set`**.
Startup generates defaults only when `config.env` does not exist; setting a
single key first creates a partial file without the Flask host/port settings.
If a partial file already exists, add `FLASK_RUN_HOST=0.0.0.0` and
`FLASK_RUN_PORT=7275` with `config set`, then restart. Keep configuration
values shell-compatible because the file is sourced as shell configuration.

Rootless Podman maps the host owner to container root with
`--userns=keep-id:uid=0,gid=0 --user=0:0`. The entrypoint uses this same identity
for ownership changes when the launcher sets `VULNSCOUT_ROOTLESS_PODMAN=true`.
This lets startup read the private configuration and keeps mounted paths
host-owned. Both launcher and entrypoint must include this fix: rebuild your
container image, or use `--dev` to mount the updated local entrypoint.
If an older container left the cache or `config.env` owned by a subordinate host
UID, the launcher restores ownership through `podman unshare` before loading
the configuration, including when the cache is private (mode `700`). The
configuration stays private (mode `600`); do not make it world-readable to
work around a permission error.

```text
# Set a config value
./vulnscout config set <key> <value>

# Print one value
./vulnscout config get <key>

# List current configuration (sensitive values masked)
./vulnscout config list

# Remove a config key
./vulnscout config unset <key>
```

Example — initialize configuration, then set an NVD API key for higher API rate limits:

```bash
./vulnscout start
./vulnscout config set NVD_API_KEY abc123
./vulnscout restart
```

### Environment Variables

Use `config set` for application settings such as API keys, proxy values, and
report metadata. Arbitrary host environment variables are **not** automatically
forwarded into the container.

Export host launcher settings before invocation. In particular, export
`VULNSCOUT_CONTAINER`, `VULNSCOUT_BUILD_DIR`, and `VULNSCOUT_CACHE_DIR` before
the first run: container identity and initial config-file lookup are determined
before the stored configuration is loaded. `VULNSCOUT_IMAGE` and
`VULNSCOUT_OUTPUTS_DIR` can also be configured persistently.

Stored configuration is sourced after host variables, so stored values override
same-named exports (except settings such as the container name that were already
resolved before sourcing). The launcher explicitly forwards host `GRYPE_MEMLIMIT` and
`SBOM_CVE_CHECK_AUTO_UPDATE` at container creation, but does not inject later
host changes into `docker exec`/`podman exec`. Restart after environment, mount,
or web-listener changes. Scan commands reload persistent application settings;
an already-running web server must be restarted to pick up config-file changes.

#### Container & Runtime

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNSCOUT_CONTAINER` | Name of the container; export on the host before invocation | `vulnscout` |
| `VULNSCOUT_IMAGE` | Container image to use | `docker.io/sflinux/vulnscout:v0.23` |
| `VULNSCOUT_BUILD_DIR` | Root build directory on the host; export before first run | `.vulnscout` beside the launcher |
| `VULNSCOUT_OUTPUTS_DIR` | Directory for output files on the host | `$VULNSCOUT_BUILD_DIR/outputs` |
| `VULNSCOUT_CACHE_DIR` | Cache directory (SQLite database and config); export before first run | `$VULNSCOUT_BUILD_DIR/cache` |
| `FLASK_RUN_PORT` | Container web-listener port; keep `7275` with the wrapper's fixed `7275:7275` publishing | `7275` in generated config |
| `FLASK_RUN_HOST` | Container bind address; keep `0.0.0.0` for access through the published port | `0.0.0.0` in generated config |
| `VITE_API_URL` | Optional backend API URL for the dev frontend (empty uses Vite's same-origin `/api` proxy) | empty |
| `USER_UID` | UID used to write output files | current user |
| `USER_GID` | GID used to write output files | current group |

The wrapper always publishes host port `7275` to container port `7275`; changing
`FLASK_RUN_PORT` alone does not change this mapping. To use a different host
port, manage the container yourself with a suitable `-p` mapping; see
[Using Container Entrypoint](container-entrypoint.md).

`REFRESH_REMOTE_DELAY` is a legacy setting, not a refresh scheduler. Generated
configs contain `2w` and the entrypoint fallback is `48h`, but current enrichment
does not consume this value. Use `refresh` explicitly when current data is needed.

#### Scan & Enrichment

| Variable | Description | Default |
|----------|-------------|---------|
| `NVD_API_KEY` | NVD API key for higher rate limits | _(none)_ |
| `IGNORE_PARSING_ERRORS` | Continue scanning even if input files contain errors | `false` |
| `VERBOSE_MODE` | Enable verbose logging in the container | `false` |
| `SBOM_CVE_CHECK_AUTO_UPDATE` | Clone/fetch local advisory databases before NVD/local sbom-cve-check scans; `0` uses existing clones offline | `1` |
| `VULNSCOUT_SBOM_CVE_CHECK_DB_DIR` | Optional host directory with `nvd-fkie` and `cvelist` clones; mounted by the wrapper at `/local_databases` on startup | cache's `local_databases` directory |

#### Report Metadata

| Variable | Description | Default |
|----------|-------------|---------|
| `PRODUCT_NAME` | Product name embedded in reports and SBOMs | _(none)_ |
| `PRODUCT_VERSION` | Product version embedded in reports | _(none)_ |
| `AUTHOR_NAME` | Author/company name embedded in reports | _(none)_ |
| `CLIENT_NAME` | Customer company name (optional, may be empty) | _(none)_ |
| `CONTACT_EMAIL` | Contact email embedded in reports | _(none)_ |
| `DOCUMENT_URL` | URL embedded in exported SBOM documents | _(none)_ |

## HTTP Proxy Configuration

VulnScout supports HTTP proxies. Set them via the config command:

```bash
./vulnscout start
./vulnscout config set HTTP_PROXY http://proxy.example.com:8080
./vulnscout config set HTTPS_PROXY http://proxy.example.com:8080
./vulnscout config set NO_PROXY localhost,127.0.0.1
./vulnscout restart
```

Start `serve` again after restarting if the web interface is needed. Merely
exporting these variables on the host does not forward them into the wrapper's
container. For a container you manage yourself, pass them with `docker run -e`
or put them in the mounted configuration, then recreate/restart the web process
as appropriate.
