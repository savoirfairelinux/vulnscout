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

The default tag is `v0.24`; `update` does not select a newer release tag
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

`config get`, `set`, `unset`, and `list` manage two stores. Application settings
live in `$VULNSCOUT_CACHE_DIR/config.env`, shared with the container. Launcher
settings live in
`$VULNSCOUT_BUILD_DIR/launcher.env` on the host. Keep the build directory and
helper state under operator control, outside any directory shared with a
container. The default cache and outputs are *children* of the build directory.

**Upgrading:** use the updated wrapper to stop any old helper
(`./vulnscout ai-context helper stop`). The wrapper ignores these launcher
settings in the old `cache/config.env`; it does not copy them into host policy:

- `VULNSCOUT_HOST_HELPER_STATE_DIR`
- `VULNSCOUT_BIND_ADDRESS`
- `VULNSCOUT_CONTAINER`, `VULNSCOUT_IMAGE`
- `VULNSCOUT_CACHE_DIR`, `VULNSCOUT_OUTPUTS_DIR`, `VULNSCOUT_SBOM_CVE_CHECK_DB_DIR`
- `VITE_API_URL` (the host dev frontend's backend URL)

Re-enter only values you have independently verified, for example
`./vulnscout config set VULNSCOUT_IMAGE localhost/vulnscout:host-folders`, or export
them on the host. `VULNSCOUT_BUILD_DIR` must be exported if non-default; a cache
entry cannot select the build directory. Existing application settings stay in
place and do not need migration.

Before moving helper state, run `./vulnscout ai-context helper stop` with
the **old** settings still in effect. Move the entire private state directory,
including `.approval.key` and `registry.json` if present, keeping its ownership
and `0700` permissions. Then set `VULNSCOUT_HOST_HELPER_STATE_DIR` to the new
location (or unset it to use the default) and run `./vulnscout ai-context helper start`.
`config set` and `unset` refuse to switch away from a running helper's state,
even if its socket is missing. Stop it before changing an exported override, too.

`config set` saves absolute, resolved cache and helper state directories. Relative
paths supplied in the environment or in an older launcher file are resolved
from the directory where you invoke the wrapper. The cache root may be an
operator-controlled symlink; `host-helper/` inside the shared cache must not be
a symlink.

On a fresh installation, run `./vulnscout start` **before setting application keys**.
Startup generates defaults only when `config.env` does not exist; setting a
single key first creates a partial file without the Flask host/port settings.
If a partial file already exists, add `FLASK_RUN_HOST=0.0.0.0` and
`FLASK_RUN_PORT=7275` with `config set`, then restart. Keep configuration
values in the application file shell-compatible because the **container**
entrypoint sources it. The host wrapper never sources either file. Launcher
values are single-line literals; quote spaces for your command shell.

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

Export `VULNSCOUT_BUILD_DIR` to select a different launcher configuration.
Container name, image, host mount directories, helper state
directory, and `VITE_API_URL` can be set persistently. Explicit host environment
values override these saved settings. `config get` and `list` show stored values, not environment
overrides. The launcher explicitly forwards host `GRYPE_MEMLIMIT` and
`SBOM_CVE_CHECK_AUTO_UPDATE` at container creation, but does not inject later
host changes into `docker exec`/`podman exec`. Restart after environment, mount,
or web-listener changes. Scan commands reload persistent application settings;
an already-running web server must be restarted to pick up config-file changes.

#### Container & Runtime

| Variable | Description | Default |
|----------|-------------|---------|
| `VULNSCOUT_CONTAINER` | Name of the container; export on the host before invocation | `vulnscout` |
| `VULNSCOUT_IMAGE` | Container image to use | `docker.io/sflinux/vulnscout:v0.24` |
| `VULNSCOUT_BUILD_DIR` | Root build directory on the host; export before first run | `.vulnscout` beside the launcher |
| `VULNSCOUT_OUTPUTS_DIR` | Directory for output files on the host | `$VULNSCOUT_BUILD_DIR/outputs` |
| `VULNSCOUT_CACHE_DIR` | Cache directory (SQLite database and config); export before first run | `$VULNSCOUT_BUILD_DIR/cache` |
| `VULNSCOUT_BIND_ADDRESS` | Host IPv4 address on which to publish port `7275`; set on the host, not in the shared config | `127.0.0.1` |
| `FLASK_RUN_PORT` | Container web-listener port; keep `7275` with the wrapper's port mapping | `7275` in generated config |
| `FLASK_RUN_HOST` | Container bind address; keep `0.0.0.0` for access through the published port | `0.0.0.0` in generated config |
| `VITE_API_URL` | Optional backend API URL for the dev frontend (empty uses Vite's same-origin `/api` proxy) | empty |
| `USER_UID` | UID used to write output files | current user |
| `USER_GID` | GID used to write output files | current group |
| `VULNSCOUT_HOST_HELPER_STATE_DIR` | Host-only directory of the host folder helper (alias registry, PID and log); export on the host | `$VULNSCOUT_BUILD_DIR/host-helper` |

The wrapper always publishes host port `7275` to container port `7275`; changing
`FLASK_RUN_PORT` alone does not change this mapping. To use a different host
port, manage the container yourself with a suitable `-p` mapping; see
[Using Container Entrypoint](container-entrypoint.md).

To allow LAN clients, use e.g. `./vulnscout config set VULNSCOUT_BIND_ADDRESS 192.168.1.10`
(substitute the host's LAN IPv4 address). `0.0.0.0` publishes the UI and API on
**all IPv4 interfaces**. Restrict network access appropriately. Setting or unsetting
the key recreates a running container unless the host environment overrides it;
start `serve` again if needed. A non-loopback
publication never enables the container-forwarder exception for the Agent or host-folder API.
Use `./vulnscout config unset VULNSCOUT_BIND_ADDRESS` to restore the default
when no host environment override is active.

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
