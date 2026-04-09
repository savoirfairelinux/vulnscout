# Developer's Guide

## Developing VulnScout

### Requirements

* Docker or Podman (rootless or with your user in the `docker` group)
* Node.js 22 (via NVM) is required to develop the frontend without issues.
  Installation guide: [nvm](https://github.com/nvm-sh/nvm)

```bash
nvm install 22
nvm use 22
```

### Project Structure

| Directory | Purpose |
|-----------|---------|
| `src/` | Python/Flask backend (controllers, models, routes, helpers) |
| `frontend/` | React + TypeScript frontend (Vite, Tailwind CSS) |
| `tests/` | Backend unit, integration, end-to-end and webapp tests |
| `frontend/tests/` | Frontend unit tests (Jest + Testing Library) |
| `src/migrations/` | Alembic database migrations |
| `.vulnscout/` | Local cache, outputs and example input files |

### Modify the Backend

The backend is a Flask application located in `src/`. When running in dev mode the local `src/` directory is mounted into the container, so any change is picked up immediately without rebuilding the image.

Start the container in dev mode:

```bash
./vulnscout --dev start
```

Or start with inputs and the web UI in one step:

```bash
./vulnscout --dev --serve \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json
```

Flask will run with `--debug` when `DEV_MODE=true` is set in the container, enabling auto-reload on Python file changes.

### Modify the Frontend

By default, the `frontend/` directory is not mounted into the container. To get hot-reload for frontend changes, run VulnScout in dev mode — this starts the backend container and a Vite dev server on the host side:

```bash
./vulnscout --dev start
```

Or combined with a serve command that also loads input files:

```bash
./vulnscout --dev --serve \
  --add-spdx /path/to/sbom.spdx.json \
  --add-cve-check /path/to/cve-check.json
```

The Vite dev server reads `VITE_API_URL` from `frontend/.env` (created automatically from the config, default: `http://localhost:7275`) to proxy API requests to the backend container.

If `node_modules` are not yet installed, the script will run `npm install` automatically.

> **Note:** Dev mode requires `npm` to be available on the host. Use NVM 22 to ensure compatibility.

---

## Testing the Project

We use [CQFD](https://github.com/savoirfairelinux/cqfd) to run testing tools in a container.

### Quick Setup with CQFD

#### Step 1: Setup CQFD and Docker/Podman

- Install Docker: [https://docs.docker.com/engine/install/](https://docs.docker.com/engine/install/)
- Or install Podman: [https://podman.io/docs/installation](https://podman.io/docs/installation)

If using Docker, make sure it runs without requiring `sudo`. To do so, add your user to the `docker` group:

```bash
sudo groupadd docker
sudo usermod -aG docker $USER
```

Log out and log back in to apply the changes.

- Install CQFD:

```bash
git clone https://github.com/savoirfairelinux/cqfd.git
cd cqfd
sudo make install
```

For more information, visit the [CQFD GitHub repository](https://github.com/savoirfairelinux/cqfd).

#### Step 2: Initialise CQFD for this Project

Once installed, initialise the container image:

```bash
cqfd init
```

> **Note:** This only needs to be done once, unless the container definition (`.cqfd/docker/Dockerfile`) is modified.

#### Step 3: Run Tests with CQFD

To run all tests using CQFD, execute the following command:

```bash
cqfd
```

You can also run the tests separately:

```bash
cqfd -b test_backend
cqfd -b test_frontend
cqfd -b test_ci
```

### Running Tests Locally (without CQFD)

#### Backend

Activate the virtual environment and install dev dependencies first:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements/dev.txt
```

Then run the tests:

```bash
# All unit tests
pytest tests/unit_tests/

# All webapp (API) tests
pytest tests/webapp_tests/

# All tests with coverage report in terminal
pytest --cov=src tests/

# All tests with HTML coverage report
pytest --cov-report html --cov=src tests/

# Type checking
mypy --config-file tests/tox.ini
```

#### Frontend

```bash
cd frontend
npm install
npm run test          # unit tests
npm run coverage      # tests + coverage report
npm run lint          # ESLint
npm run build         # production build check
```

### Setting a Custom Version

The container version is set at build time via the `VULNSCOUT_VERSION` Docker build argument (defined in the `Dockerfile`).
It is baked into the image as both an environment variable (`ENV VULNSCOUT_VERSION`) and the OCI label `org.opencontainers.image.version`.

To build the image with a custom version:

```bash
docker build --build-arg VULNSCOUT_VERSION=v1.2.3 -t vulnscout:v1.2.3 .
```

The version is then available at runtime:

- Inside the container: via the `VULNSCOUT_VERSION` environment variable (used by the Flask `/api/version` endpoint and `entrypoint.sh --version`).
- From the host: via `docker inspect` on the image label (used by `./vulnscout --version`).

> **Note:** The `ci/release_tag.sh` script automates version bumps by updating the `ARG VULNSCOUT_VERSION` line in the `Dockerfile` along with other version references.

### Testing the Docker Image

You can test the Docker image using the provided `tests` Makefile.
To build and test the Docker image, run:

```bash
make -C tests docker_build docker_test docker_clean
```

Optionally set a custom tag:

```bash
export BUILD_TAG="my-local-test"
make -C tests docker_build docker_test docker_clean
```

---

## Code Quality and Linting

### Python Backend (Flask)

| Task | Command |
|------|---------|
| Linter | `flake8` |
| Type checking (from `tests/` folder) | `mypy --config-file tox.ini` |
| Unit tests | `pytest` |
| Coverage (terminal) | `pytest --cov=src` |
| Coverage (HTML) | `pytest --cov-report html --cov=src` |

### Frontend (React + TypeScript)

| Task | Command |
|------|---------|
| Dev server | `npm run dev` |
| Build | `npm run build` |
| Unit tests | `npm run test` (uses Jest + Testing Library) |
| Linter | `npm run lint` (ESLint) |
| Coverage report | `npm run coverage` |

> **Note:** Running `make -C tests test` will execute all linters and tests. If `pre-commit` is installed, `flake8` will also run on every commit. With CQFD, use `cqfd -b test` to run the full suite.

### Pre-commit Hook

We use `pre-commit` to automatically run `flake8` before every commit.

To enable it:

```bash
pip install pre-commit
pre-commit install
```

This helps enforce code quality and consistency across all contributions.

---

## Release Process

VulnScout follows a semantic versioning strategy with development versions between releases.

### Version Numbering Strategy

The versioning workflow follows these steps:

1. **Current stable version**: `v0.9.1` (example - keep for now)
2. **Before creating a release tag**: Bump version to `v0.10`
3. **First PR after release**: Bump version to `v0.10-dev`
4. **Feature PRs**: Continue development with `-dev` suffix
5. Repeat the cycle
