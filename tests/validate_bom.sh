#!/usr/bin/env bash
# BOM Schema Validation Script
# Validates CycloneDX, SPDX, and OpenVEX files against official JSON schemas.
#
# Tools used:
#   - ajv-cli + ajv-formats: for CycloneDX (1.4, 1.5 and 1.6) and SPDX (2.2, 2.3, 3.0.1)
#   - vexctl: for OpenVEX
#
# Sceham files were sourced from:
#
# CycloneDX (from CycloneDX/specification repo):
# bom-1.4.schema.json = https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.4.schema.json
# bom-1.5.schema.json = https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.5.schema.json
# bom-1.6.schema.json = https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6.schema.json
# spdx.schema.json = https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json
# jsf-0.82.schema.json = https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json
#
# SPDX 2.x (from spdx/spdx-spec repo):
# spdx-schema-2.2.json = https://raw.githubusercontent.com/spdx/spdx-spec/development/v2.2.2/schemas/spdx-schema.json
# spdx-schema-2.3.json = https://raw.githubusercontent.com/spdx/spdx-spec/support/2.3/schemas/spdx-schema.json
#
# SPDX 3.x:
# spdx-json-schema-3.0.1.json = https://spdx.org/schema/3.0.1/spdx-json-schema.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCHEMA_DIR="${SCRIPT_DIR}/schemas"
CDX_SCHEMA_DIR="${SCHEMA_DIR}/cyclonedx"
SPDX_SCHEMA_DIR="${SCHEMA_DIR}/spdx"
NPM_PREFIX="${SCHEMA_DIR}/.npm"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
ERRORS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

print_header() {
    echo ""
    echo -e "${BOLD}=== $1 ===${NC}"
}

print_pass() {
    echo -e "  ${GREEN}PASS${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

print_fail() {
    echo -e "  ${RED}FAIL${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    ERRORS+=("$1")
}

print_skip() {
    echo -e "  ${YELLOW}SKIP${NC} $1"
    SKIP_COUNT=$((SKIP_COUNT + 1))
}

# Install ajv-cli and ajv-formats into a contained directory
ensure_ajv() {
    if ! command -v npx &> /dev/null; then
        echo "ERROR: npx not found. Please install Node.js and npm."
        exit 1
    fi

    if [[ ! -x "${NPM_PREFIX}/node_modules/.bin/ajv" ]]; then
        echo "Installing ajv-cli and ajv-formats into ${NPM_PREFIX}..."
        mkdir -p "${NPM_PREFIX}"
        npm install --prefix "${NPM_PREFIX}" ajv-cli ajv-formats
    fi
}

# Detect BOM format and version from file contents.
# Sets FORMAT and VERSION variables.
detect_format() {
    local file="$1"

    # Check for CycloneDX (has "specVersion" and "bomFormat": "CycloneDX")
    if jq -e 'select(.bomFormat == "CycloneDX" and .specVersion != null)' "$file" > /dev/null 2>&1; then
        FORMAT="cyclonedx"
        VERSION=$(jq -r '.specVersion' "$file")
        return 0
    fi

    # Check for SPDX 2.x (has "spdxVersion")
    if jq -e 'has("spdxVersion")' "$file" > /dev/null 2>&1; then
        FORMAT="spdx2"
        VERSION=$(jq -r '.spdxVersion' "$file")
        return 0
    fi

    # Check for SPDX 3.x (has "@context" containing "spdx.org")
    if jq -e '."@context" | tostring | test("spdx\\.org")' "$file" > /dev/null 2>&1; then
        FORMAT="spdx3"
        # Extract version from @context URL
        VERSION=$(jq -r '(."@context" | tostring | capture("spdx\\.org/rdf/(?<v>[0-9]+\\.[0-9]+\\.[0-9]+)").v) // "3.0.1"' "$file")
        return 0
    fi

    # Check for OpenVEX (has "@context" containing "openvex")
    if jq -e '."@context" | tostring | ascii_downcase | test("openvex")' "$file" > /dev/null 2>&1; then
        FORMAT="openvex"
        VERSION=""
        return 0
    fi

    FORMAT="unknown"
    VERSION=""
    return 1
}

# Select the appropriate schema file for the detected format/version.
select_schema() {
    local format="$1"
    local version="$2"

    case "${format}" in
        cyclonedx)
            case "${version}" in
                1.4) echo "${CDX_SCHEMA_DIR}/bom-1.4.schema.json" ;;
                1.5) echo "${CDX_SCHEMA_DIR}/bom-1.5.schema.json" ;;
                1.6) echo "${CDX_SCHEMA_DIR}/bom-1.6.schema.json" ;;
                *)   echo ""; return 1 ;;
            esac
            ;;
        spdx2)
            case "${version}" in
                SPDX-2.2) echo "${SPDX_SCHEMA_DIR}/spdx-schema-2.2.json" ;;
                SPDX-2.3) echo "${SPDX_SCHEMA_DIR}/spdx-schema-2.3.json" ;;
                *)        echo ""; return 1 ;;
            esac
            ;;
        spdx3)
            case "${version}" in
                3.0.1) echo "${SPDX_SCHEMA_DIR}/spdx-json-schema-3.0.1.json" ;;
                *)     echo ""; return 1 ;;
            esac
            ;;
        *)
            echo ""; return 1
            ;;
    esac
}

# Validate a file with ajv against the appropriate schema.
# Returns 0 on success, 1 on failure.
validate_with_ajv() {
    local file="$1"
    local format="$2"
    local version="$3"
    local schema

    schema=$(select_schema "${format}" "${version}")
    if [[ -z "${schema}" ]]; then
        echo "No schema available for ${format} ${version}"
        return 1
    fi

    local ajv_args=(validate -c ajv-formats --strict=false)

    case "${format}" in
        cyclonedx)
            ajv_args+=(--spec=draft7)
            ajv_args+=(-s "${schema}")
            ajv_args+=(-r "${CDX_SCHEMA_DIR}/spdx.schema.json")
            ajv_args+=(-r "${CDX_SCHEMA_DIR}/jsf-0.82.schema.json")
            ;;
        spdx2)
            ajv_args+=(--spec=draft7)
            ajv_args+=(-s "${schema}")
            ;;
        spdx3)
            ajv_args+=(--spec=draft2020)
            ajv_args+=(-s "${schema}")
            ;;
    esac

    ajv_args+=(-d "${file}")

    "${NPM_PREFIX}/node_modules/.bin/ajv" "${ajv_args[@]}" 2>&1
}

# Validate a file with vexctl.
validate_with_vexctl() {
    local file="$1"
    vexctl validate "${file}" 2>&1
}

# Validate a single file, expecting it to pass.
validate_expect_pass() {
    local file="$1"
    local rel_path="${file#"${REPO_ROOT}/"}"

    if ! detect_format "${file}"; then
        print_fail "${rel_path} (could not detect format)"
        return
    fi

    if [[ "${FORMAT}" == "openvex" ]]; then
        if ! command -v vexctl &> /dev/null; then
            print_skip "${rel_path} (vexctl not installed)"
            return
        fi
        if validate_with_vexctl "${file}" > /dev/null 2>&1; then
            print_pass "${rel_path} (OpenVEX)"
        else
            print_fail "${rel_path} (OpenVEX validation failed)"
        fi
        return
    fi

    if validate_with_ajv "${file}" "${FORMAT}" "${VERSION}" > /dev/null 2>&1; then
        print_pass "${rel_path} (${FORMAT} ${VERSION})"
    else
        print_fail "${rel_path} (${FORMAT} ${VERSION} schema validation failed)"
        echo "    Details:"
        validate_with_ajv "${file}" "${FORMAT}" "${VERSION}" 2>&1 | sed 's/^/    /' || true
    fi
}

# Validate a single file, expecting it to fail.
validate_expect_fail() {
    local file="$1"
    local label="$2"
    local rel_path="${file#"${REPO_ROOT}/"}"

    if validate_with_ajv "${file}" "${label}" "" > /dev/null 2>&1; then
        print_fail "${rel_path} (expected validation to fail, but it passed)"
    else
        print_pass "${rel_path} (correctly rejected)"
    fi
}

# Negative test: validate an invalid file against a specific schema directly.
validate_invalid_cdx() {
    local file="$1"
    local rel_path="${file#"${REPO_ROOT}/"}"
    local schema="${CDX_SCHEMA_DIR}/bom-1.4.schema.json"

    if "${NPM_PREFIX}/node_modules/.bin/ajv" validate -c ajv-formats --strict=false --spec=draft7 \
        -s "${schema}" \
        -r "${CDX_SCHEMA_DIR}/spdx.schema.json" \
        -r "${CDX_SCHEMA_DIR}/jsf-0.82.schema.json" \
        -d "${file}" > /dev/null 2>&1; then
        print_fail "${rel_path} (expected validation to fail, but it passed)"
    else
        print_pass "${rel_path} (correctly rejected as invalid CycloneDX)"
    fi
}

validate_invalid_spdx() {
    local file="$1"
    local rel_path="${file#"${REPO_ROOT}/"}"
    local schema="${SPDX_SCHEMA_DIR}/spdx-schema-2.2.json"

    if "${NPM_PREFIX}/node_modules/.bin/ajv" validate -c ajv-formats --strict=false --spec=draft7 \
        -s "${schema}" \
        -d "${file}" > /dev/null 2>&1; then
        print_fail "${rel_path} (expected validation to fail, but it passed)"
    else
        print_pass "${rel_path} (correctly rejected as invalid SPDX)"
    fi
}

# ============================================================================
# Main
# ============================================================================

echo -e "${BOLD}BOM Schema Validation${NC}"
echo "Schemas: ${SCHEMA_DIR}"
echo ""

ensure_ajv

# --- Positive tests: valid files that must pass ---
print_header "CycloneDX Validation (positive tests)"
validate_expect_pass "${REPO_ROOT}/tests/docker/cdx/valid_v1_4.cdx.json"
validate_expect_pass "${REPO_ROOT}/example/spdx2/cyclonedx-export/bom.json"
validate_expect_pass "${REPO_ROOT}/example/spdx2/cyclonedx-export/vex.json"

print_header "SPDX 2.x Validation (positive tests)"
validate_expect_pass "${REPO_ROOT}/tests/docker/spdx/valid_v2_2.spdx.json"

print_header "SPDX 3.x Validation (positive tests)"
validate_expect_pass "${REPO_ROOT}/example/spdx3/core-image-minimal-qemux86-64.rootfs.spdx.json"

# --- Negative tests: invalid files that must fail ---
print_header "Negative Tests (must be rejected)"
validate_invalid_cdx "${REPO_ROOT}/tests/docker/cdx/invalid.cdx.json"
validate_invalid_spdx "${REPO_ROOT}/tests/docker/spdx/invalid.spdx.json"

# --- Summary ---
echo ""
echo -e "${BOLD}=== Summary ===${NC}"
echo -e "  ${GREEN}Passed: ${PASS_COUNT}${NC}"
echo -e "  ${RED}Failed: ${FAIL_COUNT}${NC}"
echo -e "  ${YELLOW}Skipped: ${SKIP_COUNT}${NC}"
echo ""

if [[ ${FAIL_COUNT} -gt 0 ]]; then
    echo -e "${RED}${BOLD}VALIDATION FAILED${NC}"
    echo "Failures:"
    for err in "${ERRORS[@]}"; do
        echo "  - ${err}"
    done
    exit 1
fi

echo -e "${GREEN}${BOLD}ALL VALIDATIONS PASSED${NC}"
exit 0
