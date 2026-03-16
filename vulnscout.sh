#!/bin/bash

# VulnScout script intended to be used in projects.
# Some features include running an interactive scan, generate report, non-interactive scan, etc.
# Use `vulnscout.sh --help` for more information.
# Exit 0: everything ok
# Exit 1: execution error (missing conf, docker issue)
# Exit 2: only in non-interactive mode, used when report failed to met user conditions
#
# Note: Keep this file indented with tabs, not spaces, or you break the help message.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail # Enable error checking

show_help() {
  echo "    VulnScout ${VULNSCOUT_VERSION}"
  echo "    Copyright (C) 2024-2026 Savoir-faire Linux, Inc."
  echo ""
  echo "    This program comes with ABSOLUTELY NO WARRANTY. This is free"
  echo "    software, and you are welcome to redistribute it under the terms"
  echo "    of the GNU GPLv3 license; see the LICENSE for more informations."
  echo ""
  echo "Usage: ./vulnscout.sh --name <project_name> [--option]"
  echo ""
  echo "Mandatory argument:"
  echo "  --name <project_name> name of the sub folder entry in .vulnscout/"
  echo ""
  echo "Extra Vulnscout configuration:"
  echo "  --workdir_path <path>   (default: current directory) Path to vulnscout installation"
  echo "  --nvd-api-key <key>   (optional) NVD API key to increase rate limits"
  echo "  --http-proxy <url>   (optional) HTTP proxy URL"
  echo "  --https-proxy <url>   (optional) HTTPS proxy URL"
  echo "  --no-proxy <hosts>   (optional) Comma-separated list of hosts to bypass proxy"
  echo ""
  echo "Sources configuration:"
  echo "  --variant <name>   variant name for the following input file(s) (default: 'default')"
  echo "  --spdx  <path>     path to the SPDX 2 or SPDX 3 SBOM file/archive"
  echo "  --cdx  <path>      path to the CycloneDX directory"
  echo "  --openvex  <path>      path to the OpenVEX JSON file"
  echo "  --cve-check  <path>      path to the Yocto CVE check JSON file
  --cve-check-exclude-patched     do not parse cve_check vulnerabilities with patched status"
  echo "  --ignore-parsing-errors     do not stop execution on parsing error"
  echo ""
  echo "Non-interactive configuration:"
  echo "  --no_webui  Disable the web UI (default: enabled)"
  echo "  --fail_condition <condition>  Set the fail condition for the scan (e.g., cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%))"
  echo "  --report-template <filename>  Template filename from .vulnscout/templates/ to generate in non-interactive mode"
  echo ""
  echo "Optional company/product information (for report generation):"
  echo "  --product_name <name>       Product name"
  echo "  --product_version <version> Product version"
  echo "  --company_name <name>       Company name"
  echo "  --contact_email <email>     Contact email"
  echo "  --document_url <url>        Document URL"
  echo ""
  echo "Other options:"
  echo "  --db-uri <uri>    Custom SQLAlchemy database URI (default: sqlite in cache folder)"
  echo "  --skip-grype-scan Skip the Grype scan which can detect new vulnerabilities"
  echo "  --help, -h        Show this help message and exit"
  echo "  --build           Build the Docker image locally (requires --dev)
  --dev             Use the development version of VulnScout"
  echo "  -d, --detach      Run VulnScout in detached mode"
  echo "  --stop            Stop running VulnScout container"
}

require_value(){
    local flag="$1"
    local value="$2"

    if [[ -z "$value" || "$value" =~ ^-- ]]; then
        echo "Error: $flag requires a value"
        exit 1
    fi
}

require_directory() {
    local flag="$1"
    local path="$2"

    if [[ -z "$path" || "$path" =~ ^-- ]]; then
        echo "Error: $flag requires a value"
        exit 1
    fi

    if [[ ! -d "$path" ]]; then
        echo "Error: Directory not found for $flag: $path"
        exit 1
    fi
}

require_file() {
    local flag="$1"
    local path="$2"

    if [[ -z "$path" || "$path" =~ ^-- ]]; then
        echo "Error: $flag requires a value"
        exit 1
    fi

    if [[ ! -f "$path" ]]; then
        echo "Error: File not found for $flag: $path"
        exit 1
    fi
}

VULNSCOUT_PATH="$(dirname "$(readlink -f "$0")")/.vulnscout"
VULNSCOUT_SPDX_PATH=""
VULNSCOUT_CDX_PATH=""
VULNSCOUT_OPENVEX_PATH=""
VULNSCOUT_CVE_PATH=""
VULNSCOUT_ENTRY_NAME=""
VULNSCOUT_FAIL_CONDITION=""
VULNSCOUT_NVD_API_KEY=""
VULNSCOUT_INTERACTIVE_MODE="true"
VULNSCOUT_VERBOSE_MODE="false"
VULNSCOUT_FLASK_RUN_PORT="7275"
VULNSCOUT_FLASK_RUN_HOST="0.0.0.0"
VULNSCOUT_GENERATE_DOCUMENTS="summary.adoc,time_estimates.csv"
VULNSCOUT_IGNORE_PARSING_ERRORS="false"
VULNSCOUT_PRODUCT_NAME=""
VULNSCOUT_PRODUCT_VERSION=""
VULNSCOUT_COMPANY_NAME=""
VULNSCOUT_CONTACT_EMAIL=""
VULNSCOUT_DOCUMENT_URL=""
VULNSCOUT_DEV_MODE="false"
CONTAINER_IMAGE="docker.io/sflinux/vulnscout:latest"
VULNSCOUT_HTTP_PROXY=""
VULNSCOUT_HTTPS_PROXY=""
VULNSCOUT_NO_PROXY="localhost,127.0.0.1"
VULNSCOUT_CVE_EXCLUDE_PATCHED="false"
VULNSCOUT_SKIP_GRYPE_SCAN="false"
VULNSCOUT_DETACH_MODE="false"
VULNSCOUT_STOP_MODE="false"
VULNSCOUT_BUILD_LOCAL="false"
VULNSCOUT_DB_URI=""
COMPOSE_PROVIDER=""
YAML_REQUIRES_UPDATE="false"
VULNSCOUT_VARIANT_NAME="default"

# Build version string
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
GIT_DESCRIBE=$(git -C "$SCRIPT_DIR" describe --tags --always 2>/dev/null || echo "")
GIT_HASH=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null || echo "")

if [ -n "$GIT_HASH" ]; then
	VULNSCOUT_VERSION="${GIT_DESCRIBE:-g${GIT_HASH:0:8}}"
elif [ -f "$SCRIPT_DIR/frontend/package.json" ]; then
	VULNSCOUT_VERSION=$(grep '"version":' "$SCRIPT_DIR/frontend/package.json" | head -n 1 | sed -E 's/.*"version": "([^"]+)".*/\1/')
fi
VULNSCOUT_TEMPLATE=""

# If no arguments are provided, show help and exit
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      require_value "$1" "${2:-}"
      VULNSCOUT_ENTRY_NAME="$2"
      shift 2
    ;;
    --workdir_path)
      require_directory "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_PATH="$2/.vulnscout"
      shift 2
      ;;
    --nvd-api-key)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_NVD_API_KEY="$2"
      shift 2
      ;;
    --fail_condition)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_FAIL_CONDITION="$2"
      shift 2
      ;;
    --report-template)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_TEMPLATE="$2"
      shift 2
      ;;
    --variant)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_VARIANT_NAME="$2"
      shift 2
      ;;
    --spdx)
      require_file "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_SPDX_PATH="$(readlink -f "$2")"
      shift 2
      ;;
    --openvex)
      require_file "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_OPENVEX_PATH="$(readlink -f "$2")"
      shift 2
      ;;
    --cdx)
      require_directory "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_CDX_PATH="$(readlink -f "$2")"
      shift 2
      ;;
    --cve-check)
      require_file "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_CVE_PATH="$(readlink -f "$2")"
      shift 2
      ;;
    --product_name)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_PRODUCT_NAME="$2"
      shift 2
      ;;
    --product_version)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_PRODUCT_VERSION="$2"
      shift 2
      ;;
    --company_name)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_COMPANY_NAME="$2"
      shift 2
      ;;
    --contact_email)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_CONTACT_EMAIL="$2"
      shift 2
      ;;
    --document_url)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_DOCUMENT_URL="$2"
      shift 2
      ;;
    --http-proxy)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_HTTP_PROXY="$2"
      shift 2
      ;;
    --https-proxy)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_HTTPS_PROXY="$2"
      shift 2
      ;;
    --no-proxy)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_NO_PROXY="$2"
      shift 2
      ;;
    --no_webui)
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_INTERACTIVE_MODE="false"
      shift
      ;;
    --db-uri)
      require_value "$1" "${2:-}"
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_DB_URI="$2"
      shift 2
      ;;
    --skip-grype-scan)
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_SKIP_GRYPE_SCAN="true"
      shift
      ;;
    --cve-check-exclude-patched)
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_CVE_EXCLUDE_PATCHED="true"
      shift
      ;;
    --ignore-parsing-errors)
      YAML_REQUIRES_UPDATE="true"
      VULNSCOUT_IGNORE_PARSING_ERRORS="true"
      shift
      ;;
    --build)
      VULNSCOUT_BUILD_LOCAL="true"
      shift
      ;;
    --dev)
      VULNSCOUT_DEV_MODE="true"
      shift
      ;;
    -d|--detach)
      VULNSCOUT_DETACH_MODE="true"
      shift
      ;;
    --stop)
      VULNSCOUT_STOP_MODE="true"
      shift
      ;;
    --help|-h)
      show_help
      exit 0
      ;;
    *)
      echo "Error: Unknown argument '$1'"
      show_help
      exit 1
      ;;
  esac
done

# If template is specified, add it to GENERATE_DOCUMENTS
if [ -n "$VULNSCOUT_TEMPLATE" ]; then
  VULNSCOUT_GENERATE_DOCUMENTS="$VULNSCOUT_GENERATE_DOCUMENTS,$VULNSCOUT_TEMPLATE"
fi

# Create paths and yaml file variable
VULNSCOUT_COMBINED_PATH="$VULNSCOUT_PATH/$VULNSCOUT_ENTRY_NAME"
YAML_FILE="$VULNSCOUT_COMBINED_PATH/docker-$VULNSCOUT_ENTRY_NAME.yml"

check_compose_provider_command() {
    if command -v podman &> /dev/null && command -v podman-compose &> /dev/null; then
        COMPOSE_PROVIDER="podman-compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_PROVIDER="docker-compose"
    elif command -v docker &> /dev/null && docker compose version &> /dev/null; then
        COMPOSE_PROVIDER="docker compose"
    else
        echo "Error: \"docker compose\" or \"docker-compose\" is not installed or not in PATH."
        exit 1
    fi
    echo "Docker Compose command found: $COMPOSE_PROVIDER"
}

create_yaml_file(){

    if [ -z "$VULNSCOUT_ENTRY_NAME" ]; then
        echo "Error: --name argument is required."
        exit 1
    fi

    if [ ! -d "$VULNSCOUT_PATH/$VULNSCOUT_ENTRY_NAME" ]; then
        echo "Creating: Directory '$VULNSCOUT_PATH/$VULNSCOUT_ENTRY_NAME'"
        mkdir -p "$VULNSCOUT_PATH/$VULNSCOUT_ENTRY_NAME"
    fi

    if [ ! -f "$YAML_FILE" ]; then
        touch "$YAML_FILE"
    fi

    # Add Header section
    cat > "$YAML_FILE" <<EOF
services:
  vulnscout:
    image: $CONTAINER_IMAGE
    container_name: vulnscout
    restart: "no"
    ports:
      - "7275:7275"
    volumes:
EOF

    # Add Volumes section
    if [ -n "$VULNSCOUT_CVE_PATH" ]; then
        echo "      - $VULNSCOUT_CVE_PATH:/scan/inputs/yocto_cve_check/$(basename -- "$VULNSCOUT_CVE_PATH"):ro,Z" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_SPDX_PATH" ]; then
        echo "      - $VULNSCOUT_SPDX_PATH:/scan/inputs/spdx/$(basename -- "$VULNSCOUT_SPDX_PATH"):ro,Z" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_CDX_PATH" ]; then
        echo "      - $VULNSCOUT_CDX_PATH:/scan/inputs/cdx/$VULNSCOUT_ENTRY_NAME.cdx.json:ro,Z" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_OPENVEX_PATH" ]; then
        echo "      - $VULNSCOUT_OPENVEX_PATH:/scan/inputs/openvex/$(basename -- "$VULNSCOUT_OPENVEX_PATH"):ro,Z" >> "$YAML_FILE"
    fi
    if [ "$VULNSCOUT_DEV_MODE" = "true" ]; then
        echo "      - $( dirname -- "$( readlink -f -- "$0"; )"; )/src:/scan/src:Z" >> "$YAML_FILE"
        echo "      - $( dirname -- "$( readlink -f -- "$0"; )"; )/migrations:/scan/src/migrations:Z" >> "$YAML_FILE"
    fi
    echo "      - $VULNSCOUT_COMBINED_PATH/output:/scan/outputs:Z" >> "$YAML_FILE"
    echo "      - $VULNSCOUT_PATH/cache:/cache/vulnscout:Z" >> "$YAML_FILE"
    # Mount templates directory if it exists
    if [ -d "$VULNSCOUT_PATH/templates" ]; then
        echo "      - $VULNSCOUT_PATH/templates:/scan/templates:ro,Z" >> "$YAML_FILE"
    fi

    # Add Environment Variables section
    cat >> "$YAML_FILE" <<EOF
    environment:
      - FLASK_RUN_PORT=$VULNSCOUT_FLASK_RUN_PORT
      - FLASK_RUN_HOST=$VULNSCOUT_FLASK_RUN_HOST
      - IGNORE_PARSING_ERRORS=$VULNSCOUT_IGNORE_PARSING_ERRORS
      - GENERATE_DOCUMENTS=$VULNSCOUT_GENERATE_DOCUMENTS
      - VERBOSE_MODE=$VULNSCOUT_VERBOSE_MODE
      - VULNSCOUT_VERSION=$VULNSCOUT_VERSION
      - DEV_MODE=$VULNSCOUT_DEV_MODE
      - VARIANT_NAME=$VULNSCOUT_VARIANT_NAME
EOF

    if [ -n "$(id -u)" ] && [ -n "$(id -g)" ]; then
        echo "      - USER_UID=$(id -u)" >> "$YAML_FILE"
        echo "      - USER_GID=$(id -g)" >> "$YAML_FILE"
    fi

    if [ -n "$VULNSCOUT_FAIL_CONDITION" ]; then
        echo "      - INTERACTIVE_MODE=false" >> "$YAML_FILE"
        echo "      - FAIL_CONDITION=$VULNSCOUT_FAIL_CONDITION" >> "$YAML_FILE"
    elif [ "$VULNSCOUT_INTERACTIVE_MODE" = "false" ]; then
        echo "      - INTERACTIVE_MODE=false" >> "$YAML_FILE"
    else
        echo "      - INTERACTIVE_MODE=true" >> "$YAML_FILE"
    fi

    if [ -n "$VULNSCOUT_PRODUCT_NAME" ]; then
        echo "      - PRODUCT_NAME=$VULNSCOUT_PRODUCT_NAME" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_ENTRY_NAME" ]; then
      echo "      - PROJECT_NAME=$VULNSCOUT_ENTRY_NAME" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_PRODUCT_VERSION" ]; then
        echo "      - PRODUCT_VERSION=$VULNSCOUT_PRODUCT_VERSION" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_COMPANY_NAME" ]; then
        echo "      - COMPANY_NAME=$VULNSCOUT_COMPANY_NAME" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_CONTACT_EMAIL" ]; then
        echo "      - CONTACT_EMAIL=$VULNSCOUT_CONTACT_EMAIL" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_DOCUMENT_URL" ]; then
        echo "      - DOCUMENT_URL=$VULNSCOUT_DOCUMENT_URL" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_DB_URI" ]; then
        echo "      - FLASK_SQLALCHEMY_DATABASE_URI=$VULNSCOUT_DB_URI" >> "$YAML_FILE"
    fi
    if [ "$VULNSCOUT_SKIP_GRYPE_SCAN" = "true" ]; then
        echo "      - SKIP_GRYPE_SCAN=true" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_NVD_API_KEY" ]; then
        echo "      - NVD_API_KEY=$VULNSCOUT_NVD_API_KEY" >> "$YAML_FILE"
    fi
    if [ -n "$VULNSCOUT_HTTP_PROXY" ] || [ -n "$VULNSCOUT_HTTPS_PROXY" ]; then
        if [ -n "$VULNSCOUT_HTTP_PROXY" ]; then
            echo "      - HTTP_PROXY=$VULNSCOUT_HTTP_PROXY" >> "$YAML_FILE"
        fi
        if [ -n "$VULNSCOUT_HTTPS_PROXY" ]; then
            echo "      - HTTPS_PROXY=$VULNSCOUT_HTTPS_PROXY" >> "$YAML_FILE"
        fi
        echo "      - NO_PROXY=$VULNSCOUT_NO_PROXY" >> "$YAML_FILE"
    fi
    if [ "$VULNSCOUT_CVE_EXCLUDE_PATCHED" = "true" ]; then
        echo "      - CVE_CHECK_EXCLUDE_PATCHED=true" >> "$YAML_FILE"
    fi

    # Scan the provided report template for env("VAR") usage and pass those host env vars to container
    if [ -n "$VULNSCOUT_TEMPLATE" ] && [ -f "$VULNSCOUT_PATH/templates/$VULNSCOUT_TEMPLATE" ]; then
        # Extract all env("...") and env('...') variable names from the template
        template_env_vars=$(grep -hoE 'env\s*\(\s*["\x27]([^"\x27]+)["\x27]' "$VULNSCOUT_PATH/templates/$VULNSCOUT_TEMPLATE" 2>/dev/null | \
            sed -E "s/env\s*\(\s*[\"']([^\"']+)[\"']/\1/" | \
            sort -u || true)
        
        for var_name in $template_env_vars; do
            # Get the value from host environment
            var_value="${!var_name:-}"
            if [ -n "$var_value" ]; then
                echo "      - VULNSCOUT_TPL_${var_name}=${var_value}" >> "$YAML_FILE"
            fi
        done
    fi

    echo "Vulnscout Succeed: Docker Compose file set at $YAML_FILE"
}

# Function to set up frontend - Only required for development
setup_devtools() {
  local is_detached=$1

  # Check if npm is installed
  if ! command -v npm &> /dev/null; then
    echo "Error: npm is not installed or not in PATH."
    exit 1
  fi

  # Create the .env file in frontend if it doesn't exist
  if [ ! -f frontend/.env ]; then
    echo 'VITE_API_URL="http://localhost:7275"' > frontend/.env
  fi

  # Check if node_modules exists in frontend; if not, run npm install
  if [ ! -d frontend/node_modules ]; then
    echo "node_modules not found. Running npm install first..."
    (cd frontend && npm install)
  fi

  # Start frontend dev server from within the frontend folder
  echo "Starting frontend in development mode..."
  (cd frontend && npm run dev) &
  npm_pid=$!
  echo "Frontend dev server started (PID $npm_pid)"

  # Store PID for later cleanup
  echo "$npm_pid" > .vulnscout-npm.pid

  if [ "$is_detached" = "false" ]; then
    # Function to cleanup background process on exit (Ctrl+C)
    cleanup() {
        echo -e "\n Stopping frontend dev server (PID $npm_pid)..."
        kill -- -$(ps -o pgid= $npm_pid | grep -o '[0-9]*') 2>/dev/null
        wait $npm_pid 2>/dev/null
        rm -f .vulnscout-npm.pid
        exit 0
    }
    trap cleanup SIGINT SIGTERM EXIT
  else
    echo "Frontend dev server running in detached mode. Use './vulnscout.sh --stop' to stop it."
  fi
}

start_vulnscout(){
    # Detect container engine
    if [[ "$COMPOSE_PROVIDER" = "podman-compose" ]]; then
        CONTAINER_ENGINE="podman"
    else
        CONTAINER_ENGINE="docker"
    fi

    # Build or pull the container image
    if [ "$VULNSCOUT_BUILD_LOCAL" = "true" ]; then
        echo "Building Docker image locally from $SCRIPT_DIR ..."
        $CONTAINER_ENGINE build -t "$CONTAINER_IMAGE" "$SCRIPT_DIR"
    else
        $CONTAINER_ENGINE pull $CONTAINER_IMAGE
    fi

    # Close any existing container processes
    $CONTAINER_ENGINE rm -f vulnscout 2>/dev/null || true

    # Start docker services
    if [ "$VULNSCOUT_DETACH_MODE" = "true" ]; then
        $COMPOSE_PROVIDER -f "$YAML_FILE" up -d
        if [ "$VULNSCOUT_DEV_MODE" = "true" ]; then
            echo "Frontend dev server is available at http://localhost:5173"
            echo "Backend dev server is available at http://localhost:7275"
        else
            echo "VulnScout is available at http://localhost:7275"
        fi
        return 0
    fi
    
    $COMPOSE_PROVIDER -f "$YAML_FILE" up

    # Retrieve container exit code directly from Docker
    docker_exit_code=$($CONTAINER_ENGINE inspect vulnscout --format '{{.State.ExitCode}}' 2>/dev/null || echo 1)

    # Retrieve container logs
    docker_result=$($CONTAINER_ENGINE logs vulnscout 2>/dev/null || echo "")

    if [ "$docker_exit_code" -eq 2 ]; then
        echo "---------------- Vulnscout triggered fail condition ----------------"
        echo "--- Vulnscout exited with code 2 with fail condition: $VULNSCOUT_FAIL_CONDITION ---"
        exit 2
    else
        echo "---------------- Vulnscout scanning success ----------------"
        if [ -n "$VULNSCOUT_FAIL_CONDITION" ]; then
            echo "---------- Condition set : $VULNSCOUT_FAIL_CONDITION ----------"
        fi
        echo "--- Vulnscout has generated multiple files here : $VULNSCOUT_COMBINED_PATH/output ---"
    fi

}

if [ "$VULNSCOUT_BUILD_LOCAL" = "true" ] && [ "$VULNSCOUT_DEV_MODE" != "true" ]; then
    echo "Error: --build requires --dev mode."
    exit 1
fi

check_compose_provider_command

# Handle stop mode
if [ "$VULNSCOUT_STOP_MODE" = "true" ]; then
  echo "Stopping running VulnScout..."
  
  # Stop frontend dev server if running
  if [ -f .vulnscout-npm.pid ]; then
    npm_pid=$(cat .vulnscout-npm.pid)
    if ps -p "$npm_pid" > /dev/null 2>&1; then
      echo "Stopping frontend dev server (PID $npm_pid)..."
      kill -- -$(ps -o pgid= "$npm_pid" | grep -o '[0-9]*') 2>/dev/null || kill "$npm_pid" 2>/dev/null || true
    fi
    rm -f .vulnscout-npm.pid
  fi
  
  # Detect container engine
  if [[ "$COMPOSE_PROVIDER" = "podman-compose" ]]; then
    CONTAINER_ENGINE="podman"
  else
    CONTAINER_ENGINE="docker"
  fi
  
  $CONTAINER_ENGINE rm -f vulnscout 2>/dev/null || true
  
  echo "VulnScout stopped."
  exit 0
fi

# Reuse existing compose file when only runtime flags were provided.
# Recreate only when at least one YAML-affecting option was passed.
if [ "$YAML_REQUIRES_UPDATE" = "false" ] && [ -n "$VULNSCOUT_ENTRY_NAME" ] && [ -f "$YAML_FILE" ]; then
  echo "Reusing existing Docker Compose file: $YAML_FILE"
else
  create_yaml_file
fi

if [ "$VULNSCOUT_DEV_MODE" = "true" ]; then
  setup_devtools "$VULNSCOUT_DETACH_MODE"
fi
start_vulnscout
