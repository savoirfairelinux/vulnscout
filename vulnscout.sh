#!/bin/bash

# VulnScout script intended to be used in projects.
# Some features include running an interactive scan, generate report, CI/CD scan, etc.
# Use `vulnscout.sh --help` for more information.
# Exit 0: everything ok
# Exit 1: execution error (missing conf, docker issue)
# Exit 2: only in ci mode, used when report failed to met user conditions
#
# Note: Keep this file indented with tabs, not spaces, or you break the help message.
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail # Enable error checking

show_help() {
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
  echo "  --spdx  <path>     path to the SPDX 2 or SPDX 3 SBOM file/archive"
  echo "  --cdx  <path>      path to the CycloneDX directory"
  echo "  --openvex  <path>      path to the OpenVEX JSON file"
  echo "  --cve-check  <path>      path to the Yocto CVE check JSON file"
  echo ""
  echo "CI configuration:"
  echo "  --no_webui  Disable the web UI (default: enabled)"
  echo "  --fail_condition <condition>  Set the fail condition for the scan (e.g., cvss >= 9.0 or (cvss >= 7.0 and epss >= 50%))"
  echo ""
  echo "Optional company/product information (for report generation):"
  echo "  --product_name <name>       Product name"
  echo "  --product_version <version> Product version"
  echo "  --company_name <name>       Company name"
  echo "  --contact_email <email>     Contact email"
  echo "  --document_url <url>        Document URL"
  echo ""
  echo "Other options:"
  echo "  --help, -h        Show this help message and exit"
  echo "  --dev             Use the development version of VulnScout"
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

# If no arguments are provided, show help and exit
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_ENTRY_NAME="$2"
        shift 2
      else
        echo "Error: --name requires a value"
        exit 1
      fi
      ;;
    --workdir_path)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_PATH="$2/.vulnscout"
        shift 2
      else
        echo "Error: --workdir_path requires a value"
        exit 1
      fi
      ;;
    --nvd-api-key)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_NVD_API_KEY="$2"
        shift 2
      else
        echo "Error: --nvd-api-key requires a value"
        exit 1
      fi
      ;;
    --no_webui)
      VULNSCOUT_INTERACTIVE_MODE="false"
      shift
      ;;
    --fail_condition)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_FAIL_CONDITION="$2"
        shift 2
      else
        echo "Error: --fail_condition requires a value"
        exit 1
      fi
      ;;
    --sbom)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_SPDX_PATH="$(dirname "$(readlink -f "$2")")"
        shift 2
      else
        echo "Error: --sbom requires a value"
        exit 1
      fi
      ;;
    --openvex)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_OPENVEX_PATH="$(dirname "$(readlink -f "$2")")"
        shift 2
      else
        echo "Error: --openvex requires a value"
        exit 1
      fi
      ;;
    --cdx)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_CDX_PATH="$(dirname "$(readlink -f "$2")")"
        shift 2
      else
        echo "Error: --cdx requires a value"
        exit 1
      fi
      ;;
    --cve-check)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_CVE_PATH="$(dirname "$(readlink -f "$2")")"
        shift 2
      else
        echo "Error: --cve-check requires a value"
        exit 1
      fi
      ;;
    --vulnscout_path)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_PATH="$2"
        shift 2
      else
        echo "Error: --vulnscout_path requires a value"
        exit 1
      fi
      ;;
    --product_name)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_PRODUCT_NAME="$2"
        shift 2
      else
        echo "Error: --product_name requires a value"
        exit 1
      fi
      ;;
    --product_version)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_PRODUCT_VERSION="$2"
        shift 2
      else
        echo "Error: --product_version requires a value"
        exit 1
      fi
      ;;
    --company_name)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_COMPANY_NAME="$2"
        shift 2
      else
        echo "Error: --company_name requires a value"
        exit 1
      fi
      ;;
    --contact_email)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_CONTACT_EMAIL="$2"
        shift 2
      else
        echo "Error: --contact_email requires a value"
        exit 1
      fi
      ;;
    --document_url)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_DOCUMENT_URL="$2"
        shift 2
      else
        echo "Error: --document_url requires a value"
        exit 1
      fi
      ;;
    --dev)
      VULNSCOUT_DEV_MODE="true"
      shift
      ;;
    --http-proxy)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_HTTP_PROXY="$2"
        shift 2
      else
        echo "Error: --http-proxy requires a value"
        exit 1
      fi
      ;;
    --https-proxy)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_HTTPS_PROXY="$2"
        shift 2
      else
        echo "Error: --https-proxy requires a value"
        exit 1
      fi
      ;;
    --no-proxy)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_NO_PROXY="$2"
        shift 2
      else
        echo "Error: --no-proxy requires a value"
        exit 1
      fi
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


# Create paths and yaml file variable
VULNSCOUT_COMBINED_PATH="$VULNSCOUT_PATH/$VULNSCOUT_ENTRY_NAME"
YAML_FILE="$VULNSCOUT_COMBINED_PATH/docker-$VULNSCOUT_ENTRY_NAME.yml"

check_docker_compose_command() {
    if command -v podman-compose &> /dev/null; then
        DOCKER_COMPOSE="podman-compose"
    elif docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    elif command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
    else
        echo "Error: \"docker compose\" or \"docker-compose\" is not installed or not in PATH."
        exit 1
    fi
    echo "Docker Compose command found: $DOCKER_COMPOSE"
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
    if [ ! -z "$VULNSCOUT_CVE_PATH" ]; then
        echo "      - $VULNSCOUT_CVE_PATH:/scan/inputs/yocto_cve_check/$(basename -- "$VULNSCOUT_CVE_PATH"):ro,Z" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_SPDX_PATH" ]; then
        echo "      - $VULNSCOUT_SPDX_PATH:/scan/inputs/spdx/$(basename -- "$VULNSCOUT_SPDX_PATH"):ro,Z" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_CDX_PATH" ]; then
        echo "      - $VULNSCOUT_CDX_PATH:/scan/inputs/cdx/$VULNSCOUT_ENTRY_NAME.cdx.json:ro,Z" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_OPENVEX_PATH" ]; then
        echo "      - $VULNSCOUT_OPENVEX_PATH:/scan/inputs/openvex/$(basename -- "$VULNSCOUT_OPENVEX_PATH"):ro,Z" >> "$YAML_FILE"
    fi
    if [ "$VULNSCOUT_DEV_MODE" == "true" ]; then
        echo "      - $( dirname -- "$( readlink -f -- "$0"; )"; )/src:/scan/src:Z" >> "$YAML_FILE"
    fi
    echo "      - $VULNSCOUT_COMBINED_PATH/output:/scan/outputs:Z" >> "$YAML_FILE"
    echo "      - $VULNSCOUT_PATH/cache:/cache/vulnscout:Z" >> "$YAML_FILE"

    # Add Environment Variables section
    cat >> "$YAML_FILE" <<EOF
    environment:
      - FLASK_RUN_PORT=$VULNSCOUT_FLASK_RUN_PORT
      - FLASK_RUN_HOST=$VULNSCOUT_FLASK_RUN_HOST
      - IGNORE_PARSING_ERRORS=$VULNSCOUT_IGNORE_PARSING_ERRORS
      - GENERATE_DOCUMENTS=$VULNSCOUT_GENERATE_DOCUMENTS
      - VERBOSE_MODE=$VULNSCOUT_VERBOSE_MODE
EOF

    if [ ! -z "$VULNSCOUT_FAIL_CONDITION" ]; then
        echo "      - INTERACTIVE_MODE=false" >> "$YAML_FILE"
        echo "      - FAIL_CONDITION=$VULNSCOUT_FAIL_CONDITION" >> "$YAML_FILE"
    elif [ "$VULNSCOUT_INTERACTIVE_MODE" = "false" ]; then
        echo "      - INTERACTIVE_MODE=false" >> "$YAML_FILE"
    else
        echo "      - INTERACTIVE_MODE=true" >> "$YAML_FILE"
    fi

    if [ ! -z "$VULNSCOUT_PRODUCT_NAME" ]; then
        echo "      - PRODUCT_NAME=$VULNSCOUT_PRODUCT_NAME" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_PRODUCT_VERSION" ]; then
        echo "      - PRODUCT_VERSION=$VULNSCOUT_PRODUCT_VERSION" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_COMPANY_NAME" ]; then
        echo "      - COMPANY_NAME=$VULNSCOUT_COMPANY_NAME" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_CONTACT_EMAIL" ]; then
        echo "      - CONTACT_EMAIL=$VULNSCOUT_CONTACT_EMAIL" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_DOCUMENT_URL" ]; then
        echo "      - DOCUMENT_URL=$VULNSCOUT_DOCUMENT_URL" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_NVD_API_KEY" ]; then
        echo "      - NVD_API_KEY=$VULNSCOUT_NVD_API_KEY" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_HTTP_PROXY" ] || [ ! -z "$VULNSCOUT_HTTPS_PROXY" ]; then
        if [ ! -z "$VULNSCOUT_HTTP_PROXY" ]; then
            echo "      - HTTP_PROXY=$VULNSCOUT_HTTP_PROXY" >> "$YAML_FILE"
        fi
        if [ ! -z "$VULNSCOUT_HTTPS_PROXY" ]; then
            echo "      - HTTPS_PROXY=$VULNSCOUT_HTTPS_PROXY" >> "$YAML_FILE"
        fi
        echo "      - NO_PROXY=$VULNSCOUT_NO_PROXY" >> "$YAML_FILE"
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

  if [ "$is_detached" == "false" ]; then
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
    echo "Frontend dev server running in detached mode. Use './start-example.sh --stop' to stop it."
  fi
}

start_vulnscout(){
    # Detect container engine
    if [[ "$DOCKER_COMPOSE" == "podman-compose" ]]; then
        CONTAINER_ENGINE="podman"
    else
        CONTAINER_ENGINE="docker"
    fi

    # Update the container image if necessary
    $CONTAINER_ENGINE pull $CONTAINER_IMAGE

    # Close any existing container processes
    $CONTAINER_ENGINE rm -f vulnscout 2>/dev/null || true

    # Start docker services
    $DOCKER_COMPOSE -f "$YAML_FILE" up

    # Retrieve container exit code directly from Docker
    docker_exit_code=$(docker inspect vulnscout --format '{{.State.ExitCode}}' 2>/dev/null || echo 1)

    # Retrieve container logs
    docker_result=$(docker logs vulnscout 2>/dev/null || echo "")

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

check_docker_compose_command
create_yaml_file
if [ "$VULNSCOUT_DEV_MODE" == "true" ]; then
  setup_devtools "false"
fi
start_vulnscout