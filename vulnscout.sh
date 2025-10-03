#!/bin/bash

# Exit on any command failure
set -e

show_help() {
  echo "Usage: ./vulnscout.sh --name <project_name> [--option]"
  echo ""
  echo "Mandatory argument:"
  echo "  --name <project_name> name of the sub folder entry in .vulnscout/"
  echo ""
  echo "Extra Vulnscout configuration:"
  echo "  --workdir_path <path>   (default: current directory) Path to vulnscout installation"
  echo "  --nvd-api-key <key>   (optional) NVD API key to increase rate limits"
  echo ""
  echo "Sources configuration:"
  echo "  --sbom  <path>     path to the SPDX 2 or SPDX 3 SBOM file/archive"
  echo "  --cdx  <path>      path to the CycloneDX directory"
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
}

VULNSCOUT_PATH="$(dirname "$(readlink -f "$0")")/.vulnscout"
VULNSCOUT_SBOM_PATH=""
VULNSCOUT_CDX_PATH=""
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
        VULNSCOUT_SBOM_PATH="$2"
        shift 2
      else
        echo "Error: --sbom requires a value"
        exit 1
      fi
      ;;
    --cdx)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_CDX_PATH="$2"
        shift 2
      else
        echo "Error: --cdx requires a value"
        exit 1
      fi
      ;;
    --cve-check)
      if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
        VULNSCOUT_CVE_PATH="$2"
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
    if docker compose version &> /dev/null; then
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
    image: sflinux/vulnscout:latest
    container_name: vulnscout
    restart: "no"
    ports:
      - "7275:7275"
    volumes:
EOF

    # Add Volumes section
    if [ ! -z "$VULNSCOUT_CVE_PATH" ]; then
        echo "      - $VULNSCOUT_CVE_PATH:/scan/inputs/yocto_cve_check/$(basename -- "$VULNSCOUT_CVE_PATH"):ro" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_SBOM_PATH" ]; then
        echo "      - $VULNSCOUT_SBOM_PATH:/scan/inputs/spdx/$(basename -- "$VULNSCOUT_SBOM_PATH"):ro" >> "$YAML_FILE"
    fi
    if [ ! -z "$VULNSCOUT_CDX_PATH" ]; then
        echo "      - $VULNSCOUT_CDX_PATH:/scan/inputs/cdx/$VULNSCOUT_ENTRY_NAME.cdx.json:ro" >> "$YAML_FILE"
    fi
    echo "      - $VULNSCOUT_COMBINED_PATH/output:/scan/outputs" >> "$YAML_FILE"
    echo "      - $VULNSCOUT_PATH/cache:/cache/vulnscout" >> "$YAML_FILE"

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
    echo "Vulnscout Succeed: Docker Compose file set at $YAML_FILE"
}

start_vulnscout(){
    # Update the docker image if necessary
    docker pull sflinux/vulnscout:latest

    # Close any existing docker-compose processes
    docker rm -f vulnscout 2>/dev/null || true

    # Start docker services
    $DOCKER_COMPOSE -f "$YAML_FILE" up

    # Retrieve container exit code directly from Docker
    docker_exit_code=$(docker inspect vulnscout --format '{{.State.ExitCode}}' 2>/dev/null || echo 1)

    # Retrieve container logs
    docker_result=$(docker logs vulnscout 2>/dev/null || echo "")

    if [ "$docker_exit_code" -eq 2 ]; then
        echo "---------------- Vulnscout triggered fail condition ----------------"
        echo "--- Vulnscout exited with code 2 with fail condition: $VULNSCOUT_FAIL_CONDITION ---"
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
start_vulnscout