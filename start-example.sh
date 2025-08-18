#!/bin/bash

# Exit on any command failure
set -e

show_help() {
  echo "Usage: ./start-example.sh [--dev] [--spdx3] [--help]"
  echo ""
  echo "Options:"
  echo "  --dev         Start frontend in development mode (npm run dev) and mount volume on src/ for the backend"
  echo "  --spdx3       Use the SPDX-3 example instead of SPDX-2"
  echo "  --help        Show this help message and exit"
  echo ""
  echo "Default mode:"
  echo "  If no option is passed, the example will be started for SPDX2."
}

# Function to set up frontend - Only required for development
setup_devtools() {

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

  # Function to cleanup background process on exit (Ctrl+C)
  cleanup() {
      echo -e "\n Stopping frontend dev server (PID $npm_pid)..."
      kill -- -$(ps -o pgid= $npm_pid | grep -o '[0-9]*') 2>/dev/null
      wait $npm_pid 2>/dev/null
      exit 0
  }
  trap cleanup SIGINT SIGTERM EXIT

  sleep 1

  # Modify the docker-compose file to mount the backend src/ directory in addition
  DOCKER_EXTRA_VOLUMES="-f .vulnscout/docker-dev-override.yml"
}

# Default settings
NPM_MODE="none"
DOCKER_COMPOSE_FILE=".vulnscout/example/docker-example.yml"
DOCKER_EXTRA_VOLUMES=""

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --dev)
      NPM_MODE="dev"
      ;;
    --spdx3)
      DOCKER_COMPOSE_FILE=".vulnscout/example-spdx3/docker-example-spdx3.yml"
      ;;
    --help|-h)
      show_help
      exit 0
      ;;
    *)
      echo "Error: Unknown argument '$arg'"
      show_help
      exit 1
      ;;
  esac
done

## Check for required docker compose command
if ! command -v docker &> /dev/null; then
  echo "Error: Docker is not installed or not in PATH."
  exit 1
fi

if [ "$NPM_MODE" == "dev" ]; then
  setup_devtools
fi

if docker compose version &> /dev/null; then
  DOCKER_COMPOSE="docker compose"
elif command -v docker-compose &> /dev/null; then
  DOCKER_COMPOSE="docker-compose"
else
  echo "Error: \"docker compose\" or \"docker-compose\" is not installed or not in PATH."
  exit 1
fi

echo "Docker Compose command found: $DOCKER_COMPOSE"

## Backend Development Environment Setup Script

# Update the docker image if necessary
docker pull sflinux/vulnscout:latest

# Close any existing docker-compose processes
docker rm -f vulnscout 2>/dev/null || true

# Start docker services
$DOCKER_COMPOSE -f "$DOCKER_COMPOSE_FILE" $DOCKER_EXTRA_VOLUMES up