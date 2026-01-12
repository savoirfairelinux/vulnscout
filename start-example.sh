#!/bin/bash

# Exit on any command failure
set -e

show_help() {
  echo "Usage: ./start-example.sh [OPTION]"
  echo ""
  echo "Options:"
  echo "  --dev         Start frontend in development mode (npm run dev) and mount volume on src/ for the backend"
  echo "  --spdx3       Use the SPDX-3 example instead of SPDX-2"
  echo "  --detach      Start docker services in detached mode"
  echo "  --stop        Stop running example"
  echo "  --help        Show this help message and exit"
  echo ""
  echo "Default mode:"
  echo "  If no option is passed, the example will be started for SPDX2."
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

  sleep 1

  # Modify the docker-compose file to mount the backend src/ directory in addition
  DOCKER_EXTRA_VOLUMES="-f .vulnscout/docker-dev-override.yml"
}

# Default settings
NPM_MODE="none"
DOCKER_COMPOSE_FILE=".vulnscout/example/docker-example.yml"
DOCKER_EXTRA_VOLUMES=""
DETACH_MODE="false"
STOP_MODE="false"

# Parse arguments
for arg in "$@"; do
  case "$arg" in
    --dev)
      NPM_MODE="dev"
      ;;
    --spdx3)
      DOCKER_COMPOSE_FILE=".vulnscout/example-spdx3/docker-example-spdx3.yml"
      ;;
    -d|--detach)
      DETACH_MODE="true"
      ;;
    --stop)
      STOP_MODE="true"
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

if [ "$STOP_MODE" == "true" ]; then
  echo "Stopping running example..."
  
  # Stop frontend dev server if running
  if [ -f .vulnscout-npm.pid ]; then
    npm_pid=$(cat .vulnscout-npm.pid)
    if ps -p "$npm_pid" > /dev/null 2>&1; then
      echo "Stopping frontend dev server (PID $npm_pid)..."
      kill -- -$(ps -o pgid= "$npm_pid" | grep -o '[0-9]*') 2>/dev/null || kill "$npm_pid" 2>/dev/null || true
    fi
    rm -f .vulnscout-npm.pid
  fi
  
  $DOCKER_COMPOSE -f "$DOCKER_COMPOSE_FILE" down 2>/dev/null || true
  docker rm -f vulnscout 2>/dev/null || true
  
  echo "Example stopped."
  exit 0
fi

if [ "$NPM_MODE" == "dev" ]; then
  setup_devtools "$DETACH_MODE"
fi

echo "Docker Compose command found: $DOCKER_COMPOSE"

# Detect container engine
if [[ "$DOCKER_COMPOSE" == "podman-compose" ]]; then
  CONTAINER_ENGINE="podman"
else
  CONTAINER_ENGINE="docker"
fi

# Update the container image if necessary
$CONTAINER_ENGINE pull docker.io/sflinux/vulnscout:latest

# Close any existing container processes
$CONTAINER_ENGINE rm -f vulnscout 2>/dev/null || true

# Start Docker services
if [ "$DETACH_MODE" == "true" ]; then
  $DOCKER_COMPOSE -f "$DOCKER_COMPOSE_FILE" $DOCKER_EXTRA_VOLUMES up -d
  if [ "$NPM_MODE" == "dev" ]; then
      echo "Frontend dev server is available at http://localhost:5173"
      echo "Backend dev server is available at http://localhost:7275"
  else
      echo "Vulnscout is available at http://localhost:7275"
  fi
else
  $DOCKER_COMPOSE -f "$DOCKER_COMPOSE_FILE" $DOCKER_EXTRA_VOLUMES up
fi