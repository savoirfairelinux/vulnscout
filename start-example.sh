#!/bin/bash

## Frontend Development Environment Setup Script

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
(cd frontend && npm run dev) &
npm_pid=$!  # Save the npm process PID
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

## Backend Development Environment Setup Script
# Close any existing docker-compose processes
docker rm -f vulnscout 2>/dev/null

# Start docker services
docker compose -f .vulnscout/example/docker-example.yml up

# When docker-compose finishes (or script ends), cleanup npm too
cleanup
