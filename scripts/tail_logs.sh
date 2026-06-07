#!/bin/bash
# Helper script to tail the logs of the running test container

# Ensure we are in the project root
cd "$(dirname "$0")/.." || exit

echo "📋 Tailing logs for 'mazewall' service..."
podman compose -f infra/dev/compose.yml logs -f mazewall
