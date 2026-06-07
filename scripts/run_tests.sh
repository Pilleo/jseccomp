#!/bin/bash
# Helper script to run tests inside the Podman container environment

# Ensure we are in the project root
cd "$(dirname "$0")/.." || exit

echo "🚀 Starting Podman compose environment..."
podman compose -f infra/dev/compose.yml up -d

echo "🧪 Running Gradle check in container..."
podman compose -f infra/dev/compose.yml exec mazewall ./gradlew check "$@"

# Tip: you can pass gradle arguments like: ./scripts/run_tests.sh --tests "*.PolicyTest"
