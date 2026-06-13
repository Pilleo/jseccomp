#!/bin/bash
# Helper script to run tests inside the Podman container environment

# Ensure we are in the project root
cd "$(dirname "$0")/.." || exit

echo "🚀 Starting containerized integration tests..."
# We use --info to ensure we see the security violation logs and seccomp transitions
./scripts/run_containerized_tests.sh test --info "$@"

# Tip: you can pass gradle arguments like: ./scripts/run_tests.sh --tests "*.PolicyTest"
