#!/bin/bash
# Helper script to run all linting and static analysis tools

# Ensure we are in the project root
cd "$(dirname "$0")/.." || exit

echo "🧹 Running ktlint check..."
./gradlew ktlintCheck

echo "🔍 Running Detekt analysis..."
./gradlew detekt

echo "🪲 Running SpotBugs analysis..."
./gradlew spotbugsMain

echo "✅ All linting tasks completed."
