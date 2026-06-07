#!/bin/bash
# Helper script to parse Jacoco XML reports and verify coverage thresholds

# Ensure we are in the project root
cd "$(dirname "$0")/.." || exit

# Run Jacoco report generation first if it doesn't exist or to ensure it's fresh
# Note: This runs inside podman to ensure tests have run in the correct environment
echo "📊 Generating Jacoco reports in container..."
podman compose -f infra/dev/compose.yml exec mazewall ./gradlew jacocoTestReport

echo ""
echo "🧐 Verifying coverage thresholds..."
echo "--------------------------------------------------"

# Function to extract coverage for a class/package from XML
get_coverage() {
    local xml_file=$1
    local type=$2
    local name=$3

    # Use xmllint to extract the COVERED and MISSED instructions for the target
    # This is a bit complex due to Jacoco XML structure
    local stats=$(xmllint --xpath "//${type}[@name='$name']/counter[@type='INSTRUCTION']" "$xml_file" 2>/dev/null)

    if [ -z "$stats" ]; then
        echo "N/A"
        return
    fi

    local missed=$(echo "$stats" | sed -E 's/.*missed="([0-9]+)".*/\1/')
    local covered=$(echo "$stats" | sed -E 's/.*covered="([0-9]+)".*/\1/')
    local total=$((missed + covered))

    if [ "$total" -eq 0 ]; then
        echo "0.00"
    else
        echo "scale=2; $covered * 100 / $total" | bc
    fi
}

check_threshold() {
    local label=$1
    local current=$2
    local min=$3

    if [ "$current" == "N/A" ]; then
        echo "❓ $label: Could not find data"
        return
    fi

    if (( $(echo "$current >= $min" | bc -l) )); then
        echo "✅ $label: $current% (Min: $min%)"
    else
        echo "❌ $label: $current% (Min: $min%) - UNDER THRESHOLD!"
    fi
}

# --- Enforcer ---
ENFORCER_XML="enforcer/build/reports/jacoco/test/jacocoTestReport.xml"
if [ -f "$ENFORCER_XML" ]; then
    echo "Module: :enforcer"
    check_threshold "Landlock" "$(get_coverage "$ENFORCER_XML" "class" "io/mazewall/landlock/Landlock")" "65.0"
    check_threshold "LinuxNative" "$(get_coverage "$ENFORCER_XML" "class" "io/mazewall/LinuxNative")" "78.0"
    # Core classes (Policy as proxy)
    check_threshold "Core (Policy)" "$(get_coverage "$ENFORCER_XML" "class" "io/mazewall/Policy")" "80.0"
else
    echo "❌ Enforcer report missing: $ENFORCER_XML"
fi

echo ""

# --- Profiler ---
PROFILER_XML="profiler/build/reports/jacoco/test/jacocoTestReport.xml"
if [ -f "$PROFILER_XML" ]; then
    echo "Module: :profiler"
    check_threshold "Profiler" "$(get_coverage "$PROFILER_XML" "class" "io/mazewall/profiler/Profiler")" "60.0"
else
    echo "❌ Profiler report missing: $PROFILER_XML"
fi

echo "--------------------------------------------------"
