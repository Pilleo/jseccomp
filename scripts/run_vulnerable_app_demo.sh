#!/usr/bin/env bash
set -e

# Curated HSL color palette tailored to a professional, premium dark-mode feel
CYAN='\033[1;36m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'

echo -e "${CYAN}=========================================================================${RESET}"
echo -e "${CYAN}                 MAZEWALL: CVE DEMO AUTOMATION SUITE                     ${RESET}"
echo -e "${CYAN}=========================================================================${RESET}"

# 1. Detect Compose CLI engine (Podman preferred, falling back to Docker)
COMPOSE_CMD=""
if command -v podman &>/dev/null; then
    COMPOSE_CMD="podman compose"
elif command -v docker &>/dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo -e "${RED}[ERROR] Neither podman nor docker CLI could be found. Please install one to run the containerized demo.${RESET}"
    exit 1
fi
echo -e "${GREEN}[INFO] Using container engine:${RESET} $COMPOSE_CMD"

# 2. Build the application bootJar
echo -e "${CYAN}[STEP 1/5] Building the Vulnerable Spring Boot Application...${RESET}"
../gradlew :demos:vulnerable-web-app:bootJar

# Create output directory on host to persist all results, SBoB files, and stack traces
mkdir -p ../demos/output

# 3. Boot up the unprotected and protected instances
echo -e "\n${CYAN}[STEP 2/5] Launching containerized environment...${RESET}"
COMPOSE_FILE="../demos/vulnerable-web-app/compose.yml"
$COMPOSE_CMD -f "$COMPOSE_FILE" down --remove-orphans &>/dev/null || true
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d --build

# Guarantee clean container teardown on exit
cleanup() {
    echo -e "\n${YELLOW}🧹 Gracefully cleaning up containers...${RESET}"
    $COMPOSE_CMD -f "$COMPOSE_FILE" down &>/dev/null || true
    echo -e "${GREEN}✅ Teardown complete. Goodbye!${RESET}"
}
trap cleanup EXIT

# 4. Wait for services to start and be fully active
echo -e "\n${CYAN}[STEP 3/5] Waiting for Spring Boot instances to initialize...${RESET}"

echo -n -e "⏳ Waiting for ${RED}Unprotected Service${RESET} (port 8082)..."
until curl -s http://localhost:8082/template &>/dev/null; do
    sleep 1.5
    echo -n "."
done
echo -e " [${GREEN}Ready${RESET}]"

echo -n -e "⏳ Waiting for ${GREEN}Protected Service${RESET} (port 8081)..."
until curl -s http://localhost:8081/template &>/dev/null; do
    sleep 1.5
    echo -n "."
done
echo -e " [${GREEN}Ready${RESET}]"

# 5. Run the 11 exploit vectors
echo -e "\n${CYAN}[STEP 4/5] Executing automated CVE exploitation suite...${RESET}"
UNPROT_JSON="../demos/output/unprotected_results.json"
PROT_JSON="../demos/output/protected_results.json"
REPORT_MD="../demos/output/report.md"

echo -e "🔥 Running exploits against ${RED}Unprotected Service${RESET}..."
python3 ../exploits/run_all.py http://localhost:8082 > "$UNPROT_JSON"

echo -e "🛡️ Running exploits against ${GREEN}Protected Service${RESET} (Mazewall Guarded)..."
python3 ../exploits/run_all.py http://localhost:8081 > "$PROT_JSON"

# 6. Generate the Markdown comparison report
echo -e "\n${CYAN}[STEP 5/5] Generating verification report...${RESET}"
python3 ../exploits/verify_results.py "$UNPROT_JSON" "$PROT_JSON" "$REPORT_MD"

# 7. Print a premium ASCII color-coded outcome table
python3 - "$UNPROT_JSON" "$PROT_JSON" "$REPORT_MD" << 'EOF'
import sys
import json

unprot_path = sys.argv[1]
prot_path = sys.argv[2]
report_path = sys.argv[3]

with open(unprot_path) as f:
    unprot = json.load(f)
with open(prot_path) as f:
    prot = json.load(f)

print('\n\033[1;36m=========================================================================\033[0m')
print('\033[1;36m                 MAZEWALL REAL-WORLD CVE DEMO RESULTS SUMMARY            \033[0m')
print('\033[1;36m=========================================================================\033[0m')
print(f'{"#":<3} | {"Attack Vector / CVE Target":<40} | {"Unprotected":<12} | {"Mazewall Protected":<12}')
print('-' * 77)
for k in sorted(unprot.keys()):
    u = unprot[k]
    p = prot[k]
    u_status = '\033[1;31mSucceeded\033[0m' if u['succeeded'] else '\033[1;32mBlocked\033[0m'
    p_status = '\033[1;31mSucceeded\033[0m' if p['succeeded'] else '\033[1;32mBlocked\033[0m'
    num = k.split('_')[0]
    print(f'{num:<3} | {u["name"]:<40} | {u_status:<21} | {p_status:<21}')
print('\033[1;36m=========================================================================\033[0m')
print(f'\033[1;32m[RESULT]\033[0m Comparative report compiled at: \033[1m{report_path}\033[0m')
EOF
