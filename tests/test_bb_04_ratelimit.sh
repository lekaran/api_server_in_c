#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 04 - RATE LIMIT BYPASS
# 14 techniques différentes de bypass du rate limiting
# Test d'efficacité et de couverture des contrôles
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/bb_04_ratelimit_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 04 - RATE LIMIT BYPASS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Fonction qui envoie N requêtes rapides avec un header IP spécifique
# et vérifie si le rate limit s'applique
test_bypass() {
    local label="$1"
    local header_name="$2"
    local header_value="$3"
    local N=8
    local blocked=0
    local passed=0

    for i in $(seq 1 $N); do
        if [ -n "$header_name" ]; then
            RESP=$(curl -s -o /tmp/rl_body.txt -w "%{http_code}" \
                -X POST "$BASE_URL/login" \
                -H "Content-Type: application/json" \
                -H "$header_name: $header_value" \
                -d '{"username":"rl_test","password":"Test1234!"}' 2>/dev/null)
        else
            RESP=$(curl -s -o /tmp/rl_body.txt -w "%{http_code}" \
                -X POST "$BASE_URL/login" \
                -H "Content-Type: application/json" \
                -d '{"username":"rl_test","password":"Test1234!"}' 2>/dev/null)
        fi
        BODY=$(cat /tmp/rl_body.txt 2>/dev/null)
        if echo "$BODY" | grep -qi "rate_limit\|too_many\|retry_after"; then
            blocked=$((blocked+1))
        else
            passed=$((passed+1))
        fi
    done

    if [ "$blocked" -eq 0 ]; then
        log_vuln "[RL-BYPASS] '$label' ($header_name: $header_value) → BYPASS RÉUSSI! $passed/$N requêtes passées sans rate limit"
    elif [ "$blocked" -lt "$N" ]; then
        log_vuln "[RL-PARTIAL] '$label' → BYPASS PARTIEL: $passed passées, $blocked bloquées"
    else
        log_pass "[RL-OK] '$label' → Rate limit actif ($blocked/$N bloquées)"
    fi
    sleep 1
}

# ============================================================
# 1. SANS HEADER (baseline - confirm rate limit actif)
# ============================================================
echo "--- [1] BASELINE - sans header IP (vrai 127.0.0.1) ---" | tee -a "$RESULTS_FILE"
test_bypass "no-header" "" ""

echo "" | tee -a "$RESULTS_FILE"
echo "--- [2] BYPASS VIA HEADERS IP ALTERNATIFS ---" | tee -a "$RESULTS_FILE"
sleep 31  # Reset rate limit baseline

# ============================================================
# 2. HEADERS DE BYPASS CLASSIQUES
# ============================================================
declare -A BYPASS_HEADERS=(
    ["X-Forwarded-For"]="192.168.100.1"
    ["X-Real-IP"]="192.168.100.2"
    ["X-Originating-IP"]="192.168.100.3"
    ["X-Remote-IP"]="192.168.100.4"
    ["X-Remote-Addr"]="192.168.100.5"
    ["X-Client-IP"]="192.168.100.6"
    ["X-Host"]="192.168.100.7"
    ["Forwarded"]="for=192.168.100.8"
    ["True-Client-IP"]="192.168.100.9"
    ["CF-Connecting-IP"]="192.168.100.10"
    ["X-Cluster-Client-IP"]="192.168.100.11"
    ["X-Forwarded-Host"]="192.168.100.12"
    ["X-ProxyUser-IP"]="192.168.100.13"
    ["Via"]="1.1 192.168.100.14"
)
for HEADER in "${!BYPASS_HEADERS[@]}"; do
    test_bypass "$HEADER" "$HEADER" "${BYPASS_HEADERS[$HEADER]}"
    sleep 31  # Reset entre chaque test
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. X-Forwarded-For avec valeurs multiples
# ============================================================
echo "--- [3] X-FORWARDED-FOR MULTI-VALEURS ---" | tee -a "$RESULTS_FILE"
MULTI_XFF=(
    "192.168.200.1, 10.0.0.1"
    "192.168.200.2, 10.0.0.1, 172.16.0.1"
    "127.0.0.1, 192.168.200.3"
    "::1"
    "0.0.0.0"
    "255.255.255.255"
    "localhost"
    "192.168.200.4"
    "192.168.200.5\r\nX-Injected: evil"
)
for VAL in "${MULTI_XFF="${MULTI_XFF[@]}""; do
    test_bypass "XFF-multi" "X-Forwarded-For" "$VAL"
    sleep 31
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. RATE LIMIT PAR ENDPOINT (même IP, endpoints différents)
# ============================================================
echo "--- [4] RATE LIMIT PAR ENDPOINT ---" | tee -a "$RESULTS_FILE"
log_info "Test: le rate limit sur /login bloque-t-il aussi /register?"
for i in $(seq 1 5); do
    curl -s -o /dev/null -w "" -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"rl_test2","password":"Test1234!"}' 2>/dev/null
done
sleep 0.5
RESP_REG=$(curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"rl_reg_test","first_name":"A","last_name":"B","password":"Test1234!"}' 2>/dev/null)
echo "  /register après saturation /login: $RESP_REG" | tee -a "$RESULTS_FILE"
if echo "$RESP_REG" | grep -qi "rate_limit\|too_many"; then
    log_pass "[RL-ENDPOINT] Rate limit global par IP (touche /register aussi)"
else
    log_info "[RL-ENDPOINT] Rate limit par endpoint (pas de cross-endpoint blocking)"
fi

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. RATE LIMIT WINDOW - EDGE CASE (juste avant expiration)
# ============================================================
echo "--- [5] WINDOW EDGE CASE ---" | tee -a "$RESULTS_FILE"
sleep 31
log_info "Saturation du rate limit..."
for i in $(seq 1 10); do
    curl -s -o /dev/null -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"edge_test","password":"Test1234!"}' 2>/dev/null
done
log_info "Attente 29 secondes (juste avant reset)..."
sleep 29
RESP_EDGE=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"edge_test","password":"Test1234!"}' 2>/dev/null)
echo "  À 29s: $RESP_EDGE" | tee -a "$RESULTS_FILE"
sleep 3
RESP_EDGE2=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"edge_test","password":"Test1234!"}' 2>/dev/null)
echo "  À 32s: $RESP_EDGE2" | tee -a "$RESULTS_FILE"

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. RATE LIMIT - BYPASS PAR SLOWLORIS (connexion lente)
# ============================================================
echo "--- [6] RATE LIMIT ET CONNEXION LENTE ---" | tee -a "$RESULTS_FILE"
sleep 31
log_info "Envoi de connexion très lente (simule un client lent)..."
# Utilise --limit-rate pour envoyer très lentement (1 byte/s)
RESP_SLOW=$(curl -s -o /tmp/rl_body.txt -w "%{http_code}" \
    --limit-rate 10 \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"slow_test","password":"Test1234!"}' 2>/dev/null)
BODY=$(cat /tmp/rl_body.txt 2>/dev/null)
echo "  Connexion lente → HTTP $RESP_SLOW | $BODY" | tee -a "$RESULTS_FILE"

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS RATE LIMIT: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
