#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 01 - RECONNAISSANCE
# Cible : http://127.0.0.1:8080
# Objectif : Mapper endpoints, méthodes HTTP, headers de
#            sécurité, formats acceptés, verbosité d'erreur
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/bb_01_recon_results.txt"
PASS=0; FAIL=0; INFO=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; INFO=$((INFO+1)); }
log_pass()  { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_sec()   { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 01 - RECONNAISSANCE" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "  Cible: $BASE_URL" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ---- HELPER ----
req() {
    local method="$1"; local path="$2"; shift 2
    curl -s -o /tmp/bb_body.txt -w "%{http_code}|%{time_total}|%{size_download}" \
        -X "$method" "$BASE_URL$path" "$@" 2>/dev/null
}

check_header() {
    local header="$1"; local response="$2"
    echo "$response" | grep -qi "^$header:" && echo "present" || echo "absent"
}

# ============================================================
# 1. DÉCOUVERTE DES MÉTHODES HTTP SUR /register
# ============================================================
echo "--- [1] MÉTHODES HTTP sur /register ---" | tee -a "$RESULTS_FILE"
for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
    RESP=$(curl -s -o /tmp/bb_body.txt -w "%{http_code}" \
        -X "$METHOD" "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -d '{"username":"probe","first_name":"A","last_name":"B","password":"Test1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/bb_body.txt 2>/dev/null)
    if [ "$METHOD" = "POST" ]; then
        log_info "POST /register → $RESP | body: $BODY"
    elif [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
        log_sec "MÉTHODE $METHOD /register retourne $RESP — méthode non attendue acceptée! body: $BODY"
    else
        log_info "  $METHOD /register → $RESP | body: $BODY"
    fi
    sleep 0.2
done

echo "" | tee -a "$RESULTS_FILE"
echo "--- [2] MÉTHODES HTTP sur /login ---" | tee -a "$RESULTS_FILE"
for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
    RESP=$(curl -s -o /tmp/bb_body.txt -w "%{http_code}" \
        -X "$METHOD" "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"probe","password":"Test1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/bb_body.txt 2>/dev/null)
    if [ "$METHOD" = "POST" ]; then
        log_info "POST /login → $RESP | body: $BODY"
    elif [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
        log_sec "MÉTHODE $METHOD /login retourne $RESP — méthode non attendue acceptée! body: $BODY"
    else
        log_info "  $METHOD /login → $RESP | body: $BODY"
    fi
    sleep 0.2
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. SCAN DE ROUTES NON DOCUMENTÉES
# ============================================================
echo "--- [3] SCAN DE ROUTES NON DOCUMENTÉES ---" | tee -a "$RESULTS_FILE"
PATHS=(
    "/admin" "/admin/" "/api" "/api/v1" "/api/v2"
    "/users" "/user" "/profile" "/dashboard"
    "/health" "/healthz" "/ping" "/status" "/metrics"
    "/debug" "/info" "/version" "/.env" "/.git"
    "/config" "/settings" "/secret" "/secrets"
    "/logout" "/token" "/refresh" "/reset" "/forgot"
    "/api/register" "/api/login" "/v1/register" "/v1/login"
    "/register/" "/login/" "//register" "//login"
    "/%2e%2e/" "/..%2f" "/../etc/passwd"
    "/register%00" "/login%00"
    "/REGISTER" "/LOGIN" "/Register" "/Login"
)
for PATH_ITEM in "${PATHS[@]}"; do
    RESP=$(curl -s -o /tmp/bb_body.txt -w "%{http_code}" \
        -X GET "$BASE_URL$PATH_ITEM" 2>/dev/null)
    BODY=$(cat /tmp/bb_body.txt 2>/dev/null | head -c 100)
    if [ "$RESP" != "404" ] && [ "$RESP" != "000" ]; then
        log_warn "Route $PATH_ITEM → $RESP (pas un 404!) | body: $BODY"
    fi
    sleep 0.1
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. ANALYSE DES HEADERS DE SÉCURITÉ
# ============================================================
echo "--- [4] HEADERS DE SÉCURITÉ ---" | tee -a "$RESULTS_FILE"
HEADERS_RESP=$(curl -sI -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"probe","password":"probe"}' 2>/dev/null)

echo "$HEADERS_RESP" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Vérification headers de sécurité attendus
declare -A SECURITY_HEADERS=(
    ["X-Frame-Options"]="protection clickjacking"
    ["X-Content-Type-Options"]="protection MIME sniffing"
    ["Content-Security-Policy"]="protection XSS/injection"
    ["Strict-Transport-Security"]="HSTS - force HTTPS"
    ["Cache-Control"]="contrôle cache"
    ["Referrer-Policy"]="fuite d'info via Referer"
    ["X-XSS-Protection"]="protection XSS legacy"
    ["Permissions-Policy"]="contrôle des features browser"
)
for HEADER in "${!SECURITY_HEADERS[@]}"; do
    if echo "$HEADERS_RESP" | grep -qi "^$HEADER:"; then
        VALUE=$(echo "$HEADERS_RESP" | grep -i "^$HEADER:" | head -1 | tr -d '\r')
        log_pass "Header $HEADER présent → $VALUE"
    else
        log_fail "Header $HEADER ABSENT — ${SECURITY_HEADERS[$HEADER]}"
    fi
done

# Headers qui NE devraient PAS être présents
echo "" | tee -a "$RESULTS_FILE"
echo "--- [5] HEADERS DANGEREUX (ne devraient pas être là) ---" | tee -a "$RESULTS_FILE"
BAD_HEADERS=("Server" "X-Powered-By" "X-AspNet-Version" "X-Runtime" "X-Version" "Via")
for HEADER in "${BAD_HEADERS[@]}"; do
    if echo "$HEADERS_RESP" | grep -qi "^$HEADER:"; then
        VALUE=$(echo "$HEADERS_RESP" | grep -i "^$HEADER:" | head -1 | tr -d '\r')
        log_fail "Header $HEADER présent (divulgation info serveur) → $VALUE"
    else
        log_pass "Header $HEADER absent (bien)"
    fi
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. ANALYSE DES RÉPONSES D'ERREUR (info disclosure)
# ============================================================
echo "--- [6] VERBOSITÉ DES ERREURS ---" | tee -a "$RESULTS_FILE"
ERROR_TESTS=(
    '{}'
    '{"username":""}'
    '{"wrong_field":"value"}'
    'not json at all'
    '{"username":"x","first_name":"a","last_name":"b","password":"y"}'
    '{"username":"nonexistent_user_xyz","password":"wrongpassword"}'
)
for PAYLOAD in "${ERROR_TESTS[@]}"; do
    RESP=$(curl -s -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 99.1.1.$((RANDOM % 254 + 1))" \
        -d "$PAYLOAD" 2>/dev/null)
    echo "  payload: ${PAYLOAD:0:60} → $RESP" | tee -a "$RESULTS_FILE"
    if echo "$RESP" | grep -qi "stack\|trace\|exception\|errno\|sqlite\|postgres\|mysql\|/usr/\|/home/\|line [0-9]"; then
        log_sec "DIVULGATION info interne dans la réponse d'erreur: $RESP"
    fi
    sleep 1
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. CONTENU-TYPE FUZZING
# ============================================================
echo "--- [7] CONTENT-TYPE FUZZING ---" | tee -a "$RESULTS_FILE"
CONTENT_TYPES=(
    "application/json"
    "application/json; charset=utf-8"
    "application/json; charset=UTF-8"
    "application/x-www-form-urlencoded"
    "multipart/form-data"
    "text/plain"
    "text/xml"
    "application/xml"
    "application/octet-stream"
    ""
    "application/json, text/plain"
    "application/JSON"
    "APPLICATION/JSON"
)
IP_IDX=50
for CT in "${CONTENT_TYPES[@]}"; do
    IP_IDX=$((IP_IDX+1))
    RESP=$(curl -s -o /tmp/bb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: $CT" \
        -H "X-Forwarded-For: 99.2.1.$IP_IDX" \
        -d '{"username":"ctfuzz","first_name":"A","last_name":"B","password":"Test1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/bb_body.txt 2>/dev/null)
    log_info "  Content-Type='$CT' → $RESP | $BODY"
    sleep 0.3
done

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS RECON: $PASS PASS | $FAIL FAIL/VULN | $INFO INFO" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
