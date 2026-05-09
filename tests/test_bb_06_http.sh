#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 06 - HTTP PROTOCOL ABUSE
# Requêtes malformées, méthodes inconnues, HTTP smuggling,
# encodages alternatifs, pipeline abuse, CORS testing
# ============================================================

BASE_URL="http://127.0.0.1:8080"
HOST="127.0.0.1"
PORT="8080"
RESULTS_FILE="/tmp/bb_06_http_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }

# Envoie une requête HTTP brute via nc/netcat
send_raw() {
    local label="$1"
    local payload="$2"
    local timeout="${3:-3}"
    local result
    result=$(echo -ne "$payload" | nc -w "$timeout" "$HOST" "$PORT" 2>/dev/null)
    HTTP_LINE=$(echo "$result" | head -1 | tr -d '\r\n')
    echo "  [$label] → $HTTP_LINE" | tee -a "$RESULTS_FILE"
    echo "$result"
}

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 06 - HTTP PROTOCOL ABUSE" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. MÉTHODES HTTP NON STANDARD
# ============================================================
echo "--- [1] MÉTHODES HTTP NON STANDARD ---" | tee -a "$RESULTS_FILE"
for METHOD in "FUZZ" "TEST" "DEBUG" "PURGE" "PROPFIND" "PROPPATCH" "MKCOL" "COPY" "MOVE" "LOCK" "UNLOCK" "SEARCH" "ARBITRARY"; do
    RESP=$(curl -s -o /tmp/http_body.txt -w "%{http_code}" \
        -X "$METHOD" "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"test","password":"test"}' 2>/dev/null)
    BODY=$(cat /tmp/http_body.txt 2>/dev/null | head -c 80)
    if [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
        log_vuln "[$METHOD] Méthode non standard acceptée → HTTP $RESP | $BODY"
    else
        log_pass "[$METHOD] → HTTP $RESP (refusé correctement)"
    fi
    sleep 0.2
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. REQUÊTES HTTP MALFORMÉES (via nc)
# ============================================================
echo "--- [2] REQUÊTES HTTP BRUTES MALFORMÉES ---" | tee -a "$RESULTS_FILE"

# Requête incomplète (pas de \r\n\r\n)
send_raw "incomplete-no-end" "POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n"

# Requête sans Host header
RAW=$(send_raw "no-host" "POST /login HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"username\":\"test\",\"password\":\"test\"}\r\n")
echo "$RAW" | grep -qi "400\|host" && log_pass "[NO-HOST] Rejet correct" || log_vuln "[NO-HOST] Serveur accepte sans Host header: $RAW"

# Double Content-Length (HTTP Smuggling CL-CL)
send_raw "double-cl" "POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 40\r\nContent-Length: 4\r\n\r\n{\"username\":\"test\",\"password\":\"test\"}\r\n"

# Transfer-Encoding + Content-Length (HTTP Smuggling TE-CL)
send_raw "te-cl-smuggling" "POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n28\r\n{\"username\":\"test\",\"password\":\"test1234\"}\r\n0\r\n\r\n"

# HTTP Request Smuggling TE.TE (Transfer-Encoding obfusqué)
send_raw "te-obfuscated" "POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n\r\n28\r\n{\"username\":\"test\",\"password\":\"test1234\"}\r\n0\r\n\r\n"

# Requête avec \n seul (pas \r\n)
send_raw "lf-only" "POST /login HTTP/1.1\nHost: 127.0.0.1:8080\nContent-Type: application/json\nContent-Length: 40\n\n{\"username\":\"test\",\"password\":\"test\"}\n"

# Méthode avec espaces
send_raw "method-spaces" "POST  /login  HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"

# Version HTTP invalide
send_raw "invalid-version" "POST /login HTTP/9.9\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"username\":\"test\",\"password\":\"test\"}\r\n"

# HTTP/0.9 (pas de headers)
send_raw "http09" "GET /login\r\n"

# URL avec null byte
send_raw "null-in-url" "POST /login%00 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"

# Chemin très long (path overflow)
LONG_PATH=$(python3 -c "print('A'*8000)" 2>/dev/null || printf 'A%.0s' $(seq 1 8000))
send_raw "long-path" "POST /$LONG_PATH HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. CHUNKED ENCODING ABUSE
# ============================================================
echo "--- [3] CHUNKED ENCODING ABUSE ---" | tee -a "$RESULTS_FILE"

# Chunk size invalide
send_raw "invalid-chunk-size" "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ\r\ntest\r\n0\r\n\r\n"

# Chunk size négatif
send_raw "negative-chunk" "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\ntest\r\n0\r\n\r\n"

# Chunk size très grand
send_raw "huge-chunk-claimed" "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\ntest\r\n0\r\n\r\n"

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. CORS TESTING
# ============================================================
echo "--- [4] CORS TESTING ---" | tee -a "$RESULTS_FILE"
ORIGINS=(
    "https://evil.example.com"
    "http://attacker.com"
    "null"
    "https://127.0.0.1"
    "http://localhost:3000"
    "https://sub.evil.com"
    "file://"
)
for ORIGIN in "${ORIGINS[@]}"; do
    RESP_HEADERS=$(curl -sI -X OPTIONS "$BASE_URL/login" \
        -H "Origin: $ORIGIN" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Content-Type" \
        -H "X-Forwarded-For: 10.20.0.$((RANDOM%254+1))" 2>/dev/null)
    ACAO=$(echo "$RESP_HEADERS" | grep -i "Access-Control-Allow-Origin:" | head -1 | tr -d '\r')
    ACAC=$(echo "$RESP_HEADERS" | grep -i "Access-Control-Allow-Credentials:" | head -1 | tr -d '\r')

    if echo "$ACAO" | grep -q "$ORIGIN" || echo "$ACAO" | grep -q "\*"; then
        if echo "$ACAC" | grep -qi "true"; then
            log_vuln "[CORS] Origin '$ORIGIN' acceptée AVEC credentials! ACAO=$ACAO | ACAC=$ACAC"
        else
            log_info "[CORS] Origin '$ORIGIN' acceptée | $ACAO"
        fi
    else
        log_pass "[CORS] Origin '$ORIGIN' refusée | $ACAO"
    fi
    sleep 0.3
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. HTTP RESPONSE SPLITTING
# ============================================================
echo "--- [5] HTTP RESPONSE SPLITTING ---" | tee -a "$RESULTS_FILE"
SPLIT_PAYLOADS=(
    "test\r\nHTTP/1.1 200 OK\r\n\r\n<html>injected</html>"
    "test%0d%0aHTTP/1.1+200+OK%0d%0a%0d%0a<html>"
    "test%0aContent-Length:%200%0a%0aHTTP/1.1 200 OK"
)
for PAYLOAD in "${SPLIT_PAYLOADS[@]}"; do
    RESP=$(curl -s -o /tmp/http_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $PAYLOAD" \
        -d '{"username":"test","password":"test"}' \
        -H "X-Forwarded-For: 10.30.0.1" 2>/dev/null)
    log_info "[SPLIT] ${PAYLOAD:0:50} → HTTP $RESP"
    sleep 0.3
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. ENCODAGES URL ALTERNATIFS SUR LES CHEMINS
# ============================================================
echo "--- [6] ENCODAGES URL ALTERNATIFS ---" | tee -a "$RESULTS_FILE"
URL_VARIANTS=(
    "/login"
    "//login"
    "/./login"
    "/../login"
    "/%6cogin"          # 'l' encodé
    "/lo%67in"          # 'g' encodé
    "/login%20"
    "/login%09"
    "/login%0a"
    "/login%0d"
    "/login%23"         # #
    "/login%3f"         # ?
    "/login%26"         # &
    "/login/"
    "/login/."
    "/register/../login"
    "/%2flogin"
)
for URL in "${URL_VARIANTS[@]}"; do
    RESP=$(curl -s -o /tmp/http_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL$URL" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.40.0.$((RANDOM%254+1))" \
        -d '{"username":"urltest","password":"Test1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/http_body.txt 2>/dev/null | head -c 80)
    if [ "$RESP" = "200" ] || [ "$RESP" = "201" ]; then
        log_vuln "[URL-ENC] '$URL' → HTTP $RESP (comportement inattendu) | $BODY"
    else
        log_info "[URL-ENC] '$URL' → HTTP $RESP"
    fi
    sleep 0.2
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 7. HEADER POLLUTION
# ============================================================
echo "--- [7] HEADER POLLUTION (headers dupliqués) ---" | tee -a "$RESULTS_FILE"
RESP=$(curl -s -o /tmp/http_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Type: text/plain" \
    -H "X-Forwarded-For: 10.50.0.1" \
    -d '{"username":"test","password":"test"}' 2>/dev/null)
BODY=$(cat /tmp/http_body.txt 2>/dev/null)
log_info "[HEADER-POLLUTION] Double Content-Type → HTTP $RESP | $BODY"

# Double Authorization header
RESP2=$(curl -s -o /tmp/http_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer fake_token_1" \
    -H "Authorization: Bearer fake_token_2" \
    -H "X-Forwarded-For: 10.50.0.2" \
    -d '{"username":"test","password":"test"}' 2>/dev/null)
BODY2=$(cat /tmp/http_body.txt 2>/dev/null)
log_info "[HEADER-POLLUTION] Double Authorization → HTTP $RESP2 | $BODY2"

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS HTTP: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
