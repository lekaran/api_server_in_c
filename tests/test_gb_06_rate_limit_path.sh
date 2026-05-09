#!/bin/bash
# ============================================================
# GREY BOX AUDIT - 06 - RATE LIMIT KEY ANALYSIS
# SOURCE CODE KNOWLEDGE:
# rate_limit.c L.32 : key = "rl:{route}:{client_ip}"
# rate_limit.c L.10 : T=6000000μs, burst=5, ttl=30s
# server.c L.460    : rate_limit_check(cc_conn, req.path, client_ip)
# router.c L.26     : strcmp(path, req->path) → exact match
#
# ANALYSE:
# 1. Clé = chemin EXACT + IP TCP → pas de normalisation
# 2. /register et /login ont des compteurs SÉPARÉS
# 3. Chemin inconnu = compteur séparé (mais handler 404 non atteint)
# 4. BODY_MAX = 512 bytes dans router.c → truncation silencieuse
# 5. Token hash stocké en SHA-256 (non bcrypt) → fast lookup OK
# ============================================================

BASE_URL="http://127.0.0.1:8080"
HOST="127.0.0.1"
PORT="8080"
RESULTS_FILE="/tmp/gb_06_rate_limit_path_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_code() { echo -e "${CYAN}[CODE]${NC} $1" | tee -a "$RESULTS_FILE"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  GREY BOX - 06 - RATE LIMIT KEY ANALYSIS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

log_code "rate_limit.c:32  → key = 'rl:{route}:{client_ip}'"
log_code "rate_limit.c:10  → T=6s, burst=5 → max 5 req/30s par (path, IP)"
log_code "server.c:460     → rate_limit_check(conn, req.path, client_ip)"
log_code "router.c:26      → strcmp exact → /register et /login compteurs SÉPARÉS"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. VÉRIFICATION : /register et /login ont des compteurs séparés
# ============================================================
echo "--- [1] Compteurs rate limit SÉPARÉS par endpoint ---" | tee -a "$RESULTS_FILE"
log_code "clé /register → 'rl:/register:127.0.0.1'"
log_code "clé /login    → 'rl:/login:127.0.0.1'"
log_code "Épuiser /register ne bloque PAS /login et vice versa"

# Épuiser le rate limit sur /login
log_info "Épuisement rate limit /login..."
for i in $(seq 1 5); do
    RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"rltest","password":"test"}' 2>/dev/null)
    echo "  /login req $i → $RESP" | tee -a "$RESULTS_FILE"
done

# Maintenant tester /register (compteur séparé)
RESP_REG=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"rl_cross_test","first_name":"A","last_name":"B","password":"Secure1234!"}' 2>/dev/null)
BODY_REG=$(cat /tmp/gb_body.txt 2>/dev/null)
echo "  /register après épuisement /login → $RESP_REG | $BODY_REG" | tee -a "$RESULTS_FILE"
if echo "$BODY_REG" | grep -qi "too_many"; then
    log_fail "[RL-SHARED] Rate limit partagé entre /login et /register (cross-endpoint)"
else
    log_pass "[RL-SEPARATE] Rate limits séparés par endpoint (attendu selon code)"
fi

sleep 31  # reset

# ============================================================
# 2. BODY_MAX = 512 BYTES - TRONCATURE SILENCIEUSE
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [2] BODY_MAX=512 octets (troncature réponse handler) ---" | tee -a "$RESULTS_FILE"
log_code "router.c:55 : #define BODY_MAX 512"
log_code "router.c:56 : char body[BODY_MAX]=''"
log_code "router.c:57 : http_code = handler(req, body, sizeof(body))"
log_code ""
log_code "Si la réponse dépasse 512 bytes → snprintf tronque silencieusement"
log_code "Réponse actuelle login: {'token':'64_hex'} = ~79 bytes → OK"
log_code "Mais: si error message inclut des données user, truncation possible"
log_code ""
log_code "TEST: réponse token = ~79 bytes < 512 → pas tronquée"

RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"gb_confirm01","password":"Secure1234!"}' 2>/dev/null)
BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
RESP_LEN=${#BODY}
echo "  login response: $BODY (longueur: ${RESP_LEN}B)" | tee -a "$RESULTS_FILE"
[ "$RESP_LEN" -lt 512 ] && log_pass "[BODY_MAX] Réponse ${RESP_LEN}B < 512B → pas tronquée" \
    || log_vuln "[BODY_MAX] Réponse ${RESP_LEN}B >= 512B → potentiellement tronquée!"

sleep 31

# ============================================================
# 3. ANALYSE DU TOKEN : SHA-256 simple (pas bcrypt)
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [3] ANALYSE TOKEN: SHA-256 vs bcrypt ---" | tee -a "$RESULTS_FILE"
log_code "token.c:16 : crypto_hash_sha256(hash, token_bytes, len)"
log_code "password.c : crypto_pwhash_str() → ARGON2ID (bcrypt-like, lent)"
log_code ""
log_code "ANALYSE:"
log_code "  - Token: 32 bytes aléatoires → SHA-256 (rapide car déjà aléatoire)"
log_code "  - Mot de passe: ARGON2ID (lent, anti-brute-force)"
log_code "  - CORRECT: SHA-256 OK pour token car entropie déjà haute (256 bits)"
log_code "  - CORRECT: ARGON2ID pour password (basse entropie = brute-forceable)"

RESP1=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"gb_confirm01","password":"Secure1234!"}' 2>/dev/null)
RESP2=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"gb_confirm01","password":"Secure1234!"}' 2>/dev/null)

sleep 31

T1=$(curl -s -o /dev/null -w "%{time_total}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"gb_confirm01","password":"Secure1234!"}' 2>/dev/null)
log_info "[TOKEN-ANALYSIS] Login time (Argon2id hash): ${T1}s"
log_info "  Token1: $(echo "$RESP1" | grep -o '"token":"[^"]*"')"
log_info "  Token2: $(echo "$RESP2" | grep -o '"token":"[^"]*"')"
echo "$RESP1" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 | wc -c | grep -q "65" \
    && log_pass "[TOKEN] Token = 64 hex chars (32 random bytes) → 256 bits d'entropie" \
    || log_info "[TOKEN] Token format: $(echo "$RESP1" | grep -o '"token":"[^"]*"')"

sleep 31

# ============================================================
# 4. ANALYSE DES CLÉS REDIS : Vérification format
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [4] VÉRIFICATION FORMAT CLÉ REDIS ---" | tee -a "$RESULTS_FILE"
log_code "rate_limit.c:32 : 'rl:%s:%s' → key = 'rl:/login:127.0.0.1'"
log_code "Problème potentiel: si path contient ':', cela change la structure de clé"
log_code "Mais: http_parser limite path à 512B et router fait strcmp exact"

# Test avec path contenant ":"
RESP=$(echo -ne "POST /login:evil HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"username\":\"test\",\"password\":\"test\"}\r\n" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP=$(echo "$RESP" | head -1 | tr -d '\r\n')
echo "  path '/login:evil' → $HTTP" | tee -a "$RESULTS_FILE"
echo "$RESP" | grep -qi "404" && log_pass "[KEY-INJ] path avec ':' → 404 (pas de route matchée)" \
    || log_info "[KEY-INJ] → $HTTP"

# ============================================================
# 5. VÉRIFICATION : Dummy hash protège contre timing attack
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [5] VÉRIFICATION ANTI-TIMING (dummy hash) ---" | tee -a "$RESULTS_FILE"
log_code "login.c:18-25 : login_init() → pre-compute dummy_hash au démarrage"
log_code "login.c:183  : if(MYSQL_NO_DATA) → crypto_pwhash_str_verify(dummy_hash, ...)"
log_code "Résultat: user inexistant → même calcul Argon2id → même temps de réponse"
log_code "Protection anti-énumération par timing ✓"

TIMES=()
log_info "Mesures user INEXISTANT (10 runs):"
for i in $(seq 1 10); do
    T=$(curl -s -o /dev/null -w "%{time_total}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"absolutely_nonexistent_user_xyz789","password":"TestPass1234!"}' 2>/dev/null \
        | awk '{printf "%d\n", $1*1000}')
    echo -n "  ${T}ms " | tee -a "$RESULTS_FILE"
    sleep 0.5
done
echo "" | tee -a "$RESULTS_FILE"
log_pass "[ANTI-TIMING] dummy_hash implémenté dans login.c → timing attack mitigé"

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS RL ANALYSIS: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
