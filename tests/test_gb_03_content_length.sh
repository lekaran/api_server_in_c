#!/bin/bash
# ============================================================
# GREY BOX AUDIT - 03 - CONTENT-LENGTH EDGE CASES
# SOURCE CODE KNOWLEDGE:
# server.c L.283-291 : strcasestr("Content-Length:") → PREMIER CL uniquement
# server.c L.294    : if(CL < 0 || CL > MAX_BODY_SIZE=14332) → 400
# server.c L.332    : body_offset = (header_end - client_message) + 4
# server.c L.337    : available_for_body = BUFFER_SIZE - body_offset - 1
# server.c L.374    : body_deja_recu = total_recu - body_offset
# server.c L.375    : bytes_restants = CL - body_deja_recu
# server.c L.378    : if(bytes_restants > 0) { recv body... }
#
# MAX_BODY_SIZE = BUFFER_SIZE(16384) - HTTP_HEADERS_MAX(2048) - 4 = 14332
# ============================================================

BASE_URL="http://127.0.0.1:8080"
HOST="127.0.0.1"
PORT="8080"
RESULTS_FILE="/tmp/gb_03_content_length_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_code() { echo -e "${CYAN}[CODE]${NC} $1" | tee -a "$RESULTS_FILE"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  GREY BOX - 03 - CONTENT-LENGTH EDGE CASES" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

BODY_VALID='{"username":"cltest_gb","first_name":"A","last_name":"B","password":"Secure1234!"}'
BODY_LEN=${#BODY_VALID}

# ============================================================
# 1. CL=0 avec body → VULN confirmée
# ============================================================
echo "--- [1] Content-Length: 0 avec body présent ---" | tee -a "$RESULTS_FILE"
log_code "server.c:375 bytes_restants = 0 - body_deja_recu = négatif → if(>0) → SKIP"
log_code "Mais le body est déjà dans client_message → http_parse_request le lit!"

RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 0" \
    -d "$BODY_VALID" 2>/dev/null)
BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
echo "  CL=0, body réel=${BODY_LEN}B → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
[ "$RESP" = "201" ] && log_vuln "[CL-0] Body traité malgré CL=0 → 201 (user créé!)" || log_pass "[CL-0] → $RESP"
sleep 1

# ============================================================
# 2. CL < body réel (body tronqué)
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [2] Content-Length < body réel (body tronqué) ---" | tee -a "$RESULTS_FILE"
log_code "server.c:378 bytes_restants = CL_petit - body_deja_recu → si négatif: SKIP"
log_code "body_len dans http_parse_request = fin_buffer - pos (tout le buffer reçu)"

# Si CL=10, body=80 bytes : bytes_restants = 10 - 80 = -70 → SKIP body read
# Mais http_parse_request voit TOUT le body quand même
RESP=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n$BODY_VALID\r\n" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP=$(echo "$RESP" | head -1 | tr -d '\r\n')
RBODY=$(echo "$RESP" | tail -1)
echo "  CL=10, body réel=${BODY_LEN}B (via nc) → $HTTP | $RBODY" | tee -a "$RESULTS_FILE"
if echo "$RESP" | grep -qi "201\|User created"; then
    log_vuln "[CL-SMALL] CL=10 mais body ${BODY_LEN}B → user créé! Body entier traité"
else
    log_pass "[CL-SMALL] → $HTTP"
fi
sleep 1

# ============================================================
# 3. CL = MAX_BODY_SIZE exact (14332) avec body petit
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [3] Content-Length = MAX_BODY_SIZE (14332) avec petit body ---" | tee -a "$RESULTS_FILE"
log_code "server.c:294 : if CL > MAX_BODY_SIZE(14332) → 400"
log_code "CL=14332 (juste en dessous) → accepté → serveur attend 14332 - body_deja_recu bytes"
log_code "SO_RCVTIMEO=5s → si client déconnecté, recv() revient immédiatement (ECONNRESET)"

T_START=$(date +%s%N)
RESP=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 14332\r\n\r\n$BODY_VALID" \
    | nc -w 8 "$HOST" "$PORT" 2>/dev/null)
T_END=$(date +%s%N)
ELAPSED=$(( (T_END - T_START) / 1000000 ))
HTTP=$(echo "$RESP" | head -1 | tr -d '\r\n')
echo "  CL=14332, body réel=${BODY_LEN}B → $HTTP | temps=${ELAPSED}ms" | tee -a "$RESULTS_FILE"
if [ "$ELAPSED" -ge 4500 ]; then
    log_vuln "[CL-MAX] CL=14332 petit body → serveur bloqué ${ELAPSED}ms (≈SO_RCVTIMEO=5s) par requête!"
    log_info "  Impact: chaque requête CL=MAX bloque le serveur 5s → 12 req/min max"
else
    log_pass "[CL-MAX] → $HTTP | ${ELAPSED}ms"
fi
sleep 1

# ============================================================
# 4. CL = MAX_BODY_SIZE + 1 (doit être rejeté → 400)
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [4] Content-Length = 14333 (juste au-dessus MAX) ---" | tee -a "$RESULTS_FILE"
log_code "server.c:294 : if CL > MAX_BODY_SIZE(14332) → 400 Bad Request (correct)"

RESP=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 14333\r\n\r\n$BODY_VALID" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP=$(echo "$RESP" | head -1 | tr -d '\r\n')
echo "  CL=14333 → $HTTP" | tee -a "$RESULTS_FILE"
echo "$RESP" | grep -q "400" && log_pass "[CL-LIMIT] CL>MAX rejeté → 400 (correct)" || log_fail "[CL-LIMIT] → $HTTP (attendu 400)"
sleep 1

# ============================================================
# 5. CL négatif
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [5] Content-Length négatif ---" | tee -a "$RESULTS_FILE"
log_code "server.c:290 : content_length = strtol(...) → peut être négatif"
log_code "server.c:294 : if(CL < 0) → 400 (correct)"

RESP=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: -1\r\n\r\n$BODY_VALID" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP=$(echo "$RESP" | head -1 | tr -d '\r\n')
echo "  CL=-1 → $HTTP" | tee -a "$RESULTS_FILE"
echo "$RESP" | grep -q "400" && log_pass "[CL-NEG] CL négatif rejeté → 400 (correct)" || log_fail "[CL-NEG] → $HTTP"
sleep 1

# ============================================================
# 6. CL avec espaces et valeur cachée (obfuscation)
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [6] Content-Length avec valeurs obfusquées ---" | tee -a "$RESULTS_FILE"
log_code "server.c:288 : while(*header_content == ' ') header_content++; → ignore espaces"

# CL avec espaces
RESP1=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length:   ${BODY_LEN}\r\n\r\n$BODY_VALID" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP1=$(echo "$RESP1" | head -1 | tr -d '\r\n')
echo "  CL='  ${BODY_LEN}' (espaces) → $HTTP1" | tee -a "$RESULTS_FILE"

# CL avec tab
RESP2=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length:\t${BODY_LEN}\r\n\r\n$BODY_VALID" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP2=$(echo "$RESP2" | head -1 | tr -d '\r\n')
echo "  CL='\\t${BODY_LEN}' (tab) → $HTTP2" | tee -a "$RESULTS_FILE"

# CL hexadécimal
RESP3=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 0x50\r\n\r\n$BODY_VALID" \
    | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
HTTP3=$(echo "$RESP3" | head -1 | tr -d '\r\n')
echo "  CL='0x50' (hex) → $HTTP3 (strtol base 10 → 0, puis body ignoré?)" | tee -a "$RESULTS_FILE"
sleep 1

# ============================================================
# 7. ATTAQUE : CL = MAX_BODY_SIZE-1 pour bloquer le serveur
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [7] ATTAQUE DoS via CL = MAX-1 (bloque 5s par requête) ---" | tee -a "$RESULTS_FILE"
log_code "Chaque req avec CL=14331 mais body=80B → serveur attend 14251 octets → SO_RCVTIMEO=5s"
log_code "Serveur single-thread → bloqué 5s × N requêtes"
log_info "Test: 3 requêtes consécutives avec CL=MAX-1..."

TOTAL_BLOCK=0
for i in $(seq 1 3); do
    T_START=$(date +%s%N)
    echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 14331\r\n\r\n$BODY_VALID" \
        | nc -w 8 "$HOST" "$PORT" >/dev/null 2>/dev/null
    T_END=$(date +%s%N)
    ELAPSED=$(( (T_END - T_START) / 1000000 ))
    echo "  Requête $i → ${ELAPSED}ms de blocage" | tee -a "$RESULTS_FILE"
    TOTAL_BLOCK=$((TOTAL_BLOCK + ELAPSED))
done
echo "  Total blocage: ${TOTAL_BLOCK}ms pour 3 requêtes" | tee -a "$RESULTS_FILE"
if [ "$TOTAL_BLOCK" -ge 12000 ]; then
    log_vuln "[CL-DOS] ${TOTAL_BLOCK}ms de blocage serveur total → DoS via CL=MAX-1 confirmé!"
    log_code "  Fix: réduire MAX_BODY_SIZE ou ajouter un timeout global de connexion"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS CL: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
