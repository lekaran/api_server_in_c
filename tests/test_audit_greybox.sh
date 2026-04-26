#!/bin/bash
# ============================================================
#  AUDIT DE SÉCURITÉ — GREY BOX
#  Cible  : http://127.0.0.1:8080  (POST /register, POST /login)
#  DB     : MySQL
#  Auteur : audit automatisé grey-box
#  Date   : 2026-04-25
#
#  SPÉCIFICITÉ GREY BOX : chaque test est fondé sur la lecture
#  directe du code source (server.c, handler/*.c, router.c, etc.)
#  Les références de fichier/ligne sont indiquées pour chaque vuln.
# ============================================================
#
#  SECTIONS :
#   GBX-001  Content-Length case-sensitive bypass    (server.c:260)
#   GBX-002  BUFFER_SIZE vs MAX_BODY_SIZE            (server.h:4-5)
#   GBX-003  Content-Length négatif                  (server.c:265)
#   GBX-004  DoS mono-thread + argon2id              (server.c:147)
#   GBX-005  Token sans expiry / accumulation DB     (login.c:245)
#   GBX-006  Slow Loris amplifié mono-thread         (server.c:153)
#   GBX-007  HTTP version non validée                (http_parser.c:59)
#   GBX-008  Login retourne 201 au lieu de 200       (login.c:281)
#   GBX-009  UTF-8 ≥ 0x80 dans first_name/last_name  (register.c:185)
#   GBX-010  Pas de validation Content-Type          (server.c — absent)
#   GBX-011  BODY_MAX = 512 dans router.c            (router.c:11)
#   GBX-012  Content-Length = 0 avec body réel       (server.c:271)
#   GBX-013  strtol sans borne sur Content-Length    (server.c:265)
#   GBX-014  Pas de HSTS / No TLS                    (server.c — absent)
#   GBX-015  recv(fd, buf, 0) quand buffer saturé    (server.c:319)
# ============================================================

BASE_URL="http://127.0.0.1:8080"
PASS=0; WARN=0; INFO_COUNT=0
TS=$(date +%s)
LOG_FILE="/tmp/audit_greybox_${TS}.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RESET='\033[0m'

log()     { echo -e "$@" | tee -a "$LOG_FILE"; }
section() {
    log ""
    log "${BLUE}═══════════════════════════════════════════════════════════${RESET}"
    log "${BLUE}  $1${RESET}"
    log "${BLUE}═══════════════════════════════════════════════════════════${RESET}"
    log ""
}
pass()    { log "  ${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
vuln()    { log "  ${YELLOW}[VULN]${RESET} $1"; WARN=$((WARN+1)); }
info()    { log "  ${CYAN}[INFO]${RESET} $1"; INFO_COUNT=$((INFO_COUNT+1)); }
grey()    { log "  ${MAGENTA}[CODE]${RESET} $1"; }

# ════════════════════════════════════════════════════════════
#  SETUP
# ════════════════════════════════════════════════════════════
section "SETUP — Création de l'utilisateur grey-box"

GBX_USER="gbx_audit_${TS}"
GBX_PASS="GbxAudit@2026!"

SETUP_CODE=$(curl -s -o /tmp/gbx_setup.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"first_name\":\"GreyBox\",\"last_name\":\"Audit\",\"password\":\"${GBX_PASS}\"}")

if [ "$SETUP_CODE" -ne 201 ]; then
    log "${RED}ERREUR setup (HTTP $SETUP_CODE) — $(cat /tmp/gbx_setup.json)${RESET}"
    exit 1
fi

TOKEN=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" | \
    grep -o '"token":"[^"]*"' | cut -d'"' -f4)

log "  Utilisateur : $GBX_USER"
log "  Token       : ${TOKEN:0:20}... ($(echo -n "$TOKEN" | wc -c | tr -d ' ') chars)"

# ════════════════════════════════════════════════════════════
#  GBX-001 — Content-Length CASE-SENSITIVE (server.c:260)
# ════════════════════════════════════════════════════════════
section "GBX-001 — Content-Length case-sensitive bypass"

grey "server.c:260 : strstr(client_message, \"Content-Length:\") est CASE-SENSITIVE"
grey "             → envoyer 'content-length:' (minuscule) bypasse la vérification MAX_BODY_SIZE"
grey "             → content_length=0, bytes_restants<0, corps dans buffer depuis la lecture des headers"

log ""
log "[ GBX-001.1 content-length (minuscule) avec body JSON valide ]"
# Le body est dans le même segment TCP que les headers → arrive dans le buffer de lecture
R=$(curl -s -o /tmp/gbx001a.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "content-type: application/json" \
    -H "content-length: $(echo -n "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" | wc -c | tr -d ' ')" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
RESP=$(cat /tmp/gbx001a.json)
log "  HTTP $R : $RESP"
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-001.1 Login réussi avec 'content-length' minuscule → bypass du Content-Length check (HTTP $R)"
elif [ "$R" -eq 400 ] || [ "$R" -eq 401 ]; then
    pass "GBX-001.1 content-length minuscule → $R (traité correctement)"
else
    info "GBX-001.1 content-length minuscule → HTTP $R : $RESP"
fi

log ""
log "[ GBX-001.2 Content-Length UPPERCASE alterné ]"
R=$(curl -s -o /tmp/gbx001b.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "CONTENT-LENGTH: $(echo -n "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" | wc -c | tr -d ' ')" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
log "  HTTP $R"
if [ "$R" -eq 201 ]; then
    vuln "GBX-001.2 CONTENT-LENGTH uppercase → login réussi (bypass)"
else
    pass "GBX-001.2 CONTENT-LENGTH uppercase → $R"
fi

log ""
log "[ GBX-001.3 Sans header Content-Length (body quand même dans buffer) ]"
# curl --http1.1 sans Content-Length : le serveur voit content_length=0 mais le body est dans
# le premier recv() car curl envoie tout en un seul write TCP.
R=$(curl -s -o /tmp/gbx001c.json -w "%{http_code}" \
    --http1.1 \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    --data-raw "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    -H "Content-Length:" \
    --max-time 5)
RESP=$(cat /tmp/gbx001c.json)
log "  HTTP $R : $RESP"
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-001.3 Login sans Content-Length header → accepté et traité (HTTP $R) — MAX_BODY_SIZE bypassé"
elif [ "$R" -eq 400 ]; then
    pass "GBX-001.3 Sans Content-Length → $R (rejeté)"
else
    info "GBX-001.3 Sans Content-Length → HTTP $R : $RESP"
fi

# ════════════════════════════════════════════════════════════
#  GBX-002 — BUFFER_SIZE (8192) << MAX_BODY_SIZE (65536)
# ════════════════════════════════════════════════════════════
section "GBX-002 — BUFFER_SIZE vs MAX_BODY_SIZE — buffer trop petit"

grey "server.h:4  : BUFFER_SIZE = 8192 (buffer recv)"
grey "server.h:5  : MAX_BODY_SIZE = 65536 (body max déclaré)"
grey "server.c:319: recv(client_accepted, client_message+total_recu, BUFFER_SIZE-total_recu-1, 0)"
grey "PROBLÈME    : quand total_recu = BUFFER_SIZE-1, recv(fd, buf, 0) → retourne 0"
grey "            → le code interprète 0 comme 'client déconnecté' et ferme la connexion"
grey "            → une requête légitime > ~7800 bytes total (headers + body) est rejetée"

log ""
log "[ GBX-002.1 Body de 6000 octets (dans la fenêtre réelle BUFFER_SIZE) ]"
BODY_6K=$(python3 -c "
import json
body = json.dumps({
    'username': '${GBX_USER}',
    'first_name': 'T',
    'last_name': 'T',
    'password': 'P@ssw0rd1',
    'padding': 'A' * 6000
})
print(body)")
R=$(curl -s -o /tmp/gbx002a.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$BODY_6K" \
    --max-time 5)
log "  HTTP $R (body ~6KB)"
if [ "$R" -eq 400 ]; then
    pass "GBX-002.1 Body 6KB → $R (rejeté correctement, MAX_BODY_SIZE ou buffer check)"
elif [ "$R" -eq 000 ]; then
    vuln "GBX-002.1 Body 6KB → timeout/no-response (recv(0) loop, DoS potentiel)"
else
    info "GBX-002.1 Body 6KB → HTTP $R"
fi

log ""
log "[ GBX-002.2 Body de 7500 octets — dans MAX_BODY_SIZE mais > BUFFER_SIZE-headers ]"
BODY_7K=$(python3 -c "
import json
body = json.dumps({
    'username': '${GBX_USER}',
    'first_name': 'T',
    'last_name': 'T',
    'password': 'P@ssw0rd1',
    'padding': 'B' * 7500
})
print(body)")
R=$(curl -s -o /tmp/gbx002b.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$BODY_7K" \
    --max-time 8)
log "  HTTP $R (body ~7.5KB, potentiellement refusé à tort si BUFFER_SIZE=8192)"
if [ "$R" -eq 400 ]; then
    pass "GBX-002.2 Body 7.5KB → $R (bloqué)"
elif [ "$R" -eq 000 ]; then
    vuln "GBX-002.2 Body 7.5KB → connexion coupée (serveur a appelé recv(fd,buf,0) → disconnect forcé)"
else
    info "GBX-002.2 Body 7.5KB → HTTP $R"
fi

log ""
log "[ GBX-002.3 Content-Length = 32000 (< MAX_BODY_SIZE mais > BUFFER_SIZE) ]"
# Envoyer seulement les headers avec un Content-Length annoncé élevé, voir comment réagit le serveur
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 32000" \
    -d "{\"username\":\"x\",\"password\":\"y\"}" \
    --max-time 8)
log "  HTTP $R (Content-Length=32000 mais body réel ~35 bytes)"
if [ "$R" -eq 400 ]; then
    pass "GBX-002.3 Content-Length 32000 avec petit body → $R"
elif [ "$R" -eq 000 ]; then
    vuln "GBX-002.3 Content-Length 32000 → timeout : serveur attend des données qui ne viennent pas (DoS potentiel)"
else
    info "GBX-002.3 Content-Length 32000 → HTTP $R"
fi

# ════════════════════════════════════════════════════════════
#  GBX-003 — Content-Length NÉGATIF (server.c:265)
# ════════════════════════════════════════════════════════════
section "GBX-003 — Content-Length négatif"

grey "server.c:265: content_length = strtol(header_content, &endptrContent, 10)"
grey "            → pas de vérification content_length >= 0"
grey "            → Content-Length: -1 → content_length = -1"
grey "            → if(-1 > MAX_BODY_SIZE) = false → pas de rejet"
grey "            → bytes_restants = -1 - body_deja_recu < 0 → pas de lecture body"
grey "            → body déjà dans buffer depuis la boucle headers → traité normalement"

log ""
log "[ GBX-003.1 Content-Length: -1 avec body JSON valide ]"
R=$(curl -s -o /tmp/gbx003a.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: -1" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
RESP=$(cat /tmp/gbx003a.json)
log "  HTTP $R : $RESP"
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-003.1 Content-Length: -1 → Login réussi! Body traité malgré Content-Length négatif"
elif [ "$R" -eq 400 ]; then
    pass "GBX-003.1 Content-Length: -1 → $R (rejeté)"
else
    info "GBX-003.1 Content-Length: -1 → HTTP $R : $RESP"
fi

log ""
log "[ GBX-003.2 Content-Length: -999999 ]"
R=$(curl -s -o /tmp/gbx003b.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: -999999" \
    -d "{\"username\":\"x\",\"password\":\"y\"}" \
    --max-time 5)
log "  HTTP $R : $(cat /tmp/gbx003b.json)"
if [ "$R" -eq 400 ]; then
    pass "GBX-003.2 Content-Length: -999999 → $R (rejeté)"
else
    info "GBX-003.2 Content-Length: -999999 → HTTP $R"
fi

log ""
log "[ GBX-003.3 Content-Length: 0 avec body JSON valide ]"
R=$(curl -s -o /tmp/gbx003c.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 0" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
RESP=$(cat /tmp/gbx003c.json)
log "  HTTP $R : $RESP"
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-003.3 Content-Length: 0 avec body réel → Login réussi (body traité depuis buffer)"
elif [ "$R" -eq 400 ]; then
    pass "GBX-003.3 Content-Length: 0 avec body → $R (rejeté)"
else
    info "GBX-003.3 Content-Length: 0 avec body → HTTP $R : $RESP"
fi

# ════════════════════════════════════════════════════════════
#  GBX-004 — DoS MONO-THREAD + argon2id (server.c:147)
# ════════════════════════════════════════════════════════════
section "GBX-004 — DoS par saturation mono-thread + argon2id"

grey "server.c:147: boucle accept() séquentielle — UN seul client à la fois"
grey "login.c:205 : crypto_pwhash_str_verify() = argon2id ~200-500ms par vérification"
grey "server.h:72 : backlog listen() = 10 connexions en attente maximum"
grey "VECTEUR     : N connexions simultanées en login → serveur occupé N × 500ms"
grey "            → les clients légitimes attendent dans la queue (max 10) ou sont refusés"

log ""
log "[ GBX-004.1 Mesure du temps d'une vérification argon2id ]"
T1=$(python3 -c "import time; print(int(time.time()*1000))")
curl -s -o /dev/null -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"wrong_password\"}" --max-time 10
T2=$(python3 -c "import time; print(int(time.time()*1000))")
ARGON_MS=$((T2 - T1))
log "  Temps vérification argon2id (mauvais mdp) : ${ARGON_MS}ms"
if [ "$ARGON_MS" -gt 50 ]; then
    vuln "GBX-004.1 Argon2id prend ${ARGON_MS}ms/requête → avec serveur mono-thread, N connexions simultanées = N × ${ARGON_MS}ms de blocage total"
else
    info "GBX-004.1 Argon2id : ${ARGON_MS}ms/requête"
fi

log ""
log "[ GBX-004.2 Saturation avec 5 connexions parallèles ]"
log "  Lancement de 5 requêtes /login en parallèle..."
T_START=$(python3 -c "import time; print(int(time.time()*1000))")
for i in $(seq 1 5); do
    curl -s -o /dev/null -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${GBX_USER}\",\"password\":\"dos_attempt_${i}\"}" \
        --max-time 30 &
done

# Pendant ce temps, tester si le serveur répond à d'autres clients
sleep 0.2
T_CLIENT=$(python3 -c "import time; print(int(time.time()*1000))")
R_PROBE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"probe_dos_${TS}\",\"first_name\":\"P\",\"last_name\":\"P\",\"password\":\"P@ss1234\"}" \
    --max-time 15)
T_CLIENT_END=$(python3 -c "import time; print(int(time.time()*1000))")
CLIENT_WAIT=$((T_CLIENT_END - T_CLIENT))
wait

T_END=$(python3 -c "import time; print(int(time.time()*1000))")
TOTAL_MS=$((T_END - T_START))
log "  Temps total pour 5 requêtes parallèles : ${TOTAL_MS}ms"
log "  Temps d'attente d'un client légitime pendant l'attaque : ${CLIENT_WAIT}ms (HTTP $R_PROBE)"
if [ "$CLIENT_WAIT" -gt 500 ]; then
    vuln "GBX-004.2 Client légitime a attendu ${CLIENT_WAIT}ms pendant l'attaque DoS (serveur bloqué par argon2id × mono-thread)"
else
    pass "GBX-004.2 Client légitime a répondu en ${CLIENT_WAIT}ms pendant l'attaque (impact limité)"
fi

# ════════════════════════════════════════════════════════════
#  GBX-005 — TOKEN SANS EXPIRY, ACCUMULATION DB (login.c:245)
# ════════════════════════════════════════════════════════════
section "GBX-005 — Token sans expiry ni invalidation"

grey "login.c:245 : INSERT INTO tokens(user_id, token_hash) VALUES (?,?)"
grey "            → chaque login crée une NOUVELLE ligne dans la table tokens"
grey "            → aucun mécanisme d'expiry, aucun TTL, aucune rotation"
grey "            → aucune route /logout active (commentée dans router.c:17)"
grey "            → accumulation illimitée : les anciens tokens restent valides"

log ""
log "[ GBX-005.1 Génération de 10 tokens successifs (même utilisateur) ]"
TOKENS_GENERATED=0
declare -a TOKEN_LIST=()
for i in $(seq 1 10); do
    T=$(curl -s -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" | \
        grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$T" ]; then
        TOKEN_LIST+=("$T")
        TOKENS_GENERATED=$((TOKENS_GENERATED+1))
    fi
done
log "  Tokens générés : $TOKENS_GENERATED"
if [ "$TOKENS_GENERATED" -eq 10 ]; then
    vuln "GBX-005.1 10 tokens générés pour le même utilisateur sans invalidation des anciens"
    info "GBX-005.1 Tous les tokens restent théoriquement valides en base (pas de rotation)"
fi

log ""
log "[ GBX-005.2 Pas de route /logout (token non révocable) ]"
R_LOGOUT=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/logout" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    --max-time 3)
if [ "$R_LOGOUT" -eq 404 ]; then
    vuln "GBX-005.2 /logout n'existe pas → impossible de révoquer un token (vol de session = permanent)"
else
    info "GBX-005.2 /logout → HTTP $R_LOGOUT"
fi

log ""
log "[ GBX-005.3 Vérification : le 1er token est-il toujours valide après 10 nouveaux logins ? ]"
FIRST_TOKEN="${TOKEN_LIST[0]}"
info "GBX-005.3 Le premier token ne peut pas être 'utilisé' directement (pas de route protégée active)"
info "GBX-005.3 Mais la DB contient maintenant $TOKENS_GENERATED + 1 (setup) = $((TOKENS_GENERATED+1)) entrées token pour cet user"
vuln "GBX-005.3 Pas d'expiry ni de révocation → risque de stockage en base de données illimité (DoS DB à long terme)"

# ════════════════════════════════════════════════════════════
#  GBX-006 — SLOW LORIS (amplification mono-thread)
# ════════════════════════════════════════════════════════════
section "GBX-006 — Slow Loris / connexion lente"

grey "server.c:153: SO_RCVTIMEO = 5 secondes"
grey "server.c:188: boucle recv() des headers — s'arrête seulement à \\r\\n\\r\\n"
grey "            → un client qui envoie des headers byte par byte maintient"
grey "              la connexion ouverte jusqu'à 5 secondes d'inactivité"
grey "            → avec serveur mono-thread : 1 connexion lente = server bloqué 5 sec"

log ""
log "[ GBX-006.1 Connexion qui envoie les headers très lentement ]"
log "  Envoi d'une requête incomplète (sans \\r\\n\\r\\n) et mesure du blocage..."
T_SLOW_START=$(python3 -c "import time; print(int(time.time()*1000))")

# Connecter un socket et envoyer une requête partielle (sans la ligne vide finale)
# Le serveur attend jusqu'au timeout SO_RCVTIMEO (5s)
python3 -c "
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect(('127.0.0.1', 8080))
    # Envoyer des headers partiels — sans la ligne vide finale \r\n\r\n
    s.send(b'POST /login HTTP/1.1\r\n')
    s.send(b'Host: 127.0.0.1\r\n')
    s.send(b'Content-Type: application/json\r\n')
    # On s'arrête ici : le serveur attend \r\n\r\n
    time.sleep(6)  # attendre le timeout
    s.close()
except Exception as e:
    print(f'Erreur: {e}')
" &
SLOW_PID=$!

# Pendant ce temps, un client légitime essaie de se connecter
sleep 1
T_LEGIT_START=$(python3 -c "import time; print(int(time.time()*1000))")
R_LEGIT=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 12)
T_LEGIT_END=$(python3 -c "import time; print(int(time.time()*1000))")
LEGIT_WAIT=$((T_LEGIT_END - T_LEGIT_START))

wait $SLOW_PID 2>/dev/null
T_SLOW_END=$(python3 -c "import time; print(int(time.time()*1000))")
SLOW_TOTAL=$((T_SLOW_END - T_SLOW_START))

log "  Durée de blocage Slow Loris : ${SLOW_TOTAL}ms"
log "  Temps d'attente client légitime : ${LEGIT_WAIT}ms (HTTP $R_LEGIT)"

if [ "$LEGIT_WAIT" -gt 3000 ]; then
    vuln "GBX-006.1 Slow Loris efficace : client légitime a attendu ${LEGIT_WAIT}ms à cause d'une connexion lente"
elif [ "$LEGIT_WAIT" -gt 1000 ]; then
    vuln "GBX-006.1 Impact partiel : client légitime a attendu ${LEGIT_WAIT}ms (serveur mono-thread bloqué)"
else
    pass "GBX-006.1 Slow Loris impact faible : client légitime → ${LEGIT_WAIT}ms"
fi

# ════════════════════════════════════════════════════════════
#  GBX-007 — HTTP VERSION NON VALIDÉE (http_parser.c:59)
# ════════════════════════════════════════════════════════════
section "GBX-007 — HTTP version non validée"

grey "http_parser.c:59: la version est stockée dans req->version mais jamais vérifiée"
grey "router.c       : le dispatcher ne vérifie pas HTTP version"
grey "server.c       : aucune vérification de version HTTP"

log ""
log "[ GBX-007.1 HTTP/9.9 (version arbitraire) ]"
R=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
body = b'{\"username\":\"x\",\"password\":\"y\"}'
req = b'POST /login HTTP/9.9\r\n'
req += b'Content-Type: application/json\r\n'
req += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
req += b'\r\n'
req += body
s.send(req)
s.settimeout(5)
try:
    resp = s.recv(4096)
    code = resp.split(b' ')[1].decode() if len(resp.split(b' ')) > 1 else '000'
    print(code)
except:
    print('000')
s.close()
" 2>/dev/null)
log "  HTTP version '9.9' → réponse $R"
if [ "$R" = "400" ] || [ "$R" = "505" ]; then
    pass "GBX-007.1 HTTP/9.9 → $R (version invalide rejetée)"
elif [ "$R" = "401" ] || [ "$R" = "000" ]; then
    vuln "GBX-007.1 HTTP/9.9 → $R (version arbitraire traitée normalement!)"
    info "GBX-007.1 La version HTTP n'est pas validée dans http_parser.c ou router.c"
else
    info "GBX-007.1 HTTP/9.9 → $R"
fi

log ""
log "[ GBX-007.2 HTTP/0.9 (pas de headers) ]"
R09=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
# HTTP/0.9 : juste une ligne de requête, pas de headers
req = b'POST /login\r\n\r\n'
s.send(req)
s.settimeout(3)
try:
    resp = s.recv(1024)
    code = resp.split(b' ')[1].decode() if len(resp.split(b' ')) > 1 else '000'
    print(code)
except:
    print('000')
s.close()
" 2>/dev/null)
log "  HTTP/0.9 (no version) → réponse $R09"
if [ "$R09" = "400" ]; then
    pass "GBX-007.2 HTTP/0.9 → $R09 (format invalide rejeté)"
else
    info "GBX-007.2 HTTP/0.9 → $R09"
fi

log ""
log "[ GBX-007.3 Version HTTP = chaîne aléatoire (fuzzing) ]"
R_FUZZ=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
body = b'{\"username\":\"x\",\"password\":\"y\"}'
req = b'POST /login AAAAAAAAAAAAAAAAAAAA\r\n'
req += b'Content-Type: application/json\r\n'
req += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
req += b'\r\n' + body
s.send(req)
s.settimeout(3)
try:
    resp = s.recv(1024)
    parts = resp.split(b' ')
    print(parts[1].decode() if len(parts) > 1 else '000')
except:
    print('000')
s.close()
" 2>/dev/null)
log "  HTTP version = 'AAAAAAA...' → réponse $R_FUZZ"
if [ "$R_FUZZ" = "400" ]; then
    pass "GBX-007.3 Version chaîne aléatoire → $R_FUZZ (rejeté)"
elif [ "$R_FUZZ" = "401" ]; then
    vuln "GBX-007.3 Version aléatoire 'AAAAAA' traitée → $R_FUZZ (http_parser.c ne valide pas la version)"
else
    info "GBX-007.3 Version chaîne aléatoire → $R_FUZZ"
fi

# ════════════════════════════════════════════════════════════
#  GBX-008 — LOGIN RETOURNE 201 AU LIEU DE 200 (login.c:281)
# ════════════════════════════════════════════════════════════
section "GBX-008 — Code HTTP sémantiquement incorrect (201 au lieu de 200)"

grey "login.c:281 : return 201; → 201 Created"
grey "RFC 7231    : 201 Created = 'une ressource a été créée'"
grey "            → un login crée une SESSION, pas une ressource"
grey "            → devrait retourner 200 OK"
grey "IMPACT      : clients REST strict, SDKs, middleware peuvent mal interpréter le code"

log ""
log "[ GBX-008.1 Vérification du code HTTP retourné par /login ]"
LOGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}")
log "  Code HTTP de /login sur succès : $LOGIN_CODE"
if [ "$LOGIN_CODE" -eq 201 ]; then
    vuln "GBX-008.1 /login retourne HTTP 201 (Created) au lieu de 200 (OK) — sémantique REST incorrecte"
    info "GBX-008.1 Impact : certains reverse-proxies ou clients REST stricts traitent 201 différemment de 200"
elif [ "$LOGIN_CODE" -eq 200 ]; then
    pass "GBX-008.1 /login retourne 200 OK (correct)"
else
    info "GBX-008.1 /login retourne $LOGIN_CODE"
fi

# ════════════════════════════════════════════════════════════
#  GBX-009 — UTF-8 >= 0x80 dans first_name/last_name
# ════════════════════════════════════════════════════════════
section "GBX-009 — Validation permissive first_name/last_name (register.c:185)"

grey "register.c:185: if(!isalpha(*fn_ptr) && *fn_ptr != ' ' && *fn_ptr != '-' && *fn_ptr != '\'' && (unsigned char)*fn_ptr < 0x80)"
grey "               → tout byte >= 0x80 (UTF-8 multi-octets) est ACCEPTÉ sans restriction"
grey "               → emoji, scripts exotiques (arabe, chinois, Devanagari...) passent tous"
grey "               → risque : injection visuelle (homoglyphes), données inattendues en DB"

log ""
log "[ GBX-009.1 Emoji dans first_name (bytes >= 0x80) ]"
R=$(curl -s -o /tmp/gbx009a.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"utf8_${TS}_1\",\"first_name\":\"Jean🔑\",\"last_name\":\"Dupont\",\"password\":\"P@ss1234\"}")
RESP=$(cat /tmp/gbx009a.json)
log "  first_name='Jean🔑' → HTTP $R : $RESP"
if [ "$R" -eq 201 ]; then
    vuln "GBX-009.1 Emoji accepté dans first_name (bytes >= 0x80 non filtrés dans register.c:185)"
else
    pass "GBX-009.1 Emoji dans first_name → $R (rejeté)"
fi

log ""
log "[ GBX-009.2 Cyrillique homoglyph dans first_name ]"
# А = U+0410 (Cyrillique), visuellement identique à A latin
R=$(curl -s -o /tmp/gbx009b.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"utf8_${TS}_2\",\"first_name\":\"Аdmin\",\"last_name\":\"Test\",\"password\":\"P@ss1234\"}")
log "  first_name='Аdmin' (А cyrillique) → HTTP $R"
if [ "$R" -eq 201 ]; then
    vuln "GBX-009.2 Homoglyph cyrillique accepté dans first_name → usurpation visuelle possible"
else
    pass "GBX-009.2 Cyrillique dans first_name → $R (rejeté)"
fi

log ""
log "[ GBX-009.3 Script arabe dans last_name ]"
R=$(curl -s -o /tmp/gbx009c.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"utf8_${TS}_3\",\"first_name\":\"Ahmed\",\"last_name\":\"محمد\",\"password\":\"P@ss1234\"}")
log "  last_name='محمد' (arabe) → HTTP $R"
if [ "$R" -eq 201 ]; then
    info "GBX-009.3 Script arabe accepté dans last_name (permis par le check >= 0x80)"
    info "GBX-009.3 Peut être intentionnel (support international) mais non documenté"
else
    pass "GBX-009.3 Script arabe dans last_name → $R"
fi

log ""
log "[ GBX-009.4 Séquence UTF-8 invalide (bytes mal-formés) ]"
# Bytes invalides UTF-8 : 0xFF 0xFE (non valides en UTF-8)
R=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
# Body avec un byte invalide UTF-8 (0xFF) dans first_name
body = b'{\"username\":\"gbx_bad_utf8_'
body += b'${TS}'
body += b'\",\"first_name\":\"Jean\xff\",\"last_name\":\"Test\",\"password\":\"P@ss1234\"}'
req = b'POST /register HTTP/1.1\r\n'
req += b'Host: 127.0.0.1\r\n'
req += b'Content-Type: application/json\r\n'
req += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
req += b'\r\n' + body
s.send(req)
s.settimeout(5)
try:
    resp = s.recv(1024)
    parts = resp.split(b' ')
    print(parts[1].decode() if len(parts) > 1 else '000')
except:
    print('000')
s.close()
" 2>/dev/null)
log "  first_name avec byte 0xFF (UTF-8 invalide) → HTTP $R"
if [ "$R" = "400" ]; then
    pass "GBX-009.4 Byte UTF-8 invalide 0xFF → $R (rejeté par cJSON ou handler)"
elif [ "$R" = "201" ]; then
    vuln "GBX-009.4 Byte 0xFF accepté dans first_name → données corrompues potentiellement stockées en DB"
else
    info "GBX-009.4 Byte UTF-8 invalide → HTTP $R"
fi

# ════════════════════════════════════════════════════════════
#  GBX-010 — PAS DE VALIDATION Content-Type (confirmée par code)
# ════════════════════════════════════════════════════════════
section "GBX-010 — Absence de validation Content-Type (confirmée par le code)"

grey "server.c    : aucune vérification du header Content-Type"
grey "handler/*.c : aucun appel à http_get_header(req, 'content-type')"
grey "router.c    : aucune vérification de Content-Type avant dispatch"
grey "IMPACT      : le serveur accepte n'importe quel Content-Type pourvu que le body soit du JSON valide"

log ""
log "[ GBX-010.1 Login avec Content-Type: application/xml ]"
R=$(curl -s -o /tmp/gbx010a.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/xml" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
RESP=$(cat /tmp/gbx010a.json)
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-010.1 Content-Type: application/xml avec body JSON → login réussi (aucune validation Content-Type)"
elif [ "$R" -eq 415 ] || [ "$R" -eq 400 ]; then
    pass "GBX-010.1 Content-Type: application/xml → $R (rejeté)"
else
    info "GBX-010.1 Content-Type: application/xml → HTTP $R : $RESP"
fi

log ""
log "[ GBX-010.2 Login avec Content-Type: text/html ]"
R=$(curl -s -o /tmp/gbx010b.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: text/html" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
if [ "$R" -eq 201 ]; then
    vuln "GBX-010.2 Content-Type: text/html → login réussi (HTTP $R)"
else
    pass "GBX-010.2 Content-Type: text/html → $R"
fi

log ""
log "[ GBX-010.3 Login sans Content-Type du tout ]"
R=$(curl -s -o /tmp/gbx010c.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    --http1.1 \
    --data-raw "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
RESP=$(cat /tmp/gbx010c.json)
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-010.3 Aucun Content-Type → login réussi (HTTP $R)"
elif [ "$R" -eq 415 ] || [ "$R" -eq 400 ]; then
    pass "GBX-010.3 Aucun Content-Type → $R (rejeté)"
else
    info "GBX-010.3 Aucun Content-Type → HTTP $R : $RESP"
fi

# ════════════════════════════════════════════════════════════
#  GBX-011 — BODY_MAX = 512 bytes dans router.c
# ════════════════════════════════════════════════════════════
section "GBX-011 — BODY_MAX trop petit (router.c:11)"

grey "router.c:11 : #define BODY_MAX 512"
grey "router.c:52 : char body[BODY_MAX]=\"\";"
grey "router.c:53 : http_code = route_tables[i].handler(req, body, sizeof(body))"
grey "            → le buffer de réponse est limité à 512 bytes"
grey "            → snprintf tronque silencieusement si le body > 512 bytes"
grey "            → les réponses actuelles sont < 512 bytes, mais c'est une bombe à retardement"
grey "login.c:279 : snprintf(body_out, body_out_size, \"{\\\"token\\\":\\\"%s\\\"}\",token_hex)"
grey "            → token = 64 chars → réponse = ~80 bytes → OK pour l'instant"

log ""
log "[ GBX-011.1 Vérification de la taille de la réponse de /login ]"
LOGIN_RESP=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}")
RESP_LEN=$(echo -n "$LOGIN_RESP" | wc -c | tr -d ' ')
log "  Taille réponse /login : ${RESP_LEN} bytes (limite BODY_MAX = 512)"
if [ "$RESP_LEN" -lt 512 ]; then
    info "GBX-011.1 Réponse actuelle : ${RESP_LEN} bytes < 512 (BODY_MAX). Pas de troncature pour l'instant."
    vuln "GBX-011.1 BODY_MAX=512 est une limite fragile : l'ajout de champs (exp, refresh_token...) provoquerait une troncature JSON silencieuse"
fi

log ""
log "[ GBX-011.2 Vérification : la réponse d'erreur /register est-elle tronquée ? ]"
ERR_RESP=$(curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss1234\"}")
log "  Réponse 409 /register : $ERR_RESP"
if echo "$ERR_RESP" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    pass "GBX-011.2 Réponse JSON valide (pas de troncature)"
else
    vuln "GBX-011.2 Réponse JSON malformée → troncature par BODY_MAX !"
fi

# ════════════════════════════════════════════════════════════
#  GBX-012 — Content-Length = 0 avec body réel
# ════════════════════════════════════════════════════════════
section "GBX-012 — Désynchronisation Content-Length / body réel"

grey "server.c    : bytes_restants = content_length - body_deja_recu"
grey "            → si content_length=0, pas de lecture body supplémentaire"
grey "            → mais body peut être dans le buffer de la boucle headers"
grey "server.c:352: http_parse_request(client_message, total_recu, &req)"
grey "            → parse tout ce qui est dans le buffer, y compris body sans Content-Length"

log ""
log "[ GBX-012.1 Register avec Content-Length correct vs incorrect ]"
CORRECT_BODY='{"username":"gbx_cl_test_'"${TS}"'","first_name":"Test","last_name":"Audit","password":"P@ss1234"}'
CORRECT_LEN=$(echo -n "$CORRECT_BODY" | wc -c | tr -d ' ')
WRONG_LEN=5

# Avec Content-Length correct
R_CORRECT=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: $CORRECT_LEN" \
    -d "$CORRECT_BODY" \
    --max-time 5)
log "  Content-Length correct ($CORRECT_LEN) → HTTP $R_CORRECT"

# Avec Content-Length trop petit (5) → le serveur ne lira que 5 bytes de body
BODY_CL_SHORT='{"username":"gbx_cl_short_'"${TS}"'","first_name":"T","last_name":"T","password":"P@ss1234"}'
R_SHORT=$(curl -s -o /tmp/gbx012a.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: $WRONG_LEN" \
    -d "$BODY_CL_SHORT" \
    --max-time 5)
log "  Content-Length=5 avec body de $(echo -n "$BODY_CL_SHORT" | wc -c | tr -d ' ') bytes → HTTP $R_SHORT : $(cat /tmp/gbx012a.json)"
info "GBX-012.1 Content-Length=5 → le serveur lit 5 bytes de body → JSON tronqué → rejet attendu"

# ════════════════════════════════════════════════════════════
#  GBX-013 — strtol sans borne (Content-Length overflow)
# ════════════════════════════════════════════════════════════
section "GBX-013 — Content-Length = valeur extrême (strtol overflow)"

grey "server.c:265: content_length = strtol(header_content, &endptrContent, 10)"
grey "            → strtol() retourne LONG_MAX si la valeur dépasse la capacité"
grey "            → LONG_MAX > MAX_BODY_SIZE (65536) → rejet correct"
grey "            → mais si LONG_MAX négatif (overflow signé) → potentiel bypass"

log ""
log "[ GBX-013.1 Content-Length = LONG_MAX (9223372036854775807) ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 9223372036854775807" \
    -d '{}' \
    --max-time 5)
log "  Content-Length=LONG_MAX → HTTP $R"
if [ "$R" -eq 400 ]; then
    pass "GBX-013.1 LONG_MAX → $R (rejeté, MAX_BODY_SIZE check efficace)"
elif [ "$R" -eq 000 ]; then
    vuln "GBX-013.1 LONG_MAX → timeout (serveur attend body de 9 exaoctets)"
else
    info "GBX-013.1 LONG_MAX → HTTP $R"
fi

log ""
log "[ GBX-013.2 Content-Length = LONG_MAX+1 (overflow: retourne LONG_MIN négatif) ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 9223372036854775808" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
RESP=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 9223372036854775808" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
log "  Content-Length=LONG_MAX+1 → HTTP $R : $RESP"
if [ "$R" -eq 201 ] && echo "$RESP" | grep -q "token"; then
    vuln "GBX-013.2 LONG_MAX+1 (strtol overflow vers LONG_MIN) → login réussi! Bypass du MAX_BODY_SIZE"
elif [ "$R" -eq 400 ]; then
    pass "GBX-013.2 LONG_MAX+1 → $R (rejeté)"
else
    info "GBX-013.2 LONG_MAX+1 → HTTP $R"
fi

log ""
log "[ GBX-013.3 Content-Length = texte non numérique ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Content-Length: abc" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 5)
log "  Content-Length='abc' → HTTP $R"
if [ "$R" -eq 400 ]; then
    pass "GBX-013.3 Content-Length non numérique → $R (rejeté)"
elif [ "$R" -eq 201 ]; then
    vuln "GBX-013.3 Content-Length='abc' → strtol retourne 0 → login traité comme si pas de body"
else
    info "GBX-013.3 Content-Length='abc' → HTTP $R"
fi

# ════════════════════════════════════════════════════════════
#  GBX-014 — PAS DE TLS / PAS DE HSTS
# ════════════════════════════════════════════════════════════
section "GBX-014 — Absence de TLS et HSTS"

grey "server.c:41 : socket(AF_INET, SOCK_STREAM, 0) — socket TCP brut, pas de TLS"
grey "            → toutes les communications en clair sur le réseau"
grey "            → tokens, mots de passe, usernames = interceptions possibles (MITM)"
grey "            → pas de header Strict-Transport-Security dans http_response_builder.c"

log ""
log "[ GBX-014.1 Vérification absence de header HSTS ]"
HEADERS=$(curl -s -D - -o /dev/null -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}")
if echo "$HEADERS" | grep -qi "strict-transport-security"; then
    pass "GBX-014.1 Header HSTS présent"
else
    vuln "GBX-014.1 Header Strict-Transport-Security absent — pas de TLS enforced"
fi

log ""
log "[ GBX-014.2 Vérification : transmission des credentials en clair ]"
log "  ${YELLOW}Login envoyé en HTTP clair :${RESET}"
log "  POST http://127.0.0.1:8080/login"
log "  Body : {\"username\":\"...\", \"password\":\"...\"}"
vuln "GBX-014.2 Credentials (username + password) transmis en clair (HTTP, pas HTTPS)"
vuln "GBX-014.2 Tokens d'authentification transmis en clair → vol de session possible via sniff réseau"

log ""
log "[ GBX-014.3 Vérification Permissions-Policy absent ]"
if echo "$HEADERS" | grep -qi "permissions-policy"; then
    pass "GBX-014.3 Permissions-Policy présent"
else
    info "GBX-014.3 Permissions-Policy absent (recommandé pour les APIs REST)"
fi

# ════════════════════════════════════════════════════════════
#  GBX-015 — recv(fd, buf, 0) quand buffer saturé
# ════════════════════════════════════════════════════════════
section "GBX-015 — Comportement recv(0) quand BUFFER_SIZE atteint"

grey "server.c:319: recv(client_accepted, client_message+total_recu, BUFFER_SIZE-total_recu-1, 0)"
grey "            → quand total_recu = BUFFER_SIZE-1 = 8191 :"
grey "            → recv(fd, buf+8191, 0, 0) est appelé"
grey "            → sur la plupart des OS: recv avec size=0 retourne 0"
grey "server.c:330: if(nb_octets_recus == 0) → 'Client disconnected!' → close()"
grey "            → faux positif : connexion légitime fermée si headers+body ~= 8192 bytes"

log ""
log "[ GBX-015.1 Requête avec headers de grande taille (proche de BUFFER_SIZE) ]"
# Créer un header custom de 7000 bytes pour approcher BUFFER_SIZE avec le body
LONG_HEADER=$(python3 -c "print('X-Custom: ' + 'A'*7000)")
R=$(curl -s -o /tmp/gbx015a.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "$LONG_HEADER" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}" \
    --max-time 8)
log "  Header X-Custom de 7000 chars → HTTP $R"
if [ "$R" -eq 400 ]; then
    pass "GBX-015.1 Headers trop grands → $R (rejeté correctement par 'headers too big' check)"
elif [ "$R" -eq 000 ]; then
    vuln "GBX-015.1 Headers 7000 chars → connexion coupée / timeout (recv(0) bug potentiel)"
else
    info "GBX-015.1 Headers 7000 chars → HTTP $R"
fi

log ""
log "[ GBX-015.2 Headers qui font exactement BUFFER_SIZE-1 bytes ]"
# BUFFER_SIZE = 8192 : crafting headers to total exactly 8191 bytes
# Format minimal: "POST /login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: X\r\nX-Pad: AAAA...\r\n\r\n"
# = ~100 bytes de headers fixes + body. On pad avec X-Pad.
TARGET_HEADER_SIZE=8000
PAD_SIZE=$((TARGET_HEADER_SIZE - 30))
PAD=$(python3 -c "print('A' * $PAD_SIZE)")
R=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 8080))
body = b'{\"username\":\"${GBX_USER}\",\"password\":\"${GBX_PASS}\"}'
pad = b'A' * $PAD_SIZE
req = b'POST /login HTTP/1.1\r\n'
req += b'Host: 127.0.0.1:8080\r\n'
req += b'Content-Type: application/json\r\n'
req += b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
req += b'X-Pad: ' + pad + b'\r\n'
req += b'\r\n'
req += body
print(f'Total request size: {len(req)} bytes', flush=True)
import sys
if len(req) > 8192:
    # Truncate headers to avoid 'headers too big' but keep body separate
    pass
s.send(req)
s.settimeout(8)
try:
    resp = s.recv(4096)
    parts = resp.split(b' ')
    print(parts[1].decode() if len(parts) > 1 else '000')
except Exception as e:
    print('000')
s.close()
" 2>/dev/null | tail -1)
log "  Requête avec pad de ${PAD_SIZE} bytes → HTTP $R"
if [ "$R" = "400" ]; then
    pass "GBX-015.2 Grande requête → $R (rejeté)"
elif [ "$R" = "000" ]; then
    vuln "GBX-015.2 Grande requête → pas de réponse (recv(0) appelé → serveur pense client déconnecté)"
else
    info "GBX-015.2 Grande requête → HTTP $R"
fi

# ════════════════════════════════════════════════════════════
#  SECTION BONUS — Vérifications complémentaires grey box
# ════════════════════════════════════════════════════════════
section "BONUS — Vérifications complémentaires"

log "[ BONUS-1 Login avec password = 255 chars (proche PASSWORD_HASH_MAX) ]"
grey "login.c:111: strlen(pwd) > PASSWORD_HASH_MAX-1 (= 255) → rejet"
grey "           → exactement 255 chars doit passer"
PASS_255=$(python3 -c "print('A'*252 + '@a1')")
R=$(curl -s -o /tmp/gbx_bonus1.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${PASS_255}\"}" \
    --max-time 5)
log "  password=255 chars → HTTP $R"
if [ "$R" -eq 401 ]; then
    pass "BONUS-1 Password 255 chars → 401 (traité, non rejeté pour longueur)"
elif [ "$R" -eq 400 ]; then
    info "BONUS-1 Password 255 chars → 400 (rejeté à tort — vérifier la limite)"
else
    info "BONUS-1 Password 255 chars → HTTP $R"
fi

log ""
log "[ BONUS-2 Login avec password = 256 chars (= PASSWORD_HASH_MAX, doit être rejeté) ]"
PASS_256=$(python3 -c "print('A'*253 + '@a1')")
R=$(curl -s -o /tmp/gbx_bonus2.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${GBX_USER}\",\"password\":\"${PASS_256}\"}" \
    --max-time 5)
log "  password=256 chars → HTTP $R"
if [ "$R" -eq 400 ]; then
    pass "BONUS-2 Password 256 chars → 400 (rejeté correctement, > PASSWORD_HASH_MAX-1)"
elif [ "$R" -eq 401 ]; then
    info "BONUS-2 Password 256 chars → 401 (traité — vérifier la borne exacte)"
else
    info "BONUS-2 Password 256 chars → HTTP $R"
fi

log ""
log "[ BONUS-3 Race condition sur /register (double register simultané) ]"
grey "register.c : l'unicité est gérée par la contrainte UNIQUE de MySQL (errno 1062)"
grey "           → race condition entre 2 INSERT simultanés → le 2nd retourne 409"
RACE_USER="race_${TS}"
(curl -s -o /tmp/gbx_race1.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${RACE_USER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss1234\"}" > /tmp/gbx_race1_code.txt) &
(curl -s -o /tmp/gbx_race2.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${RACE_USER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss1234\"}" > /tmp/gbx_race2_code.txt) &
wait
R1=$(cat /tmp/gbx_race1_code.txt 2>/dev/null || echo "000")
R2=$(cat /tmp/gbx_race2_code.txt 2>/dev/null || echo "000")
log "  Race condition register : requête 1 → HTTP $R1, requête 2 → HTTP $R2"
if [ "$R1" -eq 201 ] && [ "$R2" -eq 201 ]; then
    vuln "BONUS-3 Race condition : deux créations simultanées réussies (HTTP 201 + 201) — double utilisateur possible"
elif ([ "$R1" -eq 201 ] && [ "$R2" -eq 409 ]) || ([ "$R1" -eq 409 ] && [ "$R2" -eq 201 ]); then
    pass "BONUS-3 Race condition gérée : un 201, un 409 (contrainte MySQL UNIQUE efficace)"
else
    info "BONUS-3 Race condition → R1=$R1, R2=$R2 (serveur mono-thread peut sérialiser automatiquement)"
fi

log ""
log "[ BONUS-4 Vérification du token SHA-256 vs argon2id ]"
grey "token.c:16  : crypto_hash_sha256() — SHA-256 rapide (correct pour token haute entropie)"
grey "login.c:235 : hash_token(token_bytes, 32, ...) — les 32 bytes = 256 bits d'entropie"
grey "            → SHA-256 est approprié pour des tokens de 256 bits d'entropie (pas pour passwords)"
pass "BONUS-4 Token haché avec SHA-256 (correct pour token haute entropie 256 bits)"

# ════════════════════════════════════════════════════════════
#  RÉCAPITULATIF FINAL
# ════════════════════════════════════════════════════════════
echo ""
log "╔═════════════════════════════════════════════════════════╗"
log "║           GREY BOX AUDIT — RÉSULTAT FINAL              ║"
log "╠═════════════════════════════════════════════════════════╣"
log "║  PASS  : $(printf '%-3d' $PASS)  (tests sans anomalie)                ║"
log "║  VULNS : $(printf '%-3d' $WARN)  (failles ou risques détectés)        ║"
log "║  INFO  : $(printf '%-3d' $INFO_COUNT)  (observations non critiques)          ║"
log "╚═════════════════════════════════════════════════════════╝"
log ""
log "  Log complet : $LOG_FILE"
log ""

exit 0
