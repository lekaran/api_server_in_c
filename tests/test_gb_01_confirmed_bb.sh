#!/bin/bash
# ============================================================
# GREY BOX AUDIT - 01 - CONFIRMATION DES FINDINGS BLACK BOX
# Utilise la connaissance du code source pour reproduire
# et expliquer précisément chaque vulnérabilité BB
# ============================================================
# CONNAISSANCES DU CODE UTILISÉES :
# - server.c L.283 : strcasestr("Content-Length:") → prend le PREMIER
# - server.c L.374 : body déjà en buffer si CL=0 → body_offset correct
# - server.c L.374-404 : bytes_restants = CL - body_déjà_reçu
# - router.c L.55 : BODY_MAX = 512 octets pour la réponse handler
# - login.c  L.284 : return 201 (devrait être 200)
# - rate_limit.c L.18 : clé = "rl:{path}:{client_ip}" (IP TCP réelle)
# ============================================================

BASE_URL="http://127.0.0.1:8080"
HOST="127.0.0.1"
PORT="8080"
RESULTS_FILE="/tmp/gb_01_confirmed_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_pass()  { echo -e "${GREEN}[PASS]${NC}  $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln()  { echo -e "${RED}[VULN]${NC}  $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info()  { echo -e "${BLUE}[INFO]${NC}  $1" | tee -a "$RESULTS_FILE"; }
log_code()  { echo -e "${CYAN}[CODE]${NC}  $1" | tee -a "$RESULTS_FILE"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  GREY BOX - 01 - CONFIRMATION FINDINGS BLACK BOX" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"

# ============================================================
# BB-VULN-04 CONFIRMÉE : POST /login retourne 201 au lieu de 200
# SOURCE : login.c ligne 284 → return 201;
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [BB-04] /login retourne 201 au lieu de 200 ---" | tee -a "$RESULTS_FILE"
log_code "login.c:284 → return 201; (devrait être 200)"

# Créer un utilisateur test
curl -s -o /dev/null -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"gb_confirm01","first_name":"Grey","last_name":"Box","password":"Secure1234!"}' 2>/dev/null
sleep 1

RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"gb_confirm01","password":"Secure1234!"}' 2>/dev/null)
BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
echo "  POST /login (succès) → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
if [ "$RESP" = "201" ]; then
    log_vuln "[BB-04-CONF] login.c:284 confirm: POST /login retourne 201 (devrait être 200 OK)"
    log_code "  Fix: changer 'return 201;' en 'return 200;' dans login.c:284"
else
    log_pass "[BB-04] POST /login → $RESP (corrigé?)"
fi

sleep 1

# ============================================================
# BB-VULN-06 CONFIRMÉE : Content-Length: 0 ignoré
# SOURCE : server.c L.374-378
#   bytes_restants = content_length(0) - body_deja_recu(>0) = négatif
#   → if (bytes_restants > 0) → SKIP
#   → body déjà dans le buffer → traité quand même !
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [BB-06] Content-Length: 0 bypass ---" | tee -a "$RESULTS_FILE"
log_code "server.c:374 : bytes_restants = content_length(0) - body_deja_recu(>0) < 0"
log_code "server.c:378 : if(bytes_restants > 0) → SKIP → body déjà dans buffer → traité"

RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "Content-Length: 0" \
    -d '{"username":"gb_cl0_test","first_name":"CL","last_name":"Zero","password":"Secure1234!"}' 2>/dev/null)
BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
echo "  Content-Length:0 avec body valide → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
if [ "$RESP" = "201" ]; then
    log_vuln "[BB-06-CONF] Body traité malgré Content-Length:0 → user créé!"
    log_code "  Fix server.c: après body reading, utiliser content_length (pas body_deja_recu) pour body_len"
else
    log_pass "[BB-06] Content-Length:0 refusé → $RESP"
fi

sleep 1

# ============================================================
# BB-VULN-07 CONFIRMÉE : Double Content-Length → connexion silencieuse
# SOURCE : server.c L.283 strcasestr → prend le PREMIER CL
#   Si CL1 > CL2 : bytes_restants = CL1 - body_reçu → attend plus d'octets
#   SO_RCVTIMEO=5s déclenche si AUCUN octet pendant 5s
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [BB-07] Double Content-Length (HTTP Smuggling) ---" | tee -a "$RESULTS_FILE"
log_code "server.c:283 strcasestr() → prend le PREMIER Content-Length"
log_code "server.c:375 bytes_restants = CL_grand - body_reçu → attend des octets"
log_code "server.c:196 SO_RCVTIMEO=5s → timeout si 0 octet pendant 5s"

# CL1=9999 (grand, premier trouvé), CL2=50 (petit, réel)
# Le serveur va lire CL1=9999 bytes mais body = ~50 bytes
# Il va attendre 5s pour les octets restants (timeout) → fermeture
T_START=$(date +%s%N)
RESP=$(echo -ne "POST /register HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 9999\r\nContent-Length: 50\r\n\r\n{\"username\":\"smugtest\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"Test1234!\"}\r\n" \
    | nc -w 10 "$HOST" "$PORT" 2>/dev/null)
T_END=$(date +%s%N)
ELAPSED=$(( (T_END - T_START) / 1000000 ))
HTTP_LINE=$(echo "$RESP" | head -1 | tr -d '\r\n')
echo "  CL1=9999, CL2=50, body=~50B → $HTTP_LINE | temps=${ELAPSED}ms" | tee -a "$RESULTS_FILE"
if [ "$ELAPSED" -ge 4000 ] && [ "$ELAPSED" -le 7000 ]; then
    log_vuln "[BB-07-CONF] Double CL → serveur attend ${ELAPSED}ms (≈SO_RCVTIMEO=5s) avant timeout"
    log_code "  Fix server.c: rejeter les requêtes avec headers dupliqués (retourner 400)"
elif [ -z "$RESP" ]; then
    log_vuln "[BB-07-CONF] Double CL → connexion fermée sans réponse"
else
    log_info "[BB-07] → ${ELAPSED}ms | réponse: $HTTP_LINE"
fi

sleep 1

# ============================================================
# BB-VULN-03 CONFIRMÉE : Content-Type non validé
# SOURCE : register.c L.91 → TODO Vérification des headers que le client envoie.
#   Ce TODO n'est pas implémenté → aucune vérification Content-Type !
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [BB-03] Content-Type non validé ---" | tee -a "$RESULTS_FILE"
log_code "register.c:91 → //TODO Vérification des headers que le client envoie."
log_code "login.c:41   → //TODO Vérification des headers que le client envoie."
log_code "Ces TODO ne sont pas implémentés → aucune vérification Content-Type!"

for CT in "text/plain" "application/xml" "text/html" "application/octet-stream" ""; do
    sleep 1
    RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: $CT" \
        -d '{"username":"cttest_gb","first_name":"A","last_name":"B","password":"Secure1234!"}' 2>/dev/null)
    BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
    echo "  Content-Type='$CT' → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
    if [ "$RESP" = "201" ] || [ "$RESP" = "200" ]; then
        log_vuln "[BB-03-CONF] Content-Type='$CT' accepté → 201 (pas de vérification CT!)"
    fi
done

sleep 1

# ============================================================
# BB-VULN-05 CONFIRMÉE : /./login → comportement inattendu
# SOURCE : router.c L.26 → strcmp(route_tables[i].path, req->path)
#   http_parser.c : path copié tel quel, PAS de normalisation URL
#   /./login → ne matche PAS strcmp("/login") → devrait être 404
#   Mais retourne 401 ! → investigation...
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [BB-05] Path normalization /./login ---" | tee -a "$RESULTS_FILE"
log_code "router.c:26 → strcmp(route_tables[i].path, req->path) → PAS de normalisation"
log_code "http_parser.c:51 → path copié tel quel depuis la requête brute"
log_code "Donc /./login ne devrait PAS matcher /login → 404 attendu"

sleep 1
RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/./login" \
    -H "Content-Type: application/json" \
    -d '{"username":"pathtest","password":"Test1234!"}' 2>/dev/null)
BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
echo "  POST /./login → HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
if [ "$RESP" = "401" ] || [ "$RESP" = "200" ]; then
    log_vuln "[BB-05-CONF] /./login → $RESP (inattendu). curl normalise le path avant envoi!"
    log_info "  NOTE: curl normalise /./login en /login AVANT d'envoyer la requête"
    log_code "  Confirmation via netcat pour envoyer le path brut:"
    RAW=$(echo -ne "POST /./login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"username\":\"pathtest\",\"password\":\"Test1234!\"}" \
        | nc -w 3 "$HOST" "$PORT" 2>/dev/null)
    echo "  via nc (raw): $(echo "$RAW" | head -1 | tr -d '\r\n')" | tee -a "$RESULTS_FILE"
    BODY_RAW=$(echo "$RAW" | tail -1)
    echo "  body: $BODY_RAW" | tee -a "$RESULTS_FILE"
    if echo "$RAW" | grep -q "404"; then
        log_pass "[BB-05] Via nc: /./login → 404 (curl normalise le chemin, pas le serveur)"
    fi
else
    log_pass "[BB-05] /./login → $RESP"
fi

sleep 1

# ============================================================
# CONFIRMATION : Rate limit basé sur IP TCP (non spoofable)
# SOURCE : server.c L.182 → inet_ntop(AF_INET, &client_addr.sin_addr, ...)
#          server.c L.460 → rate_limit_check(cc_conn, req.path, client_ip)
#          rate_limit.c L.32 → key = "rl:{route}:{client_ip}"
# X-Forwarded-For est ignoré pour le rate limiting !
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [CONFIRM] Rate limit basé sur IP TCP réelle (non spoofable) ---" | tee -a "$RESULTS_FILE"
log_code "server.c:182 → inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, ...)"
log_code "server.c:460 → rate_limit_check(cc_conn, req.path, client_ip)"
log_code "X-Forwarded-For/X-Real-IP sont IGNORÉS pour le rate limiting → BIEN"

PASSED=0; BLOCKED=0
for i in $(seq 1 8); do
    RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: 10.0.0.$i" \
        -H "X-Real-IP: 192.168.0.$i" \
        -H "CF-Connecting-IP: 1.2.3.$i" \
        -d '{"username":"rltestgb","password":"test"}' 2>/dev/null)
    if echo "$(cat /tmp/gb_body.txt)" | grep -qi "rate"; then
        BLOCKED=$((BLOCKED+1))
    else
        PASSED=$((PASSED+1))
    fi
done
if [ "$BLOCKED" -gt 0 ]; then
    log_pass "[RL-NOBYPASS] Rate limit non bypassable via headers IP: $BLOCKED/8 bloquées"
    log_code "  Preuve: ip vient de tcp_addr.sin_addr, PAS des headers HTTP"
else
    log_vuln "[RL-BYPASS] X-Forwarded-For semble bypasser le rate limit!"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS BB CONFIRMÉS: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
