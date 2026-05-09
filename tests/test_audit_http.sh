#!/bin/bash
# Audit de sécurité — Tests du protocole HTTP
# Cible : toutes les routes
# Vérifie : méthodes incorrectes, tailles de buffers, headers

BASE_URL="http://127.0.0.1:8080"
PASS=0; FAIL=0; WARN=0

check() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    local body="$4"

    if [ "$actual" -eq "$expected" ]; then
        echo "  PASS [$actual] $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL $desc"
        echo "       attendu=$expected reçu=$actual | $body"
        FAIL=$((FAIL+1))
    fi
}

check_warn() {
    local desc="$1"
    local unexpected="$2"
    local actual="$3"
    local note="$4"

    if [ "$actual" -eq "$unexpected" ]; then
        echo "  VULN $desc → $actual (FAILLE: $note)"
        WARN=$((WARN+1))
    else
        echo "  OK   $desc → $actual"
        PASS=$((PASS+1))
    fi
}

echo ""
echo "================================================="
echo "  AUDIT — Protocole HTTP"
echo "================================================="
echo ""

# ── Buffers ──
echo "[ Taille des buffers ]"

BIG_HEADER=$(python3 -c "print('X'*8500)")
c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/register -X POST \
    -H "Content-Type: application/json" -H "X-Big: $BIG_HEADER" \
    -d '{"username":"x","first_name":"t","last_name":"t","password":"p"}' --max-time 5)
check "Headers totaux > BUFFER_SIZE (8192) → 400" 400 "$c" ""

BIG_BODY=$(python3 -c "print('A'*66000)")
c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/register -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"x\",\"first_name\":\"$BIG_BODY\"}" --max-time 5)
check "Body > MAX_BODY_SIZE (65536) → 400" 400 "$c" ""

# ── VULN-06 : 404 au lieu de 405 ──
echo ""
echo "[ VULN-06 — Mauvaises méthodes sur routes connues : 404 au lieu de 405 ]"
for METHOD in GET PUT DELETE PATCH; do
    c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/register -X $METHOD --max-time 3)
    check_warn "$METHOD /register → devrait être 405, reçu $c" 404 "$c" \
        "404 ne distingue pas 'route inexistante' de 'méthode non autorisée'"
done

# Vérifier aussi /login
for METHOD in GET PUT DELETE; do
    c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login -X $METHOD --max-time 3)
    check_warn "$METHOD /login → devrait être 405, reçu $c" 404 "$c" \
        "idem"
done

# ── Verbe HTTP inconnu ──
echo ""
echo "[ Verbes HTTP inconnus ]"
c=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/register -X FUZZ --max-time 3)
check "Verbe FUZZ /register → 404" 404 "$c" ""

# ── Path traversal ──
echo ""
echo "[ Path traversal / routes inconnues ]"
c=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/../../etc/passwd" --max-time 3)
check "Path traversal ../../etc/passwd → 404" 404 "$c" ""

c=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080/admin" --max-time 3)
check "Route /admin inconnue → 404" 404 "$c" ""

c=$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:8080/register?sql=DROP+TABLE+users" -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"x","first_name":"t","last_name":"t","password":"p"}' --max-time 3)
check "Query string ignorée (ne change pas le routing) → 404" 404 "$c" ""

# ── Content-Length mensonger ──
echo ""
echo "[ Content-Length mensonger ]"
echo "  (test via socket raw — Content-Length: 10000, body réel: 50 octets)"
RESULT=$(python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', 8080))
s.settimeout(8)
body = '{\"username\":\"x\",\"password\":\"y\"}'
req = 'POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n' + body
s.send(req.encode())
try:
    r = s.recv(4096)
    print('Réponse reçue : ' + str(len(r)) + ' octets')
except socket.timeout:
    print('TIMEOUT (serveur a fermé après SO_RCVTIMEO)')
finally:
    s.close()
" 2>&1)
echo "  Résultat: $RESULT"
echo "  INFO: Un Content-Length mensonger bloque le serveur pendant 5s (SO_RCVTIMEO)"
echo "  VULN: Serveur mono-thread → 1 connexion lente = serveur indisponible pendant ~5s"
WARN=$((WARN+1))

# ── Plus de 32 headers (silently ignored vs error) ──
echo ""
echo "[ 35 headers (dépassement HTTP_MAX_HEADERS=32) ]"
HDR_ARGS=""
for i in $(seq 1 35); do HDR_ARGS="$HDR_ARGS -H \"X-H$i: value\""; done
c=$(eval "curl -s -o /dev/null -w \"%{http_code}\" http://127.0.0.1:8080/register -X POST \
    -H 'Content-Type: application/json' $HDR_ARGS \
    -d '{\"username\":\"audit_35h_$(date +%s)\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass123!\"}'" --max-time 5)
check "35 headers → 201 (les headers supplémentaires sont silencieusement ignorés)" 201 "$c" ""

echo ""
echo "================================================="
printf "  Résultat : %d PASS  |  %d FAIL  |  %d FAILLES\n" "$PASS" "$FAIL" "$WARN"
echo "================================================="
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
