#!/bin/bash
# Audit de sécurité — Tests d'authentification
# Cible : POST /login
# Vérifie : timing attack, brute force, tokens

BASE_URL="http://127.0.0.1:8080"
PASS=0; FAIL=0; WARN=0

TS=$(date +%s)
TEST_USER="audit_auth_$TS"
TEST_PASS="AuditPass123!"

echo ""
echo "================================================="
echo "  AUDIT — Authentification & Tokens"
echo "================================================="
echo ""

# Setup
echo "[ Setup ] Création de l'utilisateur $TEST_USER..."
CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/register -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USER\",\"first_name\":\"Audit\",\"last_name\":\"Auth\",\"password\":\"$TEST_PASS\"}")
if [ "$CODE" -ne 201 ]; then
    echo "ERREUR setup ($CODE) — abandon"
    exit 1
fi
echo "[ Setup ] OK"
echo ""

# ── Cas nominal ──
echo "[ Login valide ]"
R=$(curl -s -o /tmp/audit_auth.json -w "%{http_code}" http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}")
TOKEN=$(cat /tmp/audit_auth.json | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ "$R" -eq 201 ] && [ -n "$TOKEN" ]; then
    echo "  PASS [201] Login valide retourne un token de $(echo -n $TOKEN | wc -c | tr -d ' ') chars"
    PASS=$((PASS+1))
else
    echo "  FAIL Login valide: code=$R, token=$TOKEN"
    FAIL=$((FAIL+1))
fi

# ── Anti-timing attack ──
echo ""
echo "[ Anti-timing attack ]"
echo "  Mesure de 5 requêtes pour chaque cas..."

T_EXIST_TOTAL=0
for i in 1 2 3 4 5; do
    START=$(python3 -c "import time; print(int(time.time()*1000))")
    curl -s http://127.0.0.1:8080/login -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$TEST_USER\",\"password\":\"WrongPass\"}" > /dev/null
    END=$(python3 -c "import time; print(int(time.time()*1000))")
    T_EXIST_TOTAL=$((T_EXIST_TOTAL + END - START))
done
T_EXIST_AVG=$((T_EXIST_TOTAL / 5))

T_GHOST_TOTAL=0
for i in 1 2 3 4 5; do
    START=$(python3 -c "import time; print(int(time.time()*1000))")
    curl -s http://127.0.0.1:8080/login -X POST \
        -H "Content-Type: application/json" \
        -d '{"username":"ghost_user_xyz_999999","password":"WrongPass"}' > /dev/null
    END=$(python3 -c "import time; print(int(time.time()*1000))")
    T_GHOST_TOTAL=$((T_GHOST_TOTAL + END - START))
done
T_GHOST_AVG=$((T_GHOST_TOTAL / 5))

DIFF=$((T_EXIST_AVG - T_GHOST_AVG))
if [ "$DIFF" -lt 0 ]; then DIFF=$((-DIFF)); fi

echo "  Temps moyen (user existe, mauvais mdp) : ${T_EXIST_AVG}ms"
echo "  Temps moyen (user inexistant)           : ${T_GHOST_AVG}ms"
echo "  Écart                                   : ${DIFF}ms"

if [ "$DIFF" -lt 30 ]; then
    echo "  PASS Timing attack mitigation OK (écart < 30ms)"
    PASS=$((PASS+1))
else
    echo "  WARN Écart de ${DIFF}ms — potentiel timing leak"
    WARN=$((WARN+1))
fi

# ── Anti-enumération : même message d'erreur ──
echo ""
echo "[ Anti-énumération : messages d'erreur identiques ]"
MSG_WRONG=$(curl -s http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USER\",\"password\":\"WrongPass\"}")
MSG_GHOST=$(curl -s http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"ghost_xyz_999","password":"WrongPass"}')

if [ "$MSG_WRONG" = "$MSG_GHOST" ]; then
    echo "  PASS Même message pour mauvais mdp et user inexistant"
    PASS=$((PASS+1))
else
    echo "  FAIL Messages différents → user enumeration possible"
    echo "       mauvais mdp:    $MSG_WRONG"
    echo "       user inexistant: $MSG_GHOST"
    FAIL=$((FAIL+1))
fi

# ── VULN-04 : Brute force sans rate limiting ──
echo ""
echo "[ VULN-04 — Brute force : aucun rate limiting ]"
BLOCKED=0
for i in $(seq 1 10); do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$TEST_USER\",\"password\":\"BruteForce$i\"}")
    if [ "$CODE" -eq 429 ] || [ "$CODE" -eq 403 ]; then
        BLOCKED=$((BLOCKED+1))
    fi
done

if [ "$BLOCKED" -gt 0 ]; then
    echo "  PASS $BLOCKED/10 tentatives bloquées (rate limiting présent)"
    PASS=$((PASS+1))
else
    echo "  VULN 0/10 tentatives bloquées → brute force possible sans limite"
    WARN=$((WARN+1))
fi

# ── VULN-05 : Accumulation illimitée de tokens ──
echo ""
echo "[ VULN-05 — Tokens : aucun maximum par utilisateur ]"
TOKENS=()
for i in $(seq 1 5); do
    T=$(curl -s http://127.0.0.1:8080/login -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}" | \
        grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    TOKENS+=("$T")
done

UNIQUE=$(printf "%s\n" "${TOKENS[@]}" | sort -u | wc -l | tr -d ' ')
if [ "$UNIQUE" -eq 5 ]; then
    echo "  VULN 5 logins → 5 tokens uniques créés sans limite (accumulation DB possible)"
    WARN=$((WARN+1))
else
    echo "  INFO $UNIQUE tokens uniques sur 5 logins"
fi

# ── Token entropie : longueur et unicité ──
echo ""
echo "[ Token entropie ]"
T1="${TOKENS[0]}"
T2="${TOKENS[1]}"
LEN=$(echo -n "$T1" | wc -c | tr -d ' ')
if [ "$LEN" -eq 64 ] && [ "$T1" != "$T2" ]; then
    echo "  PASS Tokens de 64 chars hex (256 bits d'entropie), uniques"
    PASS=$((PASS+1))
else
    echo "  FAIL Token anormal: len=$LEN, t1=$T1, t2=$T2"
    FAIL=$((FAIL+1))
fi

echo ""
echo "================================================="
printf "  Résultat : %d PASS  |  %d FAIL  |  %d FAILLES\n" "$PASS" "$FAIL" "$WARN"
echo "================================================="
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
