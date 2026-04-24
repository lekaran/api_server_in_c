#!/bin/bash
# Audit de sécurité — Tests de validation des entrées
# Cible : POST /register et POST /login
# Résultats attendus documentés pour chaque cas

BASE_URL="http://127.0.0.1:8080"
PASS=0; FAIL=0; WARN=0

run_test() {
    local desc="$1"
    local expected="$2"
    local method="$3"
    local endpoint="$4"
    local body="$5"

    actual=$(curl -s -o /tmp/audit_body.json -w "%{http_code}" \
        -X "$method" "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$body")
    body_resp=$(cat /tmp/audit_body.json)

    if [ "$actual" -eq "$expected" ]; then
        echo "  PASS [$actual] $desc"
        PASS=$((PASS+1))
    else
        echo "  FAIL $desc"
        echo "       attendu=$expected reçu=$actual | $body_resp"
        FAIL=$((FAIL+1))
    fi
}

run_warn() {
    local desc="$1"
    local unexpected="$2"
    local method="$3"
    local endpoint="$4"
    local body="$5"
    local note="$6"

    actual=$(curl -s -o /tmp/audit_body.json -w "%{http_code}" \
        -X "$method" "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$body")
    body_resp=$(cat /tmp/audit_body.json)

    if [ "$actual" -eq "$unexpected" ]; then
        echo "  VULN $desc → $actual (FAILLE: $note)"
        WARN=$((WARN+1))
    else
        echo "  OK   $desc → $actual (bloqué)"
        PASS=$((PASS+1))
    fi
}

echo ""
echo "================================================="
echo "  AUDIT — Validation des entrées"
echo "================================================="
echo ""

TS=$(date +%s)

# ── Cas nominaux ──
echo "[ Cas nominaux ]"
run_test "Register valide → 201" 201 POST /register \
    "{\"username\":\"audit_val_$TS\",\"first_name\":\"Jean\",\"last_name\":\"Dupont\",\"password\":\"Pass123!\"}"

# ── Username ──
echo ""
echo "[ Username — règles ]"
run_test "Username manquant → 400" 400 POST /register \
    '{"first_name":"T","last_name":"T","password":"Pass123!"}'
run_test "Username nombre → 400" 400 POST /register \
    '{"username":42,"first_name":"T","last_name":"T","password":"Pass123!"}'
run_test "Username caractères invalides (espace) → 400" 400 POST /register \
    '{"username":"bad user","first_name":"T","last_name":"T","password":"Pass123!"}'
run_test "Username caractères invalides (@) → 400" 400 POST /register \
    '{"username":"bad@user","first_name":"T","last_name":"T","password":"Pass123!"}'
run_test "Username vide → 401 ou 400" 401 POST /login \
    '{"username":"","password":"Pass123!"}'

LONG_UN=$(python3 -c "print('A'*51)")
run_test "Username 51 chars → 400" 400 POST /register \
    "{\"username\":\"$LONG_UN\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass123!\"}"

MAX_UN=$(python3 -c "import random,string; print(''.join(random.choices(string.ascii_lowercase,k=40)))")
run_test "Username 40 chars → 201 (sous la limite max=50)" 201 POST /register \
    "{\"username\":\"${MAX_UN}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass123!\"}"

# ── VULN-01 : first_name / last_name sans validation de longueur ──
echo ""
echo "[ VULN-01 — first_name / last_name : longueur non vérifiée ]"
LONG_NAME=$(python3 -c "print('A'*200)")

run_warn "first_name 200 chars accepté sans erreur" 201 POST /register \
    "{\"username\":\"audit_fn_$(date +%s)\",\"first_name\":\"$LONG_NAME\",\"last_name\":\"T\",\"password\":\"Pass123!\"}" \
    "silently truncated to 100 chars, no 400 returned"

run_warn "last_name 200 chars accepté sans erreur" 201 POST /register \
    "{\"username\":\"audit_ln_$(date +%s)\",\"first_name\":\"T\",\"last_name\":\"$LONG_NAME\",\"password\":\"Pass123!\"}" \
    "silently truncated to 100 chars, no 400 returned"

# ── VULN-02 : first_name / last_name sans validation de caractères ──
echo ""
echo "[ VULN-02 — first_name / last_name : caractères spéciaux acceptés ]"
run_warn "HTML injection dans first_name" 201 POST /register \
    "{\"username\":\"audit_html_$(date +%s)\",\"first_name\":\"<script>alert(1)</script>\",\"last_name\":\"T\",\"password\":\"Pass123!\"}" \
    "HTML stored in DB without sanitization"

# ── VULN-03 : Content-Type non vérifié ──
echo ""
echo "[ VULN-03 — Content-Type non vérifié ]"
actual_noCT=$(curl -s -o /tmp/audit_body.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -d "{\"username\":\"audit_noct_$(date +%s)\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass123!\"}")
if [ "$actual_noCT" -eq 201 ]; then
    echo "  VULN Content-Type manquant → $actual_noCT (FAILLE: requête traitée sans Content-Type: application/json)"
    WARN=$((WARN+1))
else
    echo "  OK   Content-Type manquant → $actual_noCT (bloqué)"
    PASS=$((PASS+1))
fi

# ── Password ──
echo ""
echo "[ Password — règles ]"
run_test "Password manquant → 400" 400 POST /register \
    '{"username":"audit_nopwd","first_name":"T","last_name":"T"}'
run_test "Password boolean → 400" 400 POST /register \
    '{"username":"audit_boolpwd","first_name":"T","last_name":"T","password":true}'

OVER_PWD=$(python3 -c "print('A'*256)")
run_test "Password 256 chars → 400" 400 POST /register \
    "{\"username\":\"audit_ovpwd\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"$OVER_PWD\"}"

MAX_PWD=$(python3 -c "print('A'*255)")
run_test "Password 255 chars → 201 (limite max)" 201 POST /register \
    "{\"username\":\"audit_maxpwd_$TS\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"$MAX_PWD\"}"

# ── JSON ──
echo ""
echo "[ JSON malformé ]"
run_test "JSON invalide → 400" 400 POST /register '{pas du json'
run_test "Body vide → 400" 400 POST /register ''

echo ""
echo "================================================="
printf "  Résultat : %d PASS  |  %d FAIL  |  %d FAILLES\n" "$PASS" "$FAIL" "$WARN"
echo "================================================="
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
