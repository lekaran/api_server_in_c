#!/bin/bash

BASE_URL="http://127.0.0.1:8080"
PASS=0
FAIL=0

# Utilisateur créé au début et réutilisé pour tous les tests de login
TEST_USERNAME="login_testuser_$(date +%s)"
TEST_PASSWORD="Str0ng!Pass123"

run_test() {
    local description="$1"
    local expected_code="$2"
    local method="$3"
    local endpoint="$4"
    local body="$5"

    actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
        -X "$method" "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$body")

    actual_body=$(cat /tmp/test_body.json)

    if [ "$actual_code" -eq "$expected_code" ]; then
        echo "✅ PASS [$actual_code] $description"
        echo "        body: $actual_body"
        PASS=$((PASS + 1))
    else
        echo "❌ FAIL $description"
        echo "        attendu: $expected_code | reçu: $actual_code"
        echo "        body: $actual_body"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "========================================"
echo "  Tests POST /login"
echo "========================================"
echo ""

# --- Préparation : créer un utilisateur de test ---
echo "[ setup ] Création de l'utilisateur de test : $TEST_USERNAME"
setup_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"first_name\":\"Test\",\"last_name\":\"Login\",\"password\":\"$TEST_PASSWORD\"}")

if [ "$setup_code" -ne 201 ]; then
    echo "❌ Échec du setup (register retourne $setup_code) — abandon des tests"
    exit 1
fi
echo "[ setup ] OK"
echo ""

# --- Cas nominal ---
run_test "Login valide → 201 + token" 201 \
    POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":\"$TEST_PASSWORD\"}"

# --- Mauvais password ---
run_test "Mauvais password → 401" 401 \
    POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":\"WrongPassword\"}"

# --- Username inexistant ---
run_test "Username inexistant → 401" 401 \
    POST /login \
    '{"username":"ghost_user_xyz","password":"SomePass123"}'

# --- Vérification anti user-enumeration : même message pour user inexistant et mauvais mdp ---
body_wrong_pwd=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"password\":\"WrongPassword\"}")

body_no_user=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"ghost_user_xyz","password":"SomePass123"}')

if [ "$body_wrong_pwd" = "$body_no_user" ]; then
    echo "✅ PASS [security] Même message pour user inexistant et mauvais mdp (anti user-enumeration)"
    PASS=$((PASS + 1))
else
    echo "❌ FAIL [security] Messages différents → user enumeration possible"
    echo "        mauvais mdp : $body_wrong_pwd"
    echo "        user inexistant : $body_no_user"
    FAIL=$((FAIL + 1))
fi

# --- JSON invalide ---
run_test "JSON malformé → 400" 400 \
    POST /login \
    '{pas du json'

# --- Champs manquants ---
run_test "username manquant → 400" 400 \
    POST /login \
    '{"password":"Str0ng!Pass123"}'

run_test "password manquant → 400" 400 \
    POST /login \
    "{\"username\":\"$TEST_USERNAME\"}"

# --- Champs présents mais pas des strings ---
run_test "username est un nombre → 400" 400 \
    POST /login \
    '{"username":42,"password":"Str0ng!Pass123"}'

run_test "password est un booléen → 400" 400 \
    POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":true}"

# --- Body > 1024 bytes (test de l'ancien BUFFER_SIZE) ---
LONG_PWD=$(python3 -c "print('A'*600)")
run_test "Body > 1024 bytes → 401 (pas de crash)" 401 \
    POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":\"$LONG_PWD\"}"

# --- Sessions multiples : un même user peut avoir plusieurs tokens ---
token1=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"password\":\"$TEST_PASSWORD\"}" | grep -o '"token":"[^"]*"')

token2=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"password\":\"$TEST_PASSWORD\"}" | grep -o '"token":"[^"]*"')

if [ -n "$token1" ] && [ -n "$token2" ] && [ "$token1" != "$token2" ]; then
    echo "✅ PASS [security] Sessions multiples → tokens différents"
    PASS=$((PASS + 1))
else
    echo "❌ FAIL [security] Sessions multiples → tokens identiques ou absents"
    echo "        token1: $token1"
    echo "        token2: $token2"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "========================================"
printf "  Résultat : %d PASS  |  %d FAIL\n" "$PASS" "$FAIL"
echo "========================================"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
