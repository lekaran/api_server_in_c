#!/bin/bash

BASE_URL="http://127.0.0.1:8080"
PASS=0
FAIL=0

run_test() {
    local description="$1"
    local expected_code="$2"
    local body="$3"

    actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
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
echo "  Tests POST /register"
echo "========================================"
echo ""

# --- Cas nominal ---
run_test "Inscription valide → 201" 201 \
    '{"username":"testuser_001","first_name":"John","last_name":"Doe","password":"Str0ng!Pass"}'

# --- Doublon ---
run_test "Username déjà utilisé → 409" 409 \
    '{"username":"testuser_001","first_name":"John","last_name":"Doe","password":"Str0ng!Pass"}'

# --- JSON invalide ---
run_test "JSON malformé → 400" 400 \
    '{pas du json'

# --- Champs manquants ---
run_test "username manquant → 400" 400 \
    '{"first_name":"John","last_name":"Doe","password":"Str0ng!Pass"}'

run_test "first_name manquant → 400" 400 \
    '{"username":"testuser_002","last_name":"Doe","password":"Str0ng!Pass"}'

run_test "last_name manquant → 400" 400 \
    '{"username":"testuser_003","first_name":"John","password":"Str0ng!Pass"}'

run_test "password manquant → 400" 400 \
    '{"username":"testuser_004","first_name":"John","last_name":"Doe"}'

# --- Champs présents mais pas des strings ---
run_test "username est un nombre → 400" 400 \
    '{"username":42,"first_name":"John","last_name":"Doe","password":"Str0ng!Pass"}'

run_test "password est un booléen → 400" 400 \
    '{"username":"testuser_005","first_name":"John","last_name":"Doe","password":true}'

echo ""
echo "========================================"
printf "  Résultat : %d PASS  |  %d FAIL\n" "$PASS" "$FAIL"
echo "========================================"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
