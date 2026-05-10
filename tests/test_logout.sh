#!/bin/bash

BASE_URL="http://127.0.0.1:8080"
PASS=0
FAIL=0

TEST_USERNAME="logout_testuser_$(date +%s)"
TEST_PASSWORD="Test1234Z"

run_test() {
    local description="$1"
    local expected_code="$2"
    local method="$3"
    local endpoint="$4"
    local token="$5"

    if [ -n "$token" ]; then
        actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
            -X "$method" "$BASE_URL$endpoint" \
            -H "Authorization: Bearer $token")
    else
        actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
            -X "$method" "$BASE_URL$endpoint")
    fi

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
echo "  Tests POST /logout"
echo "========================================"
echo ""

# --- Setup : créer un utilisateur de test ---
echo "[ setup ] Création de l'utilisateur : $TEST_USERNAME"
setup_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"first_name\":\"Test\",\"last_name\":\"Logout\",\"password\":\"$TEST_PASSWORD\"}")

if [ "$setup_code" -ne 201 ]; then
    echo "❌ Échec du setup register ($setup_code) — abandon"
    exit 1
fi
echo "[ setup ] OK"
echo ""

# --- Obtenir un token valide ---
TOKEN=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"password\":\"$TEST_PASSWORD\"}" \
    | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "❌ Échec du login (pas de token) — abandon"
    exit 1
fi
echo "[ setup ] Token obtenu : ${TOKEN:0:16}..."
echo ""

# --- Cas nominal ---
run_test "Logout valide → 200" 200 POST /logout "$TOKEN"

# --- Token déjà révoqué (rejouer le même token) ---
run_test "Token déjà révoqué → 401" 401 POST /logout "$TOKEN"

# NOTE : les tests suivants retournent 401 (et non 400) car la route est
# is_protected=1 : auth_verify intercepte avant le handler pour tout problème
# de format ou d'absence de token.

# --- Sans header Authorization (pas de token passé) ---
run_test "Sans header Authorization → 401 (intercepté par auth_verify)" 401 POST /logout ""

# --- Token malformé (pas Bearer) ---
actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
    -X POST "$BASE_URL/logout" \
    -H "Authorization: NotBearer $TOKEN")
actual_body=$(cat /tmp/test_body.json)
if [ "$actual_code" -eq 401 ]; then
    echo "✅ PASS [$actual_code] Préfixe invalide (NotBearer) → 401"
    echo "        body: $actual_body"
    PASS=$((PASS + 1))
else
    echo "❌ FAIL Préfixe invalide (NotBearer) → attendu 401 | reçu $actual_code"
    echo "        body: $actual_body"
    FAIL=$((FAIL + 1))
fi

# --- Token 64 chars valide en format mais inconnu en DB ---
FAKE_TOKEN=$(python3 -c "print('a'*64)")
actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
    -X POST "$BASE_URL/logout" \
    -H "Authorization: Bearer $FAKE_TOKEN")
actual_body=$(cat /tmp/test_body.json)
if [ "$actual_code" -eq 401 ]; then
    echo "✅ PASS [$actual_code] Token 64 chars inconnu en DB → 401"
    echo "        body: $actual_body"
    PASS=$((PASS + 1))
else
    echo "❌ FAIL Token 64 chars inconnu en DB → attendu 401 | reçu $actual_code"
    echo "        body: $actual_body"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "========================================"
printf "  Résultat : %d PASS  |  %d FAIL\n" "$PASS" "$FAIL"
echo "========================================"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
