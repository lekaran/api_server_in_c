#!/bin/bash

BASE_URL="http://127.0.0.1:8080"
PASS=0
FAIL=0

TEST_USERNAME="profile_testuser_$(date +%s)"
TEST_PASSWORD="Test1234Z"

run_test() {
    local description="$1"
    local expected_code="$2"
    local token="$3"

    if [ -n "$token" ]; then
        actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
            -X GET "$BASE_URL/profile" \
            -H "Authorization: Bearer $token")
    else
        actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
            -X GET "$BASE_URL/profile")
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
echo "  Tests GET /profile"
echo "========================================"
echo ""

# --- Setup : créer un utilisateur de test ---
echo "[ setup ] Création de l'utilisateur : $TEST_USERNAME"
setup_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"first_name\":\"Test\",\"last_name\":\"Profile\",\"password\":\"$TEST_PASSWORD\"}")

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

# --- Sans header Authorization ---
run_test "Sans token → 401" 401 ""

# --- Token malformé (pas Bearer) ---
actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
    -X GET "$BASE_URL/profile" \
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
    -X GET "$BASE_URL/profile" \
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

# --- Cas nominal : token valide → 200 + champs attendus ---
actual_code=$(curl -s -o /tmp/test_body.json -w "%{http_code}" \
    -X GET "$BASE_URL/profile" \
    -H "Authorization: Bearer $TOKEN")
actual_body=$(cat /tmp/test_body.json)

if [ "$actual_code" -eq 200 ]; then
    echo "✅ PASS [$actual_code] Token valide → 200"
    echo "        body: $actual_body"
    PASS=$((PASS + 1))

    # Vérifier la présence des champs attendus dans le body
    for field in user_id username first_name last_name created_at updated_at; do
        if echo "$actual_body" | grep -q "\"$field\""; then
            echo "  ✅ champ '$field' présent"
            PASS=$((PASS + 1))
        else
            echo "  ❌ champ '$field' MANQUANT"
            FAIL=$((FAIL + 1))
        fi
    done

    # Vérifier que le username correspond bien à celui du setup
    if echo "$actual_body" | grep -q "\"username\":\"$TEST_USERNAME\""; then
        echo "  ✅ username correspond à $TEST_USERNAME"
        PASS=$((PASS + 1))
    else
        echo "  ❌ username ne correspond pas à $TEST_USERNAME"
        FAIL=$((FAIL + 1))
    fi

    # Vérifier que le hash de mot de passe n'est PAS exposé
    if echo "$actual_body" | grep -q "password"; then
        echo "  ❌ SECURITE : champ 'password' exposé dans la réponse !"
        FAIL=$((FAIL + 1))
    else
        echo "  ✅ champ 'password' non exposé"
        PASS=$((PASS + 1))
    fi
else
    echo "❌ FAIL Token valide → attendu 200 | reçu $actual_code"
    echo "        body: $actual_body"
    FAIL=$((FAIL + 1))
fi

# --- Token révoqué après logout ---
curl -s -o /dev/null -X POST "$BASE_URL/logout" \
    -H "Authorization: Bearer $TOKEN"

run_test "Token révoqué (après logout) → 401" 401 "$TOKEN"

echo ""
echo "========================================"
printf "  Résultat : %d PASS  |  %d FAIL\n" "$PASS" "$FAIL"
echo "========================================"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
