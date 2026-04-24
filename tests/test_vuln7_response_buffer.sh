#!/bin/bash
# Tests de non-régression pour la Vuln 7 :
# "Buffer de réponse HTTP trop petit"
#
# Principe : l'ancienne implémentation utilisait un buffer fixe de 1024 bytes.
# Si headers + body > 1024 bytes, snprintf tronquait silencieusement mais
# Content-Length annonçait la vraie taille → client bloqué ou réponse malformée.
#
# Ces tests vérifient que Content-Length = taille réelle du body reçu,
# sur tous les types de réponses (2xx, 4xx, 5xx).

BASE_URL="http://127.0.0.1:8080"
PASS=0
FAIL=0
HEADERS_FILE="/tmp/vuln7_headers.txt"

TEST_USERNAME="vuln7_user_$(date +%s)"
TEST_PASSWORD="Str0ng!Pass123"

# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

# Vérifie que Content-Length dans les headers == taille réelle du body reçu
check_content_length() {
    local description="$1"
    local method="$2"
    local endpoint="$3"
    local body="$4"

    actual_body=$(curl -s -D "$HEADERS_FILE" \
        -X "$method" "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$body")

    actual_body_len=${#actual_body}
    content_length=$(grep -i "^Content-Length:" "$HEADERS_FILE" | awk '{print $2}' | tr -d '\r')

    if [ -z "$content_length" ]; then
        echo "❌ FAIL $description"
        echo "        Content-Length absent des headers"
        FAIL=$((FAIL + 1))
        return
    fi

    if [ "$actual_body_len" -eq "$content_length" ]; then
        echo "✅ PASS $description"
        echo "        Content-Length=$content_length bytes == body reçu=$actual_body_len bytes"
        PASS=$((PASS + 1))
    else
        echo "❌ FAIL $description"
        echo "        Content-Length=$content_length bytes != body reçu=$actual_body_len bytes"
        echo "        body: $actual_body"
        FAIL=$((FAIL + 1))
    fi
}

# Vérifie le code HTTP ET la cohérence Content-Length
run_test() {
    local description="$1"
    local expected_code="$2"
    local method="$3"
    local endpoint="$4"
    local body="$5"

    actual_body=$(curl -s -D "$HEADERS_FILE" -w "" \
        -X "$method" "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$body")

    http_code=$(grep "^HTTP/" "$HEADERS_FILE" | awk '{print $2}' | tr -d '\r')
    actual_body_len=${#actual_body}
    content_length=$(grep -i "^Content-Length:" "$HEADERS_FILE" | awk '{print $2}' | tr -d '\r')

    code_ok=false
    length_ok=false

    [ "$http_code" -eq "$expected_code" ] && code_ok=true
    [ "$actual_body_len" -eq "$content_length" ] 2>/dev/null && length_ok=true

    if $code_ok && $length_ok; then
        echo "✅ PASS [$http_code] $description"
        echo "        Content-Length=$content_length bytes == body=$actual_body_len bytes"
        PASS=$((PASS + 1))
    else
        echo "❌ FAIL $description"
        $code_ok || echo "        code HTTP: attendu=$expected_code reçu=$http_code"
        $length_ok || echo "        troncature: Content-Length=$content_length != body=$actual_body_len bytes"
        echo "        body: $actual_body"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Setup : créer un utilisateur pour les tests de login
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Setup : création utilisateur de test"
echo "========================================"
curl -s -o /dev/null -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$TEST_USERNAME\",\"first_name\":\"Vuln\",\"last_name\":\"Seven\",\"password\":\"$TEST_PASSWORD\"}"
echo "Utilisateur : $TEST_USERNAME"

# ---------------------------------------------------------------------------
# Tests Vuln 7 : Content-Length = taille réelle du body
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Vuln 7 — Cohérence Content-Length"
echo "========================================"

# 2xx : réponse nominale register
run_test "POST /register → 201, body complet" \
    201 POST /register \
    "{\"username\":\"vuln7_new_$(date +%s)\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"Pass123!\"}"

# 2xx : réponse login avec token (body ~76 bytes : champ token de 64 chars hex)
run_test "POST /login → 201, token 64 chars, body complet" \
    201 POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":\"$TEST_PASSWORD\"}"

# 4xx : mauvais credentials
run_test "POST /login credentials invalides → 401, body complet" \
    401 POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":\"wrong\"}"

# 4xx : JSON invalide
run_test "POST /register JSON malformé → 400, body complet" \
    400 POST /register \
    "not_json"

# 4xx : champ manquant
run_test "POST /register champ manquant → 400, body complet" \
    400 POST /register \
    "{\"username\":\"test\"}"

# 4xx : route inexistante
run_test "GET /nonexistent → 404, body complet" \
    404 GET /nonexistent \
    ""

# 5xx : route protégée (middleware non implémenté)
run_test "POST /logout → 501, body complet" \
    501 POST /logout \
    ""

# ---------------------------------------------------------------------------
# Test spécifique : Content-Length seul (sans vérification du code)
# Simule l'ancien bug : si body > 1024 - overhead headers, troncature
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Vuln 7 — Vérification taille exacte"
echo "========================================"

check_content_length "Login : Content-Length exact sur token 64 chars" \
    POST /login \
    "{\"username\":\"$TEST_USERNAME\",\"password\":\"$TEST_PASSWORD\"}"

check_content_length "Register : Content-Length exact sur 201" \
    POST /register \
    "{\"username\":\"vuln7_size_$(date +%s)\",\"first_name\":\"Test\",\"last_name\":\"Size\",\"password\":\"Pass123!\"}"

check_content_length "404 : Content-Length exact sur Not Found" \
    GET /doesnotexist \
    ""

check_content_length "400 : Content-Length exact sur Bad Request" \
    POST /register \
    "{\"bad\":\"json\"}"

# ---------------------------------------------------------------------------
# Résumé
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
TOTAL=$((PASS + FAIL))
echo "  Résultats : $PASS/$TOTAL tests passés"
echo "========================================"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
