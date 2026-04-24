#!/bin/bash
# Test Vuln 8 — Buffer de hash inconsistant
#
# Ce test vérifie que le hash argon2 du mot de passe est correctement
# stocké et relu depuis la base de données, sans troncature silencieuse.
#
# Scénario testé :
#   1. Register   → le hash est inséré dans la colonne password_hash
#   2. Login OK   → crypto_pwhash_str_verify() doit retourner 0 (succès)
#   3. Login KO   → mauvais mot de passe doit retourner 401
#   4. Double register → username déjà pris doit retourner 409

BASE_URL="http://127.0.0.1:8080"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

check() {
    local description="$1"
    local expected="$2"
    local actual="$3"

    if [ "$actual" -eq "$expected" ]; then
        echo -e "${GREEN}[PASS]${RESET} $description (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}[FAIL]${RESET} $description — attendu HTTP $expected, reçu HTTP $actual"
        FAIL=$((FAIL + 1))
    fi
}

# Nom d'utilisateur unique pour éviter les conflits entre les runs
USERNAME="vuln8_test_$(date +%s)"

echo ""
echo "=== Test Vuln 8 — Password hash buffer ==="
echo "Username de test : $USERNAME"
echo ""

# ── Test 1 : Register ──────────────────────────────────────────────────────
BODY_REGISTER=$(cat <<EOF
{
  "username": "$USERNAME",
  "first_name": "Test",
  "last_name": "Vuln8",
  "password": "MotDePasseTresLong@2026!SecureEnough"
}
EOF
)

HTTP_REGISTER=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$BODY_REGISTER")

check "POST /register — créer un utilisateur" 201 "$HTTP_REGISTER"

# ── Test 2 : Login avec le bon mot de passe ────────────────────────────────
# C'est le test clé de la Vuln 8 :
# Si password_hash est tronqué en DB (VARCHAR 255 vs 256),
# crypto_pwhash_str_verify() retourne toujours -1 → 401 au lieu de 201.
BODY_LOGIN=$(cat <<EOF
{
  "username": "$USERNAME",
  "password": "MotDePasseTresLong@2026!SecureEnough"
}
EOF
)

RESPONSE_LOGIN=$(curl -s -o - -w "\n%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$BODY_LOGIN")

HTTP_LOGIN=$(echo "$RESPONSE_LOGIN" | tail -1)
BODY_LOGIN_RESP=$(echo "$RESPONSE_LOGIN" | head -1)

check "POST /login — bon mot de passe doit retourner 201" 201 "$HTTP_LOGIN"

# Vérifier que le token est présent dans la réponse
if echo "$BODY_LOGIN_RESP" | grep -q '"token"'; then
    echo -e "${GREEN}[PASS]${RESET} Le champ 'token' est présent dans la réponse"
    PASS=$((PASS + 1))
    TOKEN=$(echo "$BODY_LOGIN_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    echo "       Token reçu : ${TOKEN:0:16}... (tronqué pour affichage)"
else
    echo -e "${RED}[FAIL]${RESET} Le champ 'token' est absent de la réponse : $BODY_LOGIN_RESP"
    FAIL=$((FAIL + 1))
fi

# ── Test 3 : Login avec un mauvais mot de passe ────────────────────────────
BODY_WRONG_PWD=$(cat <<EOF
{
  "username": "$USERNAME",
  "password": "MauvaisMotDePasse"
}
EOF
)

HTTP_WRONG=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$BODY_WRONG_PWD")

check "POST /login — mauvais mot de passe doit retourner 401" 401 "$HTTP_WRONG"

# ── Test 4 : Login avec un username inexistant ─────────────────────────────
BODY_UNKNOWN=$(cat <<EOF
{
  "username": "utilisateur_qui_nexiste_pas",
  "password": "MotDePasseTresLong@2026!SecureEnough"
}
EOF
)

HTTP_UNKNOWN=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$BODY_UNKNOWN")

check "POST /login — utilisateur inconnu doit retourner 401" 401 "$HTTP_UNKNOWN"

# ── Test 5 : Double register (username déjà pris) ──────────────────────────
HTTP_DUPLICATE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$BODY_REGISTER")

check "POST /register — username dupliqué doit retourner 409" 409 "$HTTP_DUPLICATE"

# ── Test 6 : Body JSON invalide ────────────────────────────────────────────
HTTP_BAD_JSON=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "pas_du_json")

check "POST /login — JSON invalide doit retourner 400" 400 "$HTTP_BAD_JSON"

# ── Résultat final ─────────────────────────────────────────────────────────
echo ""
echo "==========================================="
TOTAL=$((PASS + FAIL))
echo "Résultat : $PASS/$TOTAL tests passés"
if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}Tous les tests passent — Vuln 8 corrigée correctement.${RESET}"
else
    echo -e "${RED}$FAIL test(s) échoué(s) — vérifier les logs du serveur.${RESET}"
fi
echo "==========================================="
echo ""
