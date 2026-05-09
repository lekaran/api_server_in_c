#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 03 - AUTHENTICATION ATTACKS
# Brute force, credential stuffing, auth bypass,
# account enumeration, timing attacks, JWT attacks
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/bb_03_auth_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }

IP_COUNTER=200
next_ip() { IP_COUNTER=$((IP_COUNTER+1)); echo "172.16.$((IP_COUNTER/254)).$((IP_COUNTER%254+1))"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 03 - AUTHENTICATION ATTACKS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# SETUP: Créer un utilisateur de test valide
# ============================================================
echo "--- [SETUP] Création d'un utilisateur valide pour les tests ---" | tee -a "$RESULTS_FILE"
SETUP_IP=$(next_ip)
SETUP_RESP=$(curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $SETUP_IP" \
    -d '{"username":"victim_user","first_name":"Vic","last_name":"Tim","password":"Sup3rS3cur3!"}' 2>/dev/null)
echo "  Setup register: $SETUP_RESP" | tee -a "$RESULTS_FILE"
sleep 1

# ============================================================
# 1. BRUTE FORCE /login
# ============================================================
echo "" | tee -a "$RESULTS_FILE"
echo "--- [1] BRUTE FORCE /login ---" | tee -a "$RESULTS_FILE"
COMMON_PASSWORDS=(
    "password" "password123" "123456" "admin" "admin123"
    "qwerty" "letmein" "welcome" "monkey" "dragon"
    "master" "123456789" "12345678" "1234567" "12345"
    "000000" "111111" "abc123" "password1" "iloveyou"
    "passw0rd" "pass123" "root" "toor" "test"
    "test123" "user" "login" "default" "changeme"
    "P@ssw0rd" "P@ssword1" "Passw0rd!" "Admin@123"
    "Sup3rS3cur3!" "VictimPass1!" "correcthorsebatterystaple"
)
FOUND_CREDS=""
for PWD in "${COMMON_PASSWORDS[@]}"; do
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/auth_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"victim_user\",\"password\":\"$PWD\"}" 2>/dev/null)
    BODY=$(cat /tmp/auth_body.txt 2>/dev/null)
    if [ "$RESP" = "200" ] && echo "$BODY" | grep -qi "token\|success\|welcome"; then
        log_vuln "[BRUTE] Mot de passe trouvé: '$PWD' → HTTP $RESP | $BODY"
        FOUND_CREDS="$PWD"
        break
    elif [ "$RESP" = "200" ]; then
        log_vuln "[BRUTE] HTTP 200 pour pwd='$PWD' | $BODY"
    fi
    sleep 0.3
done
[ -z "$FOUND_CREDS" ] && log_pass "[BRUTE] Aucun mot de passe commun n'a fonctionné"

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. ACCOUNT ENUMERATION (timing attack)
# ============================================================
echo "--- [2] ACCOUNT ENUMERATION (timing) ---" | tee -a "$RESULTS_FILE"
# Un user qui existe vs un qui n'existe pas - mesurer le delta de temps
TIMES_EXIST=()
TIMES_NOEXIST=()

echo "  Mesure temps réponse pour utilisateur EXISTANT:" | tee -a "$RESULTS_FILE"
for i in $(seq 1 5); do
    IP=$(next_ip)
    TIME=$(curl -s -o /dev/null -w "%{time_total}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d '{"username":"victim_user","password":"wrongpassword_xyz"}' 2>/dev/null)
    echo "    run $i: ${TIME}s" | tee -a "$RESULTS_FILE"
    TIMES_EXIST+=("$TIME")
    sleep 0.5
done

echo "  Mesure temps réponse pour utilisateur INEXISTANT:" | tee -a "$RESULTS_FILE"
for i in $(seq 1 5); do
    IP=$(next_ip)
    TIME=$(curl -s -o /dev/null -w "%{time_total}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d '{"username":"this_user_does_not_exist_xyz789","password":"wrongpassword_xyz"}' 2>/dev/null)
    echo "    run $i: ${TIME}s" | tee -a "$RESULTS_FILE"
    TIMES_NOEXIST+=("$TIME")
    sleep 0.5
done
log_info "[TIMING] Comparer manuellement les temps - si delta > 50ms → énumération possible"

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. MESSAGES D'ERREUR DIFFÉRENTS (énumération par réponse)
# ============================================================
echo "--- [3] ÉNUMÉRATION VIA MESSAGES D'ERREUR ---" | tee -a "$RESULTS_FILE"
IP1=$(next_ip); IP2=$(next_ip)
RESP_EXIST=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP1" \
    -d '{"username":"victim_user","password":"wrongpassword"}' 2>/dev/null)
sleep 0.5
RESP_NOEXIST=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP2" \
    -d '{"username":"this_user_does_not_exist_xyz789","password":"wrongpassword"}' 2>/dev/null)

echo "  Réponse user EXISTANT avec mauvais pwd: $RESP_EXIST" | tee -a "$RESULTS_FILE"
echo "  Réponse user INEXISTANT: $RESP_NOEXIST" | tee -a "$RESULTS_FILE"

if [ "$RESP_EXIST" != "$RESP_NOEXIST" ]; then
    log_vuln "[ENUM] Messages d'erreur DIFFÉRENTS → énumération de comptes possible!"
    log_vuln "  - User existant: $RESP_EXIST"
    log_vuln "  - User inexistant: $RESP_NOEXIST"
else
    log_pass "[ENUM] Mêmes messages d'erreur → pas d'énumération via message"
fi

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. AUTH BYPASS TECHNIQUES
# ============================================================
echo "--- [4] AUTHENTICATION BYPASS ---" | tee -a "$RESULTS_FILE"
AUTH_BYPASS_PAYLOADS=(
    # Credentials vides
    '{"username":"","password":""}'
    '{"username":"victim_user","password":""}'
    '{"username":"","password":"Test1234!"}'
    # Caractères spéciaux
    '{"username":"victim_user","password":"*"}'
    '{"username":"victim_user","password":".*"}'
    '{"username":".*","password":".*"}'
    '{"username":"*","password":"*"}'
    # Null
    '{"username":null,"password":null}'
    '{"username":"victim_user","password":null}'
    # Boolean/type confusion
    '{"username":true,"password":true}'
    '{"username":"victim_user","password":true}'
    '{"username":1,"password":1}'
    # Champ password absent
    '{"username":"victim_user"}'
    # Champ username absent
    '{"password":"Test1234!"}'
    # Objet vide
    '{}'
    # Array dans credentials
    '{"username":["victim_user"],"password":["Sup3rS3cur3!"]}'
    # Unicode homoglyph (bypass de filtres)
    '{"username":"victim_user","password":"Sup3rS3cur3!"}'
)
for PAYLOAD in "${AUTH_BYPASS_PAYLOADS[@]}"; do
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/auth_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        --data-raw "$PAYLOAD" 2>/dev/null)
    BODY=$(cat /tmp/auth_body.txt 2>/dev/null)
    if [ "$RESP" = "200" ] && ! echo "$BODY" | grep -qi "invalid\|error\|unauthorized"; then
        log_vuln "[BYPASS] payload='${PAYLOAD:0:60}' → HTTP $RESP | $BODY"
    else
        log_pass "[BYPASS] ${PAYLOAD:0:60} → HTTP $RESP"
    fi
    sleep 0.4
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. JWT ATTACKS (si le serveur retourne un JWT)
# ============================================================
echo "--- [5] JWT ATTACKS ---" | tee -a "$RESULTS_FILE"
# Tenter de se connecter avec les creds valides pour obtenir un token
IP=$(next_ip)
LOGIN_RESP=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP" \
    -d '{"username":"victim_user","password":"Sup3rS3cur3!"}' 2>/dev/null)
echo "  Login avec creds valides: $LOGIN_RESP" | tee -a "$RESULTS_FILE"

TOKEN=$(echo "$LOGIN_RESP" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ -n "$TOKEN" ]; then
    log_info "Token JWT obtenu: ${TOKEN:0:50}..."

    # Décomposer le JWT
    HEADER=$(echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null || echo "$TOKEN" | cut -d'.' -f1 | base64 --decode 2>/dev/null)
    PAYLOAD_JWT=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null || echo "$TOKEN" | cut -d'.' -f2 | base64 --decode 2>/dev/null)
    echo "  JWT Header: $HEADER" | tee -a "$RESULTS_FILE"
    echo "  JWT Payload: $PAYLOAD_JWT" | tee -a "$RESULTS_FILE"

    # Test alg:none
    NONE_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_')
    NONE_PAYLOAD=$(echo -n '{"username":"admin","role":"admin"}' | base64 | tr -d '=' | tr '+/' '-_')
    NONE_TOKEN="${NONE_HEADER}.${NONE_PAYLOAD}."

    IP2=$(next_ip)
    RESP_NONE=$(curl -s -X GET "$BASE_URL/profile" \
        -H "Authorization: Bearer $NONE_TOKEN" \
        -H "X-Forwarded-For: $IP2" 2>/dev/null)
    echo "  JWT alg:none test → $RESP_NONE" | tee -a "$RESULTS_FILE"

    # Test weak secret (HS256 avec "secret")
    log_info "Token JWT présent - vérifier offline si la signature utilise un secret faible"
    echo "  Token pour test offline: $TOKEN" | tee -a "$RESULTS_FILE"
else
    log_info "[JWT] Pas de token JWT dans la réponse (ou login échoué)"
fi

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. CREDENTIAL STUFFING (paires connues)
# ============================================================
echo "--- [6] CREDENTIAL STUFFING ---" | tee -a "$RESULTS_FILE"
declare -A CRED_PAIRS=(
    ["admin"]="admin"
    ["admin"]="admin123"
    ["admin"]="password"
    ["root"]="root"
    ["root"]="toor"
    ["test"]="test"
    ["user"]="user"
    ["admin"]="Admin@123"
    ["administrator"]="administrator"
    ["victim_user"]="victim_user"
    ["superuser"]="superuser"
    ["guest"]="guest"
)
for USER in "${!CRED_PAIRS[@]}"; do
    PWD="${CRED_PAIRS[$USER]}"
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/auth_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"$USER\",\"password\":\"$PWD\"}" 2>/dev/null)
    BODY=$(cat /tmp/auth_body.txt 2>/dev/null)
    if [ "$RESP" = "200" ] && ! echo "$BODY" | grep -qi "invalid\|error\|unauthorized"; then
        log_vuln "[STUFFING] Login réussi: $USER:$PWD → $RESP | $BODY"
    else
        log_pass "[STUFFING] $USER:$PWD → $RESP"
    fi
    sleep 0.4
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 7. SESSION/TOKEN RÉUTILISATION ET FIXATION
# ============================================================
echo "--- [7] SESSION ATTACKS ---" | tee -a "$RESULTS_FILE"
# Vérifier si le Set-Cookie est présent dans les réponses
IP=$(next_ip)
COOKIE_RESP=$(curl -sI -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP" \
    -d '{"username":"victim_user","password":"Sup3rS3cur3!"}' 2>/dev/null)
echo "  Headers login réponse:" | tee -a "$RESULTS_FILE"
echo "$COOKIE_RESP" | tee -a "$RESULTS_FILE"

COOKIE=$(echo "$COOKIE_RESP" | grep -i "set-cookie:" | head -1)
if [ -n "$COOKIE" ]; then
    log_info "[SESSION] Cookie présent: $COOKIE"
    # Vérifier flags sécurité sur le cookie
    echo "$COOKIE" | grep -qi "httponly" || log_vuln "[SESSION] Cookie sans HttpOnly flag!"
    echo "$COOKIE" | grep -qi "secure" || log_vuln "[SESSION] Cookie sans Secure flag!"
    echo "$COOKIE" | grep -qi "samesite" || log_vuln "[SESSION] Cookie sans SameSite flag!"
else
    log_info "[SESSION] Pas de cookie dans la réponse"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS AUTH: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
