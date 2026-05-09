#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 07 - BUSINESS LOGIC FLAWS
# Race conditions, duplicate registration, account takeover,
# username enumeration, password policy bypass
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/bb_07_business_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }

IP_COUNTER=0
next_ip() { IP_COUNTER=$((IP_COUNTER+1)); echo "192.168.$((IP_COUNTER/254+10)).$((IP_COUNTER%254+1))"; }

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 07 - BUSINESS LOGIC FLAWS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. DUPLICATE REGISTRATION (username unique?)
# ============================================================
echo "--- [1] DUPLICATE REGISTRATION ---" | tee -a "$RESULTS_FILE"
IP1=$(next_ip); IP2=$(next_ip); IP3=$(next_ip)

RESP1=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP1" \
    -d '{"username":"duptest_user","first_name":"Alice","last_name":"Smith","password":"Secure1234!"}' 2>/dev/null)
BODY1=$(cat /tmp/biz_body.txt 2>/dev/null)
echo "  1ère registration: HTTP $RESP1 | $BODY1" | tee -a "$RESULTS_FILE"
sleep 0.5

RESP2=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP2" \
    -d '{"username":"duptest_user","first_name":"Bob","last_name":"Jones","password":"DifferentPass1!"}' 2>/dev/null)
BODY2=$(cat /tmp/biz_body.txt 2>/dev/null)
echo "  2ème registration (même username): HTTP $RESP2 | $BODY2" | tee -a "$RESULTS_FILE"

if [ "$RESP2" = "201" ] || [ "$RESP2" = "200" ]; then
    log_vuln "[DUP-REG] Username dupliqué accepté! 2 comptes avec le même username créés"
else
    log_pass "[DUP-REG] Duplication refusée → HTTP $RESP2"
fi
sleep 0.5

# Variation de casse (Case sensitivity)
RESP3=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP3" \
    -d '{"username":"DUPTEST_USER","first_name":"C","last_name":"D","password":"CaseSens1!"}' 2>/dev/null)
BODY3=$(cat /tmp/biz_body.txt 2>/dev/null)
echo "  Registration avec username en MAJUSCULES: HTTP $RESP3 | $BODY3" | tee -a "$RESULTS_FILE"
[ "$RESP3" = "201" ] && log_vuln "[CASE] Username case-insensitive → compte 'DUPTEST_USER' créé alors que 'duptest_user' existe"

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. RACE CONDITION - REGISTRATION SIMULTANÉE
# ============================================================
echo "--- [2] RACE CONDITION - REGISTRATION SIMULTANÉE ---" | tee -a "$RESULTS_FILE"
log_info "10 registrations simultanées avec le même username..."
RACE_USERNAME="race_condition_user_$(date +%s)"
RACE_RESULTS=()

for i in $(seq 1 10); do
    IP=$(next_ip)
    (
        RESP=$(curl -s -o /tmp/race_body_$i.txt -w "%{http_code}" \
            -X POST "$BASE_URL/register" \
            -H "Content-Type: application/json" \
            -H "X-Forwarded-For: $IP" \
            -d "{\"username\":\"$RACE_USERNAME\",\"first_name\":\"Race$i\",\"last_name\":\"Test\",\"password\":\"Test1234!\"}" 2>/dev/null)
        echo "$RESP" > /tmp/race_result_$i.txt
    ) &
done
wait

SUCCESS_COUNT=0
for i in $(seq 1 10); do
    CODE=$(cat /tmp/race_result_$i.txt 2>/dev/null | tr -d '[:space:]')
    BODY=$(cat /tmp/race_body_$i.txt 2>/dev/null)
    echo "  Thread $i: HTTP $CODE | $BODY" | tee -a "$RESULTS_FILE"
    [ "$CODE" = "201" ] && SUCCESS_COUNT=$((SUCCESS_COUNT+1))
done

echo "  Résultat: $SUCCESS_COUNT/10 registrations réussies pour le même username" | tee -a "$RESULTS_FILE"
if [ "$SUCCESS_COUNT" -gt 1 ]; then
    log_vuln "[RACE] $SUCCESS_COUNT comptes créés simultanément avec le même username! Race condition détectée"
else
    log_pass "[RACE] Race condition gérée ($SUCCESS_COUNT succès)"
fi

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. PASSWORD POLICY BYPASS
# ============================================================
echo "--- [3] PASSWORD POLICY ---" | tee -a "$RESULTS_FILE"
declare -A PWD_TESTS=(
    ["1 char"]="a"
    ["2 chars"]="ab"
    ["3 chars"]="abc"
    ["4 chars"]="abcd"
    ["5 chars"]="abcde"
    ["6 chars"]="abcdef"
    ["vide"]=""
    ["espace seul"]=" "
    ["espaces seuls"]="     "
    ["chiffres seulement"]="123456789"
    ["minuscules seulement"]="abcdefgh"
    ["MAJUSCULES seulement"]="ABCDEFGH"
    ["sans special"]="Password1"
    ["sans chiffre"]="Password!"
    ["commun: password"]="password"
    ["commun: 123456"]="123456"
    ["unicode simple"]="pässwörD1!"
    ["emoji"]="🔑🔒🔓"
    ["null byte"]="pass\x00word"
    ["long 1000"]=$(python3 -c "print('A'*1000)" 2>/dev/null || printf 'A%.0s' $(seq 1 1000))
)
IDX=0
for TEST_LABEL in "${!PWD_TESTS[@]}"; do
    IDX=$((IDX+1))
    PWD="${PWD_TESTS[$TEST_LABEL]}"
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"pwdtest$IDX\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"$PWD\"}" 2>/dev/null)
    BODY=$(cat /tmp/biz_body.txt 2>/dev/null)
    if [ "$RESP" = "201" ]; then
        log_vuln "[PWD-POLICY] '$TEST_LABEL' accepté! HTTP $RESP"
    else
        log_pass "[PWD-POLICY] '$TEST_LABEL' refusé → HTTP $RESP"
    fi
    sleep 0.3
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. USERNAME POLICY
# ============================================================
echo "--- [4] USERNAME POLICY ---" | tee -a "$RESULTS_FILE"
USERNAME_TESTS=(
    ""
    " "
    "a"
    "ab"
    " leading_space"
    "trailing_space "
    "with space inside"
    "with\ttab"
    "with\nnewline"
    "special!@#$%^&*()"
    "emoji_😀"
    "unicode_é"
    "UPPERCASE"
    "MixedCase123"
    "very_long_username_1234567890_abcdefghijklmnop_1234567890_abcdefghijklmnop"
    "admin"
    "root"
    "administrator"
    "null"
    "undefined"
    "true"
    "false"
    "0"
    "-1"
    "../etc/passwd"
    "<script>alert(1)</script>"
    "' OR 1=1--"
)
IDX=0
for UNAME in "${USERNAME_TESTS[@]}"; do
    IDX=$((IDX+1))
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"$UNAME\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"Secure1234!\"}" 2>/dev/null)
    BODY=$(cat /tmp/biz_body.txt 2>/dev/null)
    if [ "$RESP" = "201" ] && echo "$UNAME" | grep -qE "[\x00-\x1f<>'\"]|^$|^ | $| \t"; then
        log_vuln "[USERNAME] Username invalide accepté: '${UNAME:0:40}' → HTTP $RESP"
    else
        log_info "[USERNAME] '${UNAME:0:40}' → HTTP $RESP"
    fi
    sleep 0.3
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. ACCOUNT TAKEOVER - RE-REGISTRATION D'UN COMPTE EXISTANT
# ============================================================
echo "--- [5] ACCOUNT TAKEOVER (re-registration) ---" | tee -a "$RESULTS_FILE"
IP=$(next_ip)
# Créer un compte
RESP=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP" \
    -d '{"username":"takeover_victim","first_name":"Vic","last_name":"Tim","password":"VicTimPass1!"}' 2>/dev/null)
BODY=$(cat /tmp/biz_body.txt 2>/dev/null)
echo "  Création compte victime: HTTP $RESP | $BODY" | tee -a "$RESULTS_FILE"
sleep 0.5

# Tenter de le re-créer avec un nouveau mot de passe (prise de contrôle)
IP2=$(next_ip)
RESP2=$(curl -s -o /tmp/biz_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: $IP2" \
    -d '{"username":"takeover_victim","first_name":"Attacker","last_name":"Evil","password":"AttackerPass1!"}' 2>/dev/null)
BODY2=$(cat /tmp/biz_body.txt 2>/dev/null)
echo "  Re-registration pour takeover: HTTP $RESP2 | $BODY2" | tee -a "$RESULTS_FILE"

if [ "$RESP2" = "200" ] || [ "$RESP2" = "201" ]; then
    # Vérifier si le nouveau password fonctionne
    IP3=$(next_ip)
    sleep 0.5
    LOGIN_RESP=$(curl -s -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP3" \
        -d '{"username":"takeover_victim","password":"AttackerPass1!"}' 2>/dev/null)
    echo "  Login avec nouveau password: $LOGIN_RESP" | tee -a "$RESULTS_FILE"
    echo "$LOGIN_RESP" | grep -qi "token\|success" && log_vuln "[TAKEOVER] Compte pris de contrôle via re-registration!"
fi

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. TIMING ATTACK SUR LE LOGIN (user existe vs n'existe pas)
# ============================================================
echo "--- [6] TIMING ATTACK DÉTAILLÉ ---" | tee -a "$RESULTS_FILE"
EXISTING_USER="victim_user"
NON_EXISTING_USER="zzz_this_user_does_not_exist_zzz"

echo "  Mesures pour user EXISTANT (mauvais mdp):" | tee -a "$RESULTS_FILE"
SUM_EXIST=0
for i in $(seq 1 10); do
    IP=$(next_ip)
    TIME_MS=$(curl -s -o /dev/null -w "%{time_total}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"$EXISTING_USER\",\"password\":\"wrong_password_xyz\"}" 2>/dev/null | \
        awk '{printf "%d\n", $1*1000}')
    echo "    run $i: ${TIME_MS}ms" | tee -a "$RESULTS_FILE"
    SUM_EXIST=$((SUM_EXIST + TIME_MS))
    sleep 0.5
done
AVG_EXIST=$((SUM_EXIST / 10))
echo "  Moyenne user existant: ${AVG_EXIST}ms" | tee -a "$RESULTS_FILE"

echo "  Mesures pour user INEXISTANT:" | tee -a "$RESULTS_FILE"
SUM_NOEXIST=0
for i in $(seq 1 10); do
    IP=$(next_ip)
    TIME_MS=$(curl -s -o /dev/null -w "%{time_total}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"$NON_EXISTING_USER\",\"password\":\"wrong_password_xyz\"}" 2>/dev/null | \
        awk '{printf "%d\n", $1*1000}')
    echo "    run $i: ${TIME_MS}ms" | tee -a "$RESULTS_FILE"
    SUM_NOEXIST=$((SUM_NOEXIST + TIME_MS))
    sleep 0.5
done
AVG_NOEXIST=$((SUM_NOEXIST / 10))
echo "  Moyenne user inexistant: ${AVG_NOEXIST}ms" | tee -a "$RESULTS_FILE"

DELTA=$((AVG_EXIST - AVG_NOEXIST))
[ "$DELTA" -lt 0 ] && DELTA=$((-DELTA))
echo "  Delta absolu: ${DELTA}ms" | tee -a "$RESULTS_FILE"
if [ "$DELTA" -gt 50 ]; then
    log_vuln "[TIMING] Delta de ${DELTA}ms entre user existant/inexistant → Timing attack possible (enumération)"
else
    log_pass "[TIMING] Delta acceptable: ${DELTA}ms"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS BIZ LOGIC: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
