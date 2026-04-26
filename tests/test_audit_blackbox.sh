#!/bin/bash
# ============================================================
#  AUDIT DE SÉCURITÉ — BLACK BOX
#  Cible  : http://127.0.0.1:8080  (POST /register, POST /login)
#  DB     : MySQL
#  Auteur : audit automatisé
#  Date   : 2026-04-25
# ============================================================
# Vecteurs testés :
#   1. SQL Injection (MySQL)
#   2. Security Headers & Information Disclosure
#   3. CORS
#   4. Mass Assignment & Parameter Pollution
#   5. Command Injection & SSTI
#   6. Null Bytes & Encoding Attacks
#   7. Username Case Sensitivity
#   8. HTTP Verb Tunneling
#   9. Host Header Injection
#  10. Route Discovery (wordlist)
#  11. Weak Password Policy
#  12. Response Body Analysis
# ============================================================

BASE_URL="http://127.0.0.1:8080"
PASS=0; FAIL=0; WARN=0
TS=$(date +%s)
LOG_FILE="/tmp/audit_blackbox_${TS}.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

log()     { echo -e "$@" | tee -a "$LOG_FILE"; }
section() {
    log ""
    log "${BLUE}═══════════════════════════════════════════════════${RESET}"
    log "${BLUE}  $1${RESET}"
    log "${BLUE}═══════════════════════════════════════════════════${RESET}"
    log ""
}
pass() { log "  ${GREEN}[PASS]${RESET} $1"; PASS=$((PASS+1)); }
vuln() { log "  ${YELLOW}[VULN]${RESET} $1"; WARN=$((WARN+1)); }
info() { log "  ${CYAN}[INFO]${RESET} $1"; }
fail() { log "  ${RED}[FAIL]${RESET} $1"; FAIL=$((FAIL+1)); }

# ── JSON helper : lit le champ d'une réponse JSON ──
json_field() { echo "$1" | grep -o "\"$2\":\"[^\"]*\"" | cut -d'"' -f4; }

# ════════════════════════════════════════════════════════════
#  SETUP
# ════════════════════════════════════════════════════════════
section "SETUP — Création de l'utilisateur de test"

TEST_USER="bb_audit_${TS}"
TEST_PASS="AuditBB@2026!"

SETUP_CODE=$(curl -s -o /tmp/bb_setup.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"first_name\":\"BlackBox\",\"last_name\":\"Audit\",\"password\":\"${TEST_PASS}\"}")

if [ "$SETUP_CODE" -ne 201 ]; then
    log "${RED}ERREUR setup (HTTP $SETUP_CODE) — $(cat /tmp/bb_setup.json)${RESET}"
    exit 1
fi

TOKEN=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" | \
    grep -o '"token":"[^"]*"' | cut -d'"' -f4)

log "  Utilisateur  : $TEST_USER"
log "  Token        : ${TOKEN:0:20}... ($(echo -n "$TOKEN" | wc -c | tr -d ' ') chars)"

# ════════════════════════════════════════════════════════════
#  SECTION 1 — SQL INJECTION (MySQL)
# ════════════════════════════════════════════════════════════
section "1 — SQL INJECTION (MySQL)"

# 1.1 — Login bypass classique : ' OR '1'='1
log "[ 1.1 Login bypass : ' OR '1'='1 ]"
BODY=$(printf '{"username":"'"'"' OR '"'"'1'"'"'='"'"'1'"'"' -- ","password":"x"}')
R=$(curl -s -o /tmp/bb_sqli_1.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$BODY")
RESP=$(cat /tmp/bb_sqli_1.json)
if [ "$R" -eq 201 ]; then
    vuln "1.1 Login bypass OR 1=1 réussi! Authentification bypassée (HTTP $R)"
elif echo "$RESP" | grep -qiE "mysql|syntax|sql|query|errno"; then
    vuln "1.1 Error disclosure MySQL : $RESP"
else
    pass "1.1 Login bypass OR 1=1 → $R (bloqué ou sans effet)"
fi

# 1.2 — Commentaire SQL : admin'--
log ""
log "[ 1.2 Login bypass : admin'-- ]"
R=$(curl -s -o /tmp/bb_sqli_2.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"admin'"'"'--","password":"x"}')")
RESP=$(cat /tmp/bb_sqli_2.json)
if [ "$R" -eq 201 ]; then
    vuln "1.2 SQL injection -- : login bypass admin réussi!"
elif echo "$RESP" | grep -qiE "mysql|syntax|sql|query"; then
    vuln "1.2 SQL error disclosure : $RESP"
else
    pass "1.2 SQL injection -- → $R (bloqué)"
fi

# 1.3 — Time-based blind : SLEEP(3)
log ""
log "[ 1.3 Time-based blind : ' AND SLEEP(3) -- ]"
T_START=$(python3 -c "import time; print(int(time.time()*1000))")
curl -s -o /dev/null \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"x'"'"' AND SLEEP(3) -- ","password":"y"}')" \
    --max-time 10
T_END=$(python3 -c "import time; print(int(time.time()*1000))")
T_DIFF=$((T_END - T_START))
log "  Temps de réponse : ${T_DIFF}ms (seuil alerte : 2500ms)"
if [ "$T_DIFF" -gt 2500 ]; then
    vuln "1.3 Time-based SQLi : SLEEP(3) exécuté (${T_DIFF}ms) → injection aveugle possible"
else
    pass "1.3 SLEEP(3) ignoré → ${T_DIFF}ms (pas d'injection temporelle)"
fi

# 1.4 — UNION SELECT
log ""
log "[ 1.4 UNION SELECT ]"
R=$(curl -s -o /tmp/bb_sqli_4.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"'"'"' UNION SELECT 1,2,3,4,5 -- ","password":"y"}')")
RESP=$(cat /tmp/bb_sqli_4.json)
if echo "$RESP" | grep -qE "\"[0-9]\"" || echo "$RESP" | grep -qi "union|column"; then
    vuln "1.4 UNION SELECT : réponse suspecte → $RESP"
elif [ "$R" -eq 201 ]; then
    vuln "1.4 UNION SELECT : login réussi avec injection (HTTP $R)"
else
    pass "1.4 UNION SELECT → $R (bloqué)"
fi

# 1.5 — SQL injection dans /register (champ username)
log ""
log "[ 1.5 SQL injection dans /register (username) ]"
R=$(curl -s -o /tmp/bb_sqli_5.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"sqli_reg'"'"' OR '"'"'1","first_name":"T","last_name":"T","password":"P@ss1"}')")
RESP=$(cat /tmp/bb_sqli_5.json)
if echo "$RESP" | grep -qiE "mysql|syntax|sql|error"; then
    vuln "1.5 SQL error disclosure dans /register : $RESP"
else
    pass "1.5 SQL injection /register → $R (bloqué ou sans effet)"
fi

# 1.6 — SQL injection dans le champ password (moins filtré)
log ""
log "[ 1.6 SQL injection dans le champ password ]"
R=$(curl -s -o /tmp/bb_sqli_6.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"' OR '1'='1\"}")
RESP=$(cat /tmp/bb_sqli_6.json)
if [ "$R" -eq 201 ]; then
    vuln "1.6 SQL injection password : login bypass réussi (HTTP $R)!"
elif echo "$RESP" | grep -qiE "mysql|syntax|sql|error"; then
    vuln "1.6 SQL error disclosure via password : $RESP"
else
    pass "1.6 SQL injection password → $R (bloqué)"
fi

# 1.7 — Stacked queries : '; DROP TABLE users; --
log ""
log "[ 1.7 Stacked queries : '; DROP TABLE users; -- ]"
R=$(curl -s -o /tmp/bb_sqli_7.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"x'"'"'; DROP TABLE users; -- ","password":"y"}')")
RESP=$(cat /tmp/bb_sqli_7.json)
# Test si le serveur est encore fonctionnel après
R_ALIVE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" --max-time 5)
if [ "$R_ALIVE" -ne 201 ]; then
    vuln "1.7 CRITIQUE : après stacked queries, login légitime → $R_ALIVE (table peut être corrompue)"
else
    pass "1.7 Stacked queries inoffensif → serveur intact (login légitime ok)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 2 — SECURITY HEADERS & INFORMATION DISCLOSURE
# ════════════════════════════════════════════════════════════
section "2 — SECURITY HEADERS & INFORMATION DISCLOSURE"

HEADERS=$(curl -s -D - -o /dev/null -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"hdr_probe","first_name":"T","last_name":"T","password":"P@ssw0rd!"}' 2>&1)

log "[ 2.1 Server header (version disclosure) ]"
if echo "$HEADERS" | grep -qi "^server:"; then
    SRV=$(echo "$HEADERS" | grep -i "^server:" | head -1 | tr -d '\r')
    vuln "2.1 Server header exposé : $SRV (révèle technologie/version)"
else
    pass "2.1 Pas de Server header"
fi

log ""
log "[ 2.2 X-Frame-Options (clickjacking) ]"
if echo "$HEADERS" | grep -qi "x-frame-options"; then
    pass "2.2 X-Frame-Options présent"
else
    vuln "2.2 X-Frame-Options absent → risque clickjacking"
fi

log ""
log "[ 2.3 X-Content-Type-Options (MIME sniffing) ]"
if echo "$HEADERS" | grep -qi "x-content-type-options"; then
    pass "2.3 X-Content-Type-Options présent"
else
    vuln "2.3 X-Content-Type-Options absent → risque MIME sniffing"
fi

log ""
log "[ 2.4 Content-Security-Policy ]"
if echo "$HEADERS" | grep -qi "content-security-policy"; then
    pass "2.4 Content-Security-Policy présent"
else
    vuln "2.4 Content-Security-Policy absent"
fi

log ""
log "[ 2.5 Headers complets reçus ]"
echo "$HEADERS" | grep -v "^$" | while IFS= read -r line; do
    log "    $line"
done

log ""
log "[ 2.6 Error messages — disclosure MySQL ]"
RESP=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"x'"'"'","password":"y"}')")
if echo "$RESP" | grep -qiE "mysql|sql|query|table|column|errno|exception|stack|trace|warning"; then
    vuln "2.6 Message d'erreur révèle des infos système : $RESP"
else
    pass "2.6 Messages d'erreur génériques (pas de disclosure)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 3 — CORS
# ════════════════════════════════════════════════════════════
section "3 — CORS"

log "[ 3.1 OPTIONS preflight depuis origine malveillante ]"
CORS_RESP=$(curl -s -I -X OPTIONS "$BASE_URL/register" \
    -H "Origin: http://evil.com" \
    -H "Access-Control-Request-Method: POST" \
    -H "Access-Control-Request-Headers: Content-Type")

log "  Headers CORS reçus :"
echo "$CORS_RESP" | grep -i "access-control\|origin" | while IFS= read -r line; do
    log "    $line"
done

if echo "$CORS_RESP" | grep -qi "access-control-allow-origin: \*"; then
    vuln "3.1 CORS wildcard (*) : n'importe quelle origine peut faire des requêtes"
elif echo "$CORS_RESP" | grep -qi "access-control-allow-origin: http://evil.com"; then
    vuln "3.1 CORS reflection : origine malveillante reflétée dans la réponse"
elif echo "$CORS_RESP" | grep -qi "access-control-allow-origin"; then
    ACAO=$(echo "$CORS_RESP" | grep -i "access-control-allow-origin" | head -1 | tr -d '\r')
    info "3.1 CORS origin configurée : $ACAO (vérifier si intentionnel)"
else
    pass "3.1 Pas de headers CORS → accès cross-origin non autorisé"
fi

log ""
log "[ 3.2 CORS avec Origin: null (sandbox/file://) ]"
CORS_NULL=$(curl -s -I -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "Origin: null" \
    -d '{"username":"x","password":"y"}')
if echo "$CORS_NULL" | grep -qi "access-control-allow-origin: null"; then
    vuln "3.2 Origin: null acceptée → exploitable depuis sandbox (file://)"
else
    pass "3.2 Origin: null non reflétée"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 4 — MASS ASSIGNMENT & PARAMETER POLLUTION
# ════════════════════════════════════════════════════════════
section "4 — MASS ASSIGNMENT & PARAMETER POLLUTION"

log "[ 4.1 Champs extras : role, is_admin, id ]"
MASS_USER="mass_${TS}"
R=$(curl -s -o /tmp/bb_mass.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${MASS_USER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass@123\",\"role\":\"admin\",\"is_admin\":true,\"id\":1,\"verified\":true}")
RESP=$(cat /tmp/bb_mass.json)

if [ "$R" -eq 201 ]; then
    info "4.1 Register avec role/is_admin/id extras → $R (accepté, vérifier ce qui est stocké en DB)"
    # Récupérer le token pour analyser
    MASS_TOKEN=$(curl -s -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${MASS_USER}\",\"password\":\"Pass@123\"}" | \
        grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$MASS_TOKEN" ]; then
        info "4.1 Token obtenu après mass assignment : ${MASS_TOKEN:0:20}..."
    fi
    vuln "4.1 Mass assignment : champs non déclarés (role, is_admin, id) acceptés sans erreur"
else
    pass "4.1 Mass assignment → $R (rejeté)"
fi

log ""
log "[ 4.2 HTTP Parameter Pollution — username dupliqué ]"
R=$(curl -s -o /tmp/bb_hpp.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"hpp_first","username":"admin","first_name":"T","last_name":"T","password":"Pass@123"}')
RESP=$(cat /tmp/bb_hpp.json)
info "4.2 Username dupliqué dans JSON → $R : $RESP (quel username a été utilisé ?)"

log ""
log "[ 4.3 Champs supplémentaires inconnus ignorés vs erreur ]"
R=$(curl -s -o /tmp/bb_extra.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"extra_${TS}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass@123\",\"unknown_field\":\"value\",\"__proto__\":{\"isAdmin\":true}}")
info "4.3 Prototype pollution + champs inconnus → $R : $(cat /tmp/bb_extra.json)"

# ════════════════════════════════════════════════════════════
#  SECTION 5 — COMMAND INJECTION & SSTI
# ════════════════════════════════════════════════════════════
section "5 — COMMAND INJECTION & SSTI"

log "[ 5.1 Command injection : ; ls / dans username ]"
R=$(curl -s -o /tmp/bb_cmd1.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$(printf '{"username":"test; ls /","first_name":"T","last_name":"T","password":"P@ss1"}')")
RESP=$(cat /tmp/bb_cmd1.json)
if echo "$RESP" | grep -qE "^/|bin|usr|etc|home|tmp|var"; then
    vuln "5.1 Command injection! Réponse contient des paths système : $RESP"
else
    pass "5.1 Command injection '; ls /' → $R (bloqué ou ignoré)"
fi

log ""
log "[ 5.2 Command injection : \$(id) dans password ]"
R=$(curl -s -o /tmp/bb_cmd2.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"$(id)"}')
RESP=$(cat /tmp/bb_cmd2.json)
if echo "$RESP" | grep -qiE "uid=|root|groups="; then
    vuln "5.2 Command injection! \$(id) exécuté : $RESP"
else
    pass "5.2 Command injection '\$(id)' → $R (non exécuté)"
fi

log ""
log "[ 5.3 SSTI : {{7*7}} dans first_name ]"
R=$(curl -s -o /tmp/bb_ssti.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"ssti_${TS}\",\"first_name\":\"{{7*7}}\",\"last_name\":\"T\",\"password\":\"P@ss1\"}")
RESP=$(cat /tmp/bb_ssti.json)
if echo "$RESP" | grep -q "49"; then
    vuln "5.3 SSTI! {{7*7}} évalué → 49 dans la réponse"
else
    pass "5.3 SSTI {{7*7}} → non évalué (HTTP $R)"
fi

log ""
log "[ 5.4 Backtick injection : \`whoami\` dans first_name ]"
R=$(curl -s -o /tmp/bb_btick.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"btick_${TS}\",\"first_name\":\"\`whoami\`\",\"last_name\":\"T\",\"password\":\"P@ss1\"}")
RESP=$(cat /tmp/bb_btick.json)
if echo "$RESP" | grep -qiE "root|michaelranivo|daemon|nobody"; then
    vuln "5.4 Backtick injection! \`whoami\` exécuté : $RESP"
else
    pass "5.4 Backtick injection → HTTP $R (non exécuté)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 6 — NULL BYTES & ENCODING ATTACKS
# ════════════════════════════════════════════════════════════
section "6 — NULL BYTES & ENCODING ATTACKS"

log "[ 6.1 Null byte \\u0000 dans username (JSON) ]"
R=$(curl -s -o /tmp/bb_null1.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"safe\\u0000admin\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss1\"}")
RESP=$(cat /tmp/bb_null1.json)
if [ "$R" -eq 201 ]; then
    info "6.1 Null byte \\u0000 dans username accepté → $R (vérifier ce qui est stocké : 'safe' ou 'safe\\0admin')"
    vuln "6.1 Null byte accepté sans erreur → risque de troncature C/MySQL"
else
    pass "6.1 Null byte \\u0000 → $R (rejeté)"
fi

log ""
log "[ 6.2 Unicode homoglyph : аdmin (а = U+0430 cyrillique) ]"
R=$(curl -s -o /tmp/bb_homoglyph.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"аdmin","first_name":"T","last_name":"T","password":"P@ss1"}')
RESP=$(cat /tmp/bb_homoglyph.json)
info "6.2 Username cyrillique аdmin → $R : $RESP (confusion visuelle avec 'admin')"
if [ "$R" -eq 201 ]; then
    vuln "6.2 Homoglyph accepté → usurpation visuelle d'identité possible"
fi

log ""
log "[ 6.3 URL encoding dans le body JSON : %27 OR %271 ]"
R=$(curl -s -o /tmp/bb_urlenc.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"%27 OR %271%27=%271","password":"test"}')
RESP=$(cat /tmp/bb_urlenc.json)
if [ "$R" -eq 201 ]; then
    vuln "6.3 URL-encoded SQLi décodé et exécuté → login bypass!"
else
    pass "6.3 URL encoding ignoré → $R"
fi

log ""
log "[ 6.4 Emoji et caractères Unicode larges dans password ]"
R=$(curl -s -o /tmp/bb_emoji.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"emoji_${TS}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"Pass🔑123\"}")
info "6.4 Password avec emoji → $R : $(cat /tmp/bb_emoji.json)"

# ════════════════════════════════════════════════════════════
#  SECTION 7 — USERNAME CASE SENSITIVITY
# ════════════════════════════════════════════════════════════
section "7 — USERNAME CASE SENSITIVITY"

log "[ 7.1 Register en majuscules, login en minuscules ]"
CASE_USER="CaseAudit_${TS}"
CASE_USER_LOWER=$(echo "$CASE_USER" | tr '[:upper:]' '[:lower:]')
CASE_USER_UPPER=$(echo "$CASE_USER" | tr '[:lower:]' '[:upper:]')

R_REG=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${CASE_USER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss123\"}")

R_LOWER=$(curl -s -o /tmp/bb_case_lower.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${CASE_USER_LOWER}\",\"password\":\"P@ss123\"}")

R_UPPER=$(curl -s -o /tmp/bb_case_upper.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${CASE_USER_UPPER}\",\"password\":\"P@ss123\"}")

log "  Register  '${CASE_USER}'        → $R_REG"
log "  Login     '${CASE_USER_LOWER}'  → $R_LOWER"
log "  Login     '${CASE_USER_UPPER}'  → $R_UPPER"

if [ "$R_LOWER" -eq 201 ] || [ "$R_UPPER" -eq 201 ]; then
    info "7.1 Login case-insensitive (comportement MySQL utf8 par défaut) → risque d'énumération via variantes"
    vuln "7.1 Username case-insensitive : 'admin', 'Admin', 'ADMIN' sont équivalents"
else
    pass "7.1 Login case-sensitive : casse strictement respectée"
fi

log ""
log "[ 7.2 Double registration variantes de casse ]"
R_REG2=$(curl -s -o /tmp/bb_case2.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${CASE_USER_UPPER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss123\"}")
if [ "$R_REG2" -eq 409 ] || [ "$R_REG2" -eq 400 ]; then
    pass "7.2 Registration avec casse différente rejetée → $R_REG2 (contrainte unique DB respectée)"
elif [ "$R_REG2" -eq 201 ]; then
    vuln "7.2 Deux comptes avec même username (casse différente) créés! → conflit d'identité possible"
else
    info "7.2 Registration casse différente → $R_REG2 : $(cat /tmp/bb_case2.json)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 8 — HTTP VERB TUNNELING
# ════════════════════════════════════════════════════════════
section "8 — HTTP VERB TUNNELING"

log "[ 8.1 X-HTTP-Method-Override: DELETE sur POST /register ]"
R=$(curl -s -o /tmp/bb_tunnel1.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -H "X-HTTP-Method-Override: DELETE" \
    -d '{"username":"x","first_name":"T","last_name":"T","password":"P"}')
info "8.1 X-HTTP-Method-Override: DELETE → $R : $(cat /tmp/bb_tunnel1.json)"

log ""
log "[ 8.2 X-Method-Override: PUT sur POST /login ]"
R=$(curl -s -o /tmp/bb_tunnel2.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Method-Override: PUT" \
    -d '{"username":"x","password":"y"}')
info "8.2 X-Method-Override: PUT → $R"

log ""
log "[ 8.3 _method=DELETE dans query string ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register?_method=DELETE" \
    -H "Content-Type: application/json" \
    -d '{"username":"x","first_name":"T","last_name":"T","password":"P"}')
info "8.3 ?_method=DELETE → $R"

# ════════════════════════════════════════════════════════════
#  SECTION 9 — HOST HEADER INJECTION
# ════════════════════════════════════════════════════════════
section "9 — HOST HEADER INJECTION"

log "[ 9.1 Host: evil.com ]"
R=$(curl -s -o /tmp/bb_host1.json -w "%{http_code}" \
    -X POST "http://127.0.0.1:8080/login" \
    -H "Content-Type: application/json" \
    -H "Host: evil.com" \
    -d '{"username":"x","password":"y"}' --max-time 5)
RESP=$(cat /tmp/bb_host1.json)
if echo "$RESP" | grep -qi "evil.com"; then
    vuln "9.1 Host header reflété dans la réponse → risque cache poisoning : $RESP"
else
    pass "9.1 Host: evil.com non reflété → $R"
fi

log ""
log "[ 9.2 X-Forwarded-Host: evil.com ]"
R=$(curl -s -o /tmp/bb_host2.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-Host: evil.com" \
    -d '{"username":"x","password":"y"}')
RESP=$(cat /tmp/bb_host2.json)
if echo "$RESP" | grep -qi "evil.com"; then
    vuln "9.2 X-Forwarded-Host reflété : $RESP → risque password-reset poisoning"
else
    pass "9.2 X-Forwarded-Host non reflété → $R"
fi

log ""
log "[ 9.3 X-Forwarded-For: 127.0.0.1 (spoofing IP) ]"
R=$(curl -s -o /tmp/bb_xff.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 127.0.0.1" \
    -d '{"username":"x","password":"y"}')
info "9.3 X-Forwarded-For: 127.0.0.1 → $R (contournement potentiel de rate limiting IP-based)"

# ════════════════════════════════════════════════════════════
#  SECTION 10 — ROUTE DISCOVERY
# ════════════════════════════════════════════════════════════
section "10 — ROUTE DISCOVERY"

log "[ 10.1 Scan de routes communes ]"
ROUTES=(
    "/admin" "/api" "/api/v1" "/users" "/user" "/health" "/debug"
    "/metrics" "/config" "/env" "/test" "/dev" "/swagger" "/docs"
    "/logout" "/reset-password" "/forgot-password" "/profile"
    "/v1/register" "/v1/login" "/api/register" "/api/login"
    "/register/" "/login/" "/.env" "/.git" "/server-status"
    "/status" "/ping" "/version" "/info" "/users/1" "/me"
)

FOUND_ROUTES=0
for route in "${ROUTES[@]}"; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL$route" --max-time 3)
    if [ "$CODE" -ne 404 ] && [ "$CODE" -ne 000 ]; then
        vuln "10.1 Route non documentée découverte : $route → HTTP $CODE"
        FOUND_ROUTES=$((FOUND_ROUTES+1))
    fi
done

if [ "$FOUND_ROUTES" -eq 0 ]; then
    pass "10.1 Aucune route cachée découverte parmi ${#ROUTES[@]} testées"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 11 — WEAK PASSWORD POLICY
# ════════════════════════════════════════════════════════════
section "11 — POLITIQUE MOT DE PASSE"

log "[ 11.1 Mots de passe triviaux ]"
declare -a WEAK_PWDS=("a" "123456" "password" "123456789" "qwerty" "aaaaaa" "12345678")
for pwd in "${WEAK_PWDS[@]}"; do
    UNAME="weak_$(echo "$pwd" | tr -cd '[:alnum:]')_${TS}"
    R=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${UNAME}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"${pwd}\"}")
    if [ "$R" -eq 201 ]; then
        vuln "11.1 Mot de passe trivial accepté : '${pwd}' → HTTP $R"
    else
        pass "11.1 Mot de passe '${pwd}' refusé → HTTP $R"
    fi
done

log ""
log "[ 11.2 Password = username ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"samepass_${TS}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"samepass_${TS}\"}")
if [ "$R" -eq 201 ]; then
    vuln "11.2 Password identique au username accepté → HTTP $R"
else
    pass "11.2 Password = username refusé → HTTP $R"
fi

log ""
log "[ 11.3 Password composé uniquement d'espaces ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"spaces_${TS}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"        \"}")
if [ "$R" -eq 201 ]; then
    vuln "11.3 Password = espaces accepté → HTTP $R"
else
    pass "11.3 Password = espaces refusé → HTTP $R"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 12 — RESPONSE BODY ANALYSIS
# ════════════════════════════════════════════════════════════
section "12 — ANALYSE DES RÉPONSES"

log "[ 12.1 Réponse de /register : données sensibles exposées ]"
REG_RESP=$(curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"resp_${TS}\",\"first_name\":\"Test\",\"last_name\":\"Resp\",\"password\":\"P@ss123\"}")
log "  Body /register : $REG_RESP"
if echo "$REG_RESP" | grep -qiE "password|hash|salt|argon|bcrypt|token"; then
    vuln "12.1 /register expose des données sensibles dans la réponse"
else
    pass "12.1 /register ne contient pas de hash/password/token"
fi

log ""
log "[ 12.2 Token opaque : format et entropie ]"
log "  Token : $TOKEN"
TOKEN_LEN=$(echo -n "$TOKEN" | wc -c | tr -d ' ')
if [ "$TOKEN_LEN" -ge 32 ]; then
    pass "12.2 Token longueur suffisante : ${TOKEN_LEN} chars (≥ 32)"
else
    vuln "12.2 Token trop court : ${TOKEN_LEN} chars (< 32)"
fi
if echo "$TOKEN" | grep -qE "^[0-9a-f]{64}$"; then
    pass "12.2 Token format hex 256 bits (entropie suffisante)"
elif echo "$TOKEN" | grep -q "\."; then
    info "12.2 Token semble être un JWT — analyser le payload"
fi

log ""
log "[ 12.3 Réponse d'erreur 401 : informations minimales ]"
ERR_RESP=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"nonexistent_xyz","password":"wrong"}')
log "  Body 401 : $ERR_RESP"
if echo "$ERR_RESP" | grep -qiE "mysql|sql|query|stack|trace|errno|exception|at line"; then
    vuln "12.3 Réponse 401 révèle des détails techniques"
else
    pass "12.3 Réponse 401 générique (pas de disclosure)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 13 — BRUTE FORCE & RATE LIMITING
# ════════════════════════════════════════════════════════════
section "13 — BRUTE FORCE & RATE LIMITING"

log "[ 13.1 20 tentatives de login consécutives avec mauvais mot de passe ]"
LOCK_HIT=0
for i in $(seq 1 20); do
    R=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${TEST_USER}\",\"password\":\"wrong_${i}\"}" \
        --max-time 3)
    if [ "$R" -eq 429 ] || [ "$R" -eq 423 ] || [ "$R" -eq 503 ]; then
        pass "13.1 Rate limiting déclenché après $i tentatives → HTTP $R"
        LOCK_HIT=1
        break
    fi
done
if [ "$LOCK_HIT" -eq 0 ]; then
    vuln "13.1 Aucun rate limiting détecté : 20 tentatives de login → aucun blocage (HTTP 401 indéfiniment)"
fi

log ""
log "[ 13.2 Vérification que le compte n'est pas verrouillé après les 20 tentatives ]"
R_LEGIT=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}")
if [ "$R_LEGIT" -eq 201 ]; then
    pass "13.2 Compte toujours accessible après 20 mauvais essais → pas de lockout"
else
    info "13.2 Login légitime → $R_LEGIT après 20 mauvais essais (lockout possible)"
fi

log ""
log "[ 13.3 Flood rapide : 50 registrations d'affilée ]"
FLOOD_ERRORS=0
for i in $(seq 1 50); do
    R=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"flood_${TS}_${i}\",\"first_name\":\"F\",\"last_name\":\"L\",\"password\":\"Str0ng@${i}Pass\"}" \
        --max-time 3)
    if [ "$R" -eq 429 ] || [ "$R" -eq 503 ]; then
        pass "13.3 Rate limiting sur /register déclenché à i=$i → HTTP $R"
        FLOOD_ERRORS=1
        break
    fi
done
if [ "$FLOOD_ERRORS" -eq 0 ]; then
    vuln "13.3 Aucun rate limiting sur /register : 50 comptes créés sans blocage (abus possible : spam, ressources)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 14 — MISSING FIELDS & MALFORMED JSON
# ════════════════════════════════════════════════════════════
section "14 — CHAMPS MANQUANTS & JSON MALFORMÉ"

log "[ 14.1 Register sans password ]"
R=$(curl -s -o /tmp/bb_nopass.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"nopwd_${TS}\",\"first_name\":\"T\",\"last_name\":\"T\"}")
RESP=$(cat /tmp/bb_nopass.json)
if [ "$R" -eq 400 ]; then
    pass "14.1 Register sans password → $R (rejeté correctement)"
elif [ "$R" -eq 201 ]; then
    vuln "14.1 Register sans password accepté → $R : $RESP (compte sans mot de passe!)"
else
    info "14.1 Register sans password → $R : $RESP"
fi

log ""
log "[ 14.2 Login sans username ]"
R=$(curl -s -o /tmp/bb_nouser.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"password":"P@ssword1"}')
RESP=$(cat /tmp/bb_nouser.json)
if [ "$R" -eq 400 ]; then
    pass "14.2 Login sans username → $R (rejeté correctement)"
elif [ "$R" -eq 201 ]; then
    vuln "14.2 Login sans username accepté → $R : $RESP"
else
    info "14.2 Login sans username → $R : $RESP"
fi

log ""
log "[ 14.3 Body JSON vide : {} ]"
R=$(curl -s -o /tmp/bb_empty.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{}')
RESP=$(cat /tmp/bb_empty.json)
if [ "$R" -ge 400 ] && [ "$R" -lt 500 ]; then
    pass "14.3 JSON vide {} → $R (rejeté)"
else
    vuln "14.3 JSON vide {} → $R : $RESP (comportement inattendu)"
fi

log ""
log "[ 14.4 JSON malformé ]"
R=$(curl -s -o /tmp/bb_badjson.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d 'not json at all {{{ broken')
RESP=$(cat /tmp/bb_badjson.json)
if [ "$R" -ge 400 ] && [ "$R" -lt 500 ]; then
    pass "14.4 JSON malformé → $R (rejeté)"
else
    vuln "14.4 JSON malformé accepté → $R : $RESP (crash ou comportement inattendu)"
fi

log ""
log "[ 14.5 Body vide (aucun contenu) ]"
R=$(curl -s -o /tmp/bb_nobody.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '')
RESP=$(cat /tmp/bb_nobody.json)
if [ "$R" -ge 400 ] && [ "$R" -lt 500 ]; then
    pass "14.5 Body vide → $R (rejeté)"
else
    vuln "14.5 Body vide → $R : $RESP (comportement inattendu)"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 15 — OVERSIZED PAYLOADS (Buffer Overflow / DoS)
# ════════════════════════════════════════════════════════════
section "15 — OVERSIZED PAYLOADS"

log "[ 15.1 Username de 10 000 caractères ]"
LONG_USER=$(python3 -c "print('a'*10000)")
R=$(curl -s -o /tmp/bb_longuser.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${LONG_USER}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"P@ss1234\"}" \
    --max-time 5)
RESP=$(cat /tmp/bb_longuser.json)
if [ "$R" -eq 400 ] || [ "$R" -eq 413 ]; then
    pass "15.1 Username 10 000 chars → $R (rejeté)"
elif [ "$R" -eq 201 ]; then
    vuln "15.1 Username 10 000 chars accepté → risque buffer overflow / stockage illimité"
elif [ "$R" -eq 000 ]; then
    vuln "15.1 Username 10 000 chars → serveur ne répond pas (crash ou timeout)"
else
    info "15.1 Username 10 000 chars → $R : $RESP"
fi

log ""
log "[ 15.2 Password de 1 000 caractères (bcrypt 72-byte limit) ]"
LONG_PASS=$(python3 -c "print('A'*950 + '@a1!')")
R=$(curl -s -o /tmp/bb_longpass.json -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"longpwd_${TS}\",\"first_name\":\"T\",\"last_name\":\"T\",\"password\":\"${LONG_PASS}\"}" \
    --max-time 5)
RESP=$(cat /tmp/bb_longpass.json)
if [ "$R" -eq 400 ] || [ "$R" -eq 413 ]; then
    pass "15.2 Password 1 000 chars → $R (rejeté)"
elif [ "$R" -eq 201 ]; then
    vuln "15.2 Password 1 000 chars accepté → risque bcrypt 72-byte truncation (deux passwords différents = même hash)"
    info "15.2 bcrypt tronque à 72 bytes : Aaaa...A@a1! et Bbbb...B@a1! auront le même hash si les 72 premiers bytes sont identiques"
else
    info "15.2 Password 1 000 chars → $R : $RESP"
fi

log ""
log "[ 15.3 Payload 1MB (content body DoS) ]"
BIG_BODY=$(python3 -c "import json; print(json.dumps({'username':'x','first_name':'T','last_name':'T','password':'P@ss1','extra':'A'*1000000}))")
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "$BIG_BODY" \
    --max-time 10)
if [ "$R" -eq 400 ] || [ "$R" -eq 413 ]; then
    pass "15.3 Payload 1MB → $R (rejeté ou tronqué)"
elif [ "$R" -eq 000 ]; then
    vuln "15.3 Payload 1MB → timeout/no-response (vulnérabilité DoS potentielle)"
else
    info "15.3 Payload 1MB → $R"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 16 — CONTENT-TYPE & HTTP BYPASS
# ════════════════════════════════════════════════════════════
section "16 — CONTENT-TYPE & HTTP METHOD BYPASS"

log "[ 16.1 Login sans Content-Type header ]"
R=$(curl -s -o /tmp/bb_noct.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}")
RESP=$(cat /tmp/bb_noct.json)
if [ "$R" -eq 201 ]; then
    info "16.1 Login sans Content-Type → $R (accepté — vérifier si token valide)"
elif [ "$R" -eq 400 ] || [ "$R" -eq 415 ]; then
    pass "16.1 Login sans Content-Type → $R (rejeté)"
else
    info "16.1 Login sans Content-Type → $R : $RESP"
fi

log ""
log "[ 16.2 GET sur /register (doit être rejeté) ]"
R=$(curl -s -o /tmp/bb_get.json -w "%{http_code}" \
    -X GET "$BASE_URL/register")
RESP=$(cat /tmp/bb_get.json)
if [ "$R" -eq 405 ] || [ "$R" -eq 404 ] || [ "$R" -eq 400 ]; then
    pass "16.2 GET /register → $R (méthode non autorisée, correctement rejeté)"
elif [ "$R" -eq 201 ] || [ "$R" -eq 200 ]; then
    vuln "16.2 GET /register accepté → $R (méthode non autorisée traitée comme POST)"
else
    info "16.2 GET /register → $R : $RESP"
fi

log ""
log "[ 16.3 PUT sur /login ]"
R=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PUT "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"x\",\"password\":\"y\"}")
if [ "$R" -eq 405 ] || [ "$R" -eq 404 ] || [ "$R" -eq 400 ]; then
    pass "16.3 PUT /login → $R (correctement rejeté)"
else
    info "16.3 PUT /login → $R"
fi

log ""
log "[ 16.4 Content-Type: text/plain avec body JSON valide ]"
R=$(curl -s -o /tmp/bb_textct.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: text/plain" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}")
RESP=$(cat /tmp/bb_textct.json)
if [ "$R" -eq 201 ]; then
    vuln "16.4 Content-Type: text/plain avec JSON accepté → $R (pas de validation du Content-Type)"
elif [ "$R" -eq 400 ] || [ "$R" -eq 415 ]; then
    pass "16.4 Content-Type: text/plain → $R (rejeté — validation Content-Type en place)"
else
    info "16.4 Content-Type: text/plain → $R : $RESP"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 17 — TOKEN SECURITY
# ════════════════════════════════════════════════════════════
section "17 — SÉCURITÉ DU TOKEN"

log "[ 17.1 Double login : même user → même token ou token différent ? ]"
TOKEN_2=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" | \
    grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ "$TOKEN" = "$TOKEN_2" ]; then
    vuln "17.1 Deux logins successifs retournent le MÊME token → absence de rotation de session"
else
    pass "17.1 Double login → tokens différents (rotation de session)"
fi
log "  Token 1 : ${TOKEN:0:16}..."
log "  Token 2 : ${TOKEN_2:0:16}..."

log ""
log "[ 17.2 Analyse du format de token ]"
TOKEN_LEN=$(echo -n "$TOKEN" | wc -c | tr -d ' ')
if echo "$TOKEN" | grep -qE "^[0-9a-f]{64}$"; then
    pass "17.2 Token = hex 256 bits (format sain)"
    info "17.2 Attention : token hex opaque → vérifier que c'est stocké haché en DB, pas en clair"
elif echo "$TOKEN" | grep -qE "^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"; then
    info "17.2 Token semble être un JWT — analyser le header/payload"
    JWT_HEADER=$(echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null || echo "decode error")
    JWT_PAYLOAD=$(echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null || echo "decode error")
    log "  Header  : $JWT_HEADER"
    log "  Payload : $JWT_PAYLOAD"
    if echo "$JWT_HEADER" | grep -qi '"alg":"none"'; then
        vuln "17.2 JWT avec alg:none → signature ignorée, falsification possible!"
    fi
else
    info "17.2 Token format : ${TOKEN_LEN} chars — ${TOKEN:0:20}..."
fi

log ""
log "[ 17.3 Token prédictibilité : comparer 3 tokens consécutifs ]"
TOK_A=$(curl -s -X POST "$BASE_URL/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
TOK_B=$(curl -s -X POST "$BASE_URL/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
TOK_C=$(curl -s -X POST "$BASE_URL/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
log "  Token A : $TOK_A"
log "  Token B : $TOK_B"
log "  Token C : $TOK_C"
if [ "$TOK_A" = "$TOK_B" ] && [ "$TOK_B" = "$TOK_C" ]; then
    vuln "17.3 Tokens identiques sur 3 logins consécutifs → token statique, absence d'aléatoire"
else
    pass "17.3 Tokens différents à chaque login → entropie présente"
fi

log ""
log "[ 17.4 Username enumeration : timing comparison ]"
T1=$(python3 -c "import time; print(int(time.time()*1000))")
curl -s -o /dev/null -X POST "$BASE_URL/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"${TEST_USER}\",\"password\":\"wrongpassword\"}" --max-time 5
T2=$(python3 -c "import time; print(int(time.time()*1000))")
curl -s -o /dev/null -X POST "$BASE_URL/login" -H "Content-Type: application/json" \
    -d '{"username":"user_that_definitely_does_not_exist_xyz999","password":"wrongpassword"}' --max-time 5
T3=$(python3 -c "import time; print(int(time.time()*1000))")
EXISTING_MS=$((T2 - T1))
NONEXIST_MS=$((T3 - T2))
DIFF=$((EXISTING_MS - NONEXIST_MS))
if [ "$DIFF" -lt 0 ]; then DIFF=$((-DIFF)); fi
log "  Timing user existant     : ${EXISTING_MS}ms"
log "  Timing user inexistant   : ${NONEXIST_MS}ms"
log "  Delta                    : ${DIFF}ms"
if [ "$DIFF" -gt 100 ]; then
    vuln "17.4 Timing différence > 100ms → énumération d'username possible via timing (${DIFF}ms de delta)"
else
    pass "17.4 Timing constant (~${DIFF}ms delta) → résistant à l'énumération par timing"
fi

# ════════════════════════════════════════════════════════════
#  SECTION 18 — TYPE CONFUSION & INJECTION JSON
# ════════════════════════════════════════════════════════════
section "18 — TYPE CONFUSION & INJECTION JSON"

log "[ 18.1 Username = number (integer) ]"
R=$(curl -s -o /tmp/bb_int.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":12345,"password":"test"}')
RESP=$(cat /tmp/bb_int.json)
if [ "$R" -eq 400 ]; then
    pass "18.1 Username integer → $R (type validé)"
elif [ "$R" -eq 201 ]; then
    vuln "18.1 Username integer accepté → $R (pas de validation de type)"
else
    info "18.1 Username integer → $R : $RESP"
fi

log ""
log "[ 18.2 Password = null (JSON null) ]"
R=$(curl -s -o /tmp/bb_null.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":null}')
RESP=$(cat /tmp/bb_null.json)
if [ "$R" -eq 400 ]; then
    pass "18.2 Password null → $R (rejeté)"
elif [ "$R" -eq 201 ]; then
    vuln "18.2 Password null accepté → $R : $RESP (possible bypass!"
else
    info "18.2 Password null → $R : $RESP"
fi

log ""
log "[ 18.3 Username = tableau JSON [\"admin\"] ]"
R=$(curl -s -o /tmp/bb_arr.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":["admin","root"],"password":"test"}')
RESP=$(cat /tmp/bb_arr.json)
if [ "$R" -eq 400 ]; then
    pass "18.3 Username array → $R (type validé)"
elif [ "$R" -eq 201 ]; then
    vuln "18.3 Username array accepté → $R (type confusion — quel username a été utilisé?)"
else
    info "18.3 Username array → $R : $RESP"
fi

log ""
log "[ 18.4 Password = objet JSON ]"
R=$(curl -s -o /tmp/bb_obj.json -w "%{http_code}" \
    -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":{"gt":""}}'  )
RESP=$(cat /tmp/bb_obj.json)
if [ "$R" -eq 400 ]; then
    pass "18.4 Password objet JSON → $R (rejeté — résistant NoSQL-style injection)"
elif [ "$R" -eq 201 ]; then
    vuln "18.4 Password objet JSON accepté → $R : $RESP (injection NoSQL-style!)"
else
    info "18.4 Password objet JSON → $R : $RESP"
fi

# ════════════════════════════════════════════════════════════
#  RÉCAPITULATIF FINAL
# ════════════════════════════════════════════════════════════
echo ""
log "╔═══════════════════════════════════════════════════╗"
log "║         BLACK BOX AUDIT — RÉSULTAT FINAL          ║"
log "╠═══════════════════════════════════════════════════╣"
log "║  PASS  : $(printf '%-3d' $PASS)  (tests sans anomalie)            ║"
log "║  FAIL  : $(printf '%-3d' $FAIL)  (comportements inattendus)       ║"
log "║  VULNS : $(printf '%-3d' $WARN)  (failles ou risques détectés)    ║"
log "╚═══════════════════════════════════════════════════╝"
log ""
log "  Log complet sauvegardé : $LOG_FILE"
log ""

exit 0
