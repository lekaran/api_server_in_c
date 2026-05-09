#!/bin/bash
# ============================================================
# GREY BOX AUDIT - 04 - UNICODE / HIGH-BYTE BYPASS
# SOURCE CODE KNOWLEDGE:
# register.c L.187 :
#   if(!isalpha(*fn_ptr) && *fn_ptr != ' ' && *fn_ptr != '-'
#      && *fn_ptr != '\'' && (unsigned char)*fn_ptr < 0x80)
#
# FAILLE: la condition "(unsigned char)*fn_ptr < 0x80" signifie
# que les octets >= 0x80 (UTF-8 multi-byte, latin-1, binaire)
# PASSENT la validation SANS vérification alpha!
#
# Même logique pour last_name (register.c L.218)
# USERNAME: seuls alphanum + '-' + '_' autorisés (correct)
# ============================================================

BASE_URL="http://127.0.0.1:8080"
RESULTS_FILE="/tmp/gb_04_unicode_results.txt"
PASS=0; FAIL=0; VULN=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_pass() { echo -e "${GREEN}[PASS]${NC} $1" | tee -a "$RESULTS_FILE"; PASS=$((PASS+1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1" | tee -a "$RESULTS_FILE"; FAIL=$((FAIL+1)); }
log_vuln() { echo -e "${RED}[VULN]${NC} $1" | tee -a "$RESULTS_FILE"; VULN=$((VULN+1)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RESULTS_FILE"; }
log_code() { echo -e "${CYAN}[CODE]${NC} $1" | tee -a "$RESULTS_FILE"; }

register_user() {
    local fn="$1"
    local ln="${2:-Normal}"
    local user="unicodetest$((RANDOM % 9999))"
    local RESP
    RESP=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${user}\",\"first_name\":\"${fn}\",\"last_name\":\"${ln}\",\"password\":\"Secure1234!\"}" 2>/dev/null)
    BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
    echo "$RESP|$BODY"
    sleep 0.5
}

echo "" | tee "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  GREY BOX - 04 - UNICODE / HIGH-BYTE BYPASS" | tee -a "$RESULTS_FILE"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

log_code "register.c:187"
log_code "  if(!isalpha(*fn_ptr) && *fn_ptr != ' ' && *fn_ptr != '-' && *fn_ptr != '\\''"
log_code "     && (unsigned char)*fn_ptr < 0x80) { return 400; }"
log_code ""
log_code "CONDITION REJET: (!alpha && != espace && != - && != ') && < 0x80"
log_code "Si byte >= 0x80: la condition < 0x80 est FAUSSE → rejet IMPOSSIBLE → PASS!"
echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 1. CARACTÈRES LÉGITIMES (doivent passer)
# ============================================================
echo "--- [1] Caractères légitimes (référence) ---" | tee -a "$RESULTS_FILE"
for FN in "Alice" "Marie-Claire" "Jean Pierre" "O'Brien"; do
    RESULT=$(register_user "$FN")
    CODE=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESULT" | cut -d'|' -f2)
    [ "$CODE" = "201" ] && log_pass "[LEGIT] '$FN' → $CODE" || log_fail "[LEGIT] '$FN' → $CODE | $BODY"
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 2. CARACTÈRES ASCII SPÉCIAUX (doivent être rejetés)
# ============================================================
echo "--- [2] ASCII spéciaux < 0x80 (doivent être rejetés) ---" | tee -a "$RESULTS_FILE"
log_code "register.c: (!isalpha && != espace && != - && != ') && < 0x80 → 400"
for FN in "<script>" "' OR 1=1" "; cat /etc/passwd" "test@test.com" "test!!" "test123"; do
    RESULT=$(register_user "$FN")
    CODE=$(echo "$RESULT" | cut -d'|' -f1)
    [ "$CODE" = "400" ] && log_pass "[ASCII-REJ] '$FN' → $CODE (rejeté correct)" || log_vuln "[ASCII-ACC] '$FN' → $CODE (accepté, inattendu!)"
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 3. BYTES >= 0x80 (BYPASS de validation)
# ============================================================
echo "--- [3] BYTES >= 0x80 (bypass validation via high-byte) ---" | tee -a "$RESULTS_FILE"
log_code "Si byte >= 0x80 → condition < 0x80 est fausse → pas de rejet → BYPASS!"

# UTF-8 valide (international names)
for FN in "Héloïse" "Ñoño" "Müller" "Björn" "Ångström"; do
    RESULT=$(register_user "$FN")
    CODE=$(echo "$RESULT" | cut -d'|' -f1)
    BODY=$(echo "$RESULT" | cut -d'|' -f2)
    if [ "$CODE" = "201" ]; then
        log_info "[UTF8-PASS] '$FN' (UTF-8 valide) → $CODE (attendu - noms étrangers OK)"
    else
        log_info "[UTF8-REJ] '$FN' → $CODE | $BODY"
    fi
done

echo "" | tee -a "$RESULTS_FILE"

# Bytes invalides UTF-8 (>= 0x80 mais pas séquences UTF-8 valides)
log_code "Test: octets 0x80-0xFF isolés (UTF-8 invalide mais >= 0x80)"
for HEX_SEQ in "\x80" "\x81\x82" "\xfe\xff" "\xff" "\x80\x90\xa0\xb0\xc0"; do
    RESULT=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        --data-raw "{\"username\":\"bypasstest$RANDOM\",\"first_name\":\"$HEX_SEQ\",\"last_name\":\"Normal\",\"password\":\"Secure1234!\"}" 2>/dev/null)
    BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
    if [ "$RESULT" = "201" ]; then
        log_vuln "[HIGH-BYTE] first_name avec bytes invalides UTF-8 '$HEX_SEQ' → $RESULT (stocké en DB!)"
    else
        log_pass "[HIGH-BYTE] '$HEX_SEQ' → $RESULT"
    fi
    sleep 0.5
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 4. Injection dans last_name (même vulnérabilité)
# ============================================================
echo "--- [4] MÊME BYPASS sur last_name ---" | tee -a "$RESULTS_FILE"
log_code "register.c:218 : même condition que first_name → même vulnérabilité"

for LN in "Müller" "Ñoño" "Wąsowicz"; do
    RESULT=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"lntest$RANDOM\",\"first_name\":\"Normal\",\"last_name\":\"${LN}\",\"password\":\"Secure1234!\"}" 2>/dev/null)
    BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
    [ "$RESULT" = "201" ] && log_info "[LN-HIGH] '$LN' → $RESULT (stocké)" || log_pass "[LN-HIGH] '$LN' → $RESULT"
    sleep 0.5
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 5. Contraste: username est PLUS strict (correct)
# ============================================================
echo "--- [5] USERNAME validation (plus stricte - comparaison) ---" | tee -a "$RESULTS_FILE"
log_code "register.c:151 : isalnum || '-' || '_' uniquement → bytes >= 0x80 REJETÉS aussi"
log_code "  car isalnum() retourne 0 pour bytes >= 0x80 ET '-'/'_' ne match pas → 400"

for UN in "hélio" "müller" "用户" "user@domain"; do
    RESULT=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
        -X POST "$BASE_URL/register" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${UN}\",\"first_name\":\"Normal\",\"last_name\":\"Test\",\"password\":\"Secure1234!\"}" 2>/dev/null)
    BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
    [ "$RESULT" = "400" ] && log_pass "[UN-STRICT] '$UN' → $RESULT (rejeté correct, plus strict)" \
        || log_info "[UN-STRICT] '$UN' → $RESULT | $BODY"
    sleep 0.5
done

echo "" | tee -a "$RESULTS_FILE"

# ============================================================
# 6. Impact: first_name vide (longueur zéro)
# ============================================================
echo "--- [6] CHAMP VIDE (first_name/last_name) ---" | tee -a "$RESULTS_FILE"
log_code "register.c: validation avec while(*fn_ptr) → boucle vide si chaîne vide → valide!"

RESULT=$(curl -s -o /tmp/gb_body.txt -w "%{http_code}" \
    -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"emptyfntest\",\"first_name\":\"\",\"last_name\":\"Normal\",\"password\":\"Secure1234!\"}" 2>/dev/null)
BODY=$(cat /tmp/gb_body.txt 2>/dev/null)
echo "  first_name='' (vide) → HTTP $RESULT | $BODY" | tee -a "$RESULTS_FILE"
if [ "$RESULT" = "201" ]; then
    log_vuln "[EMPTY-FN] first_name vide accepté et stocké en DB!"
    log_code "  Fix: ajouter check if(strlen(fn) == 0) { return 400; }"
else
    log_pass "[EMPTY-FN] → $RESULT"
fi

echo "" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
echo "  RÉSULTATS UNICODE: $PASS PASS | $FAIL FAIL | $VULN VULN" | tee -a "$RESULTS_FILE"
echo "  Résultats: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "========================================================" | tee -a "$RESULTS_FILE"
