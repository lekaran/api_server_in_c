#!/bin/bash
# Audit de sécurité — Tests de Déni de Service (DoS)
# Cible : server/server.c — serveur mono-thread
# Vérifie : slow HTTP, Content-Length mensonger, saturation du backlog

BASE_URL="http://127.0.0.1:8080"
PASS=0; FAIL=0; WARN=0

echo ""
echo "================================================="
echo "  AUDIT — Déni de Service (DoS)"
echo "================================================="
echo ""

# ── Référence : temps normal ──
echo "[ Référence : temps de réponse normal ]"
T_REF_START=$(python3 -c "import time; print(int(time.time()*1000))")
curl -s -o /dev/null http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"y"}'
T_REF_END=$(python3 -c "import time; print(int(time.time()*1000))")
T_REF=$((T_REF_END - T_REF_START))
echo "  Temps de référence : ${T_REF}ms"
echo ""

# ── Test 1 : Slow headers (connexion partielle) ──
echo "[ Test 1 — Slow HTTP headers (connexion sans \\r\\n\\r\\n) ]"
echo "  Envoi d'une connexion qui envoie des headers sans les terminer..."

python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', 8080))
s.send(b'POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n')
time.sleep(6)
s.close()
" &
SLOW_PID=$!

sleep 1

T_SLOW_START=$(python3 -c "import time; print(int(time.time()*1000))")
CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"y"}' --max-time 10)
T_SLOW_END=$(python3 -c "import time; print(int(time.time()*1000))")
T_SLOW=$((T_SLOW_END - T_SLOW_START))

wait $SLOW_PID 2>/dev/null

echo "  Temps de réponse pendant slow HTTP : ${T_SLOW}ms (référence: ${T_REF}ms)"
if [ "$T_SLOW" -gt 2000 ]; then
    echo "  VULN Slow HTTP bloque le serveur pendant ${T_SLOW}ms"
    WARN=$((WARN+1))
else
    echo "  PASS Serveur reste réactif (délai < 2s)"
    PASS=$((PASS+1))
fi

# ── Test 2 : Content-Length mensonger ──
echo ""
echo "[ Test 2 — Content-Length mensonger (annoncé: 65535, envoyé: 50 octets) ]"

python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', 8080))
body = '{\"username\":\"x\",\"password\":\"y\"}'
req = 'POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 65535\r\n\r\n' + body
s.send(req.encode())
time.sleep(6)
s.close()
" &
LYING_PID=$!

sleep 1

T_LIE_START=$(python3 -c "import time; print(int(time.time()*1000))")
CODE2=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"y"}' --max-time 10)
T_LIE_END=$(python3 -c "import time; print(int(time.time()*1000))")
T_LIE=$((T_LIE_END - T_LIE_START))

wait $LYING_PID 2>/dev/null

echo "  Temps de réponse pendant Content-Length mensonger : ${T_LIE}ms"
if [ "$T_LIE" -gt 2000 ]; then
    echo "  VULN Content-Length mensonger bloque le serveur pendant ${T_LIE}ms"
    WARN=$((WARN+1))
else
    echo "  PASS Serveur reste réactif (délai < 2s)"
    PASS=$((PASS+1))
fi

# ── Test 3 : Saturation du backlog (10 connexions simultanées) ──
echo ""
echo "[ Test 3 — Saturation du backlog TCP (10 connexions simultanées) ]"
echo "  Lancement de 10 connexions avec Content-Length mensonger..."

for i in $(seq 1 10); do
    python3 -c "
import socket, time
s = socket.socket()
try:
    s.connect(('127.0.0.1', 8080))
    body = '{\"username\":\"x\",\"password\":\"y\"}'
    req = 'POST /login HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Type: application/json\r\nContent-Length: 65535\r\n\r\n' + body
    s.send(req.encode())
    time.sleep(5)
finally:
    s.close()
" &
done

sleep 1

T_SAT_START=$(python3 -c "import time; print(int(time.time()*1000))")
CODE3=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"y"}' --max-time 15)
T_SAT_END=$(python3 -c "import time; print(int(time.time()*1000))")
T_SAT=$((T_SAT_END - T_SAT_START))

wait 2>/dev/null

echo "  Code reçu : $CODE3"
echo "  Temps de réponse sous saturation : ${T_SAT}ms (référence: ${T_REF}ms)"
if [ "$T_SAT" -gt 3000 ]; then
    echo "  VULN Saturation du backlog retarde la réponse de ${T_SAT}ms"
    WARN=$((WARN+1))
elif [ -z "$CODE3" ] || [ "$CODE3" -eq 0 ]; then
    echo "  VULN Aucune réponse reçue — serveur inaccessible"
    WARN=$((WARN+1))
else
    echo "  PASS Serveur reste accessible (délai < 3s)"
    PASS=$((PASS+1))
fi

# ── Test 4 : Connexion sans envoyer de données ──
echo ""
echo "[ Test 4 — Connexion TCP idle (sans envoyer de données) ]"
T_IDLE_START=$(python3 -c "import time; print(int(time.time()*1000))")
python3 -c "
import socket, time
s = socket.socket()
s.connect(('127.0.0.1', 8080))
time.sleep(7)
s.close()
" &
IDLE_PID=$!

sleep 1
T_PARA_START=$(python3 -c "import time; print(int(time.time()*1000))")
CODE4=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/login -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"x","password":"y"}' --max-time 10)
T_PARA_END=$(python3 -c "import time; print(int(time.time()*1000))")
T_PARA=$((T_PARA_END - T_PARA_START))
wait $IDLE_PID 2>/dev/null

echo "  Temps de réponse pendant connexion idle : ${T_PARA}ms"
if [ "$T_PARA" -gt 4000 ]; then
    echo "  VULN Connexion idle bloque le serveur pendant ${T_PARA}ms"
    WARN=$((WARN+1))
else
    echo "  PASS SO_RCVTIMEO protège correctement (délai < 4s)"
    PASS=$((PASS+1))
fi

echo ""
echo "================================================="
printf "  Résultat : %d PASS  |  %d FAIL  |  %d FAILLES\n" "$PASS" "$FAIL" "$WARN"
echo "================================================="
echo ""
echo "  NOTE: Ces tests valident les vulnérabilités DoS inhérentes à"
echo "  l'architecture mono-thread + absence de rate limiting."
echo ""

exit 0
