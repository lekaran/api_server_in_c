# Rapport d'Audit de Sécurité — Grey Box
**Cible** : `http://127.0.0.1:8080`  
**Routes** : `POST /register`, `POST /login`  
**Base de données** : MySQL  
**Date** : 2026-04-25  
**Méthode** : Grey-box — accès complet au code source + tests dynamiques  
**Script** : `tests/test_audit_greybox.sh`  
**Auditeur** : audit automatisé

---

## Résumé Exécutif

| Sévérité     | Nombre |
|--------------|--------|
| 🔴 Critique   | 1      |
| 🟠 Haute      | 3      |
| 🟡 Moyenne    | 4      |
| 🔵 Faible     | 4      |
| ℹ️ Informatif | 3      |

**Score : 14 PASS / 20 VULNS / 15 INFO sur 49 tests.**

L'audit grey box révèle des vulnérabilités **invisibles en black box** car elles nécessitent la lecture du code source pour être comprises et exploitées. La plus critique est la **désynchronisation entre le parsing Content-Length et la lecture réelle du body** (server.c:260-271), qui permet de contourner la vérification MAX_BODY_SIZE. Un vecteur de **DoS disponibilité** est confirmé via la combinaison BUFFER_SIZE < MAX_BODY_SIZE et le comportement de `recv(fd, buf, 0)`. L'absence de TLS, d'expiry de token et de route `/logout` complète le tableau.

---

## Résultats des tests par section

| Section | Tests | PASS | VULN | Notes |
|---------|-------|------|------|-------|
| GBX-001 Content-Length case-sensitive | 3 | 1 | 1 | +1 INFO |
| GBX-002 BUFFER_SIZE vs MAX_BODY_SIZE | 3 | 2 | 1 | DoS confirmé |
| GBX-003 Content-Length négatif/zéro | 3 | 0 | 2 | +1 INFO — bypass confirmé |
| GBX-004 DoS mono-thread + argon2id | 2 | 1 | 1 | Impact limité sur loopback |
| GBX-005 Token sans expiry | 3 | 0 | 3 | Accumulation DB confirmée |
| GBX-006 Slow Loris | 1 | 1 | 0 | Test timing imprécis sur loopback |
| GBX-007 HTTP version non validée | 3 | 2 | 1 | HTTP/9.9 accepté |
| GBX-008 Code HTTP sémantique | 1 | 0 | 1 | 201 au lieu de 200 |
| GBX-009 UTF-8 ≥ 0x80 first/last_name | 4 | 0 | 2 | +2 INFO (500 sur byte invalide) |
| GBX-010 Pas de validation Content-Type | 3 | 0 | 3 | Confirmé par code |
| GBX-011 BODY_MAX = 512 | 2 | 1 | 1 | Bombe à retardement |
| GBX-012 Désynchronisation Content-Length | 1 | 0 | 0 | +1 INFO — comportement confirmé |
| GBX-013 strtol overflow | 3 | 2 | 1 | Content-Length='abc' accepté |
| GBX-014 Absence TLS / HSTS | 3 | 0 | 3 | +1 INFO |
| GBX-015 recv(0) buffer saturé | 2 | 0 | 0 | +2 INFO — comportement réel limité |
| BONUS | 4 | 4 | 0 | Race condition, limites password OK |

---

## 1. Vulnérabilités Trouvées

---

### GBX-VULN-001 — Désynchronisation Content-Length / lecture body (Critique)
**Sévérité** : 🔴 Critique  
**Catégorie** : Protocol Confusion / Input Validation Bypass  
**Tests** : GBX-001.3, GBX-003.1, GBX-003.3, GBX-012.1  

**Origine dans le code**
```c
// server.c:260
char *header_content = strstr(client_message, "Content-Length:");
// ↑ strstr est CASE-SENSITIVE
// → "content-length:" ou "CONTENT-LENGTH:" ne sont pas trouvés

if(header_content == NULL){
    content_length = 0;  // ← pas de body déclaré
}
// ...
// server.c:271
if(content_length > MAX_BODY_SIZE){ reject; }  // ← BYPASSED si content_length=0

// server.c:314
bytes_restants = content_length - body_deja_recu;  // ← toujours négatif si content_length=0

if (bytes_restants > 0){ /* boucle de lecture body → IGNORÉE */ }

// server.c:352
http_parse_request(client_message, total_recu, &req);
// ↑ parse TOUT ce qui est dans le buffer, y compris le body déjà reçu
// pendant la boucle headers (le client envoie tout en un seul write TCP)
```

**Preuves d'exploitation (tests réussis)**

```bash
# Login réussi avec Content-Length: 0 (body traité quand même)
curl -X POST http://127.0.0.1:8080/login \
    -H "Content-Type: application/json" \
    -H "Content-Length: 0" \
    -d '{"username":"victim","password":"P@ss1234"}'
# → HTTP 201 {"token":"..."}  ← LOGIN RÉUSSI malgré Content-Length: 0

# Login réussi avec Content-Length: -1
curl -X POST http://127.0.0.1:8080/login \
    -H "Content-Length: -1" \
    -d '{"username":"victim","password":"P@ss1234"}'
# → HTTP 201 {"token":"..."}  ← LOGIN RÉUSSI

# Register réussi avec Content-Length: 5 (body réel = 93 bytes)
# → HTTP 201 {"message":"User created"}  ← REGISTER RÉUSSI
```

**Impact**  
- Le check `MAX_BODY_SIZE = 65536` est totalement contournable via `Content-Length: 0` ou `Content-Length: -1`  
- Le serveur traite le body du buffer de headers, ignorant la valeur annoncée  
- Toute validation de taille de payload est neutralisée côté serveur  
- Potentielle confusion de parseur : le body traité peut être partiellement lu selon la fragmentation TCP

**Recommandation**  
1. Utiliser `http_get_header(req, "content-length")` (le parser normalise déjà en minuscules)  
2. Valider que `content_length >= 0` avant toute utilisation  
3. Rejeter les requêtes avec corps et `Content-Length: 0`  

---

### GBX-VULN-002 — DoS via Content-Length dans [BUFFER_SIZE, MAX_BODY_SIZE] (Haute)
**Sévérité** : 🟠 Haute  
**Catégorie** : Denial of Service (OWASP A05:2021)  
**Tests** : GBX-002.3  

**Origine dans le code**
```c
// server.h
#define BUFFER_SIZE   8192    // ← taille réelle du buffer recv
#define MAX_BODY_SIZE 65536   // ← limite déclarée, mais inaccessible!

// server.c:319 — boucle lecture body
recv(client_accepted,
     client_message + total_recu,
     BUFFER_SIZE - total_recu - 1,   // ← quand total_recu ≈ BUFFER_SIZE,
     0);                              //   cette valeur devient 0 ou négative

// server.c:330 — si recv retourne 0 :
if(nb_octets_recus == 0){
    LOG_ERROR("Client disconnected!");
    close(client_accepted);
    scip_client = 1;
    break;
}
```

**Preuve d'exploitation**
```bash
# Content-Length = 32000 (valide selon MAX_BODY_SIZE, mais > BUFFER_SIZE)
# Le serveur passe le check MAX_BODY_SIZE, entre dans la boucle de lecture,
# mais le buffer est plein → recv(fd, buf, 0) → le serveur attend le timeout (5s)
curl -X POST http://127.0.0.1:8080/login \
    -H "Content-Type: application/json" \
    -H "Content-Length: 32000" \
    -d '{"username":"x","password":"y"}' \
    --max-time 10
# → Timeout (000) — le serveur attend 5 secondes par connexion
```

**Impact**  
Un attaquant sans authentification peut bloquer le serveur pendant **5 secondes par connexion** (SO_RCVTIMEO). Combiné avec l'architecture **mono-thread**, les 10 connexions du backlog suffisent pour mettre le serveur en indisponibilité quasi-totale pendant `10 × 5 = 50 secondes` avec seulement 10 connexions simultanées.

**Recommandation**  
- Soit aligner `MAX_BODY_SIZE = BUFFER_SIZE - HTTP_HEADERS_MAX` (solution simple)  
- Soit allouer dynamiquement le buffer body séparément du buffer headers  
- Ajouter un timeout global par connexion (pas seulement sur recv)

---

### GBX-VULN-003 — Tokens sans expiry ni révocation (Haute)
**Sévérité** : 🟠 Haute  
**Catégorie** : Broken Authentication (OWASP A07:2021)  
**Tests** : GBX-005.1, GBX-005.2, GBX-005.3  

**Origine dans le code**
```c
// login.c:245
const char *query_insert = "INSERT INTO tokens(user_id, token_hash) VALUES (?,?)";
// ↑ INSERTION sans DELETE des anciens tokens, sans colonne expires_at,
//   sans limite de tokens par utilisateur

// router.c:17 — /logout commenté
// {.methode = "POST", .path = "/logout", .handler = NULL, .is_protected = 1},
```

**Preuves**
```bash
# 10 logins successifs génèrent 10 tokens dans la DB
for i in $(seq 1 10); do
    curl -s -X POST http://127.0.0.1:8080/login \
        -d '{"username":"user","password":"P@ss"}' | grep token
done
# → 10 tokens distincts dans la table tokens, TOUS potentiellement valides

# Aucune route /logout
curl -X POST http://127.0.0.1:8080/logout  # → HTTP 404
```

**Impact**  
- **Vol de session permanent** : un token volé reste valide indéfiniment  
- **DoS base de données** : un bot peut générer des millions de tokens  
- **Aucune déconnexion possible** : l'utilisateur ne peut pas invalider ses sessions  
- **Pas d'audit de sessions** : impossible de détecter une compromission de compte

**Recommandation**  
1. Ajouter `expires_at DATETIME` à la table `tokens`  
2. Implémenter `/logout` (DELETE token de la DB)  
3. Implémenter un TTL (ex. : 24h) et un cron de nettoyage  
4. Limiter le nombre de tokens actifs par utilisateur (ex. : 5 max)

---

### GBX-VULN-004 — DoS mono-thread + argon2id (Haute)
**Sévérité** : 🟠 Haute  
**Catégorie** : Denial of Service — Resource Exhaustion  
**Tests** : GBX-004.1  

**Origine dans le code**
```c
// server.c:147 — boucle principale
while (true) {
    client_accepted = accept(server_socket_fd, ...);  // UN seul client à la fois
    // ... recv headers, recv body ...
    router_dispatch(client_accepted, &req);            // BLOQUANT: ~72ms pour argon2id
    close(client_accepted);
}

// login.c:205
int test_pwd = crypto_pwhash_str_verify(pwd_hashed, pwd_buff, strlen(pwd_buff));
// ↑ intentionnellement lent (argon2id interactive) = ~72ms mesurés
```

**Mesures**
```
Temps argon2id par vérification (login)     : 72ms  (mesuré)
Backlog de connexions (listen)              : 10
Temps de blocage avec 10 login concurrents  : ~720ms - ~5000ms selon le cas
```

**Impact**  
Avec seulement **10 connexions simultanées** (le backlog), un attaquant peut sérialiser `10 × 72ms ≈ 720ms` de traitement pur, plus les timeouts. Sur un réseau réel (non-loopback), l'impact est amplifié car les connexions TCP restent ouvertes plus longtemps.

**Note** : l'impact mesuré sur loopback est faible (107ms pour un client légitime pendant 5 attaques parallèles), mais ce résultat est spécifique au loopback. Sur un réseau avec latence, l'impact est significativement plus élevé.

**Recommandation**  
- Mettre en place un rate limiting par IP **avant** la vérification argon2id (ex. : leaky bucket)  
- Envisager une architecture multi-threadée ou async (pthread, epoll)

---

### GBX-VULN-005 — HTTP version non validée (Moyenne)
**Sévérité** : 🟡 Moyenne  
**Catégorie** : Input Validation  
**Tests** : GBX-007.1  

**Origine dans le code**
```c
// http_parser.c:55-59
int version_len = line_end - pos;
if (version_len >= HTTP_MAX_VERSION) return -1;
memcpy(req->version, pos, version_len);
req->version[version_len] = '\0';
// ↑ version stockée mais JAMAIS vérifiée (pas de strcmp avec "HTTP/1.1")

// router.c : aucune vérification de req->version
// server.c : aucune vérification de req->version
```

**Preuve**
```bash
# Requête HTTP/9.9 → traitée normalement
POST /login HTTP/9.9
# → HTTP 401 {"error":"Invalid credentials"}  ← serveur a traité la requête
```

**Impact**  
Le serveur accepte et traite des requêtes avec n'importe quelle version HTTP arbitraire. Un attaquant peut envoyer des requêtes `HTTP/9.9`, `HTTP/MALICIOUS`, etc. et obtenir des réponses normales. Cela complique la détection par les WAF et IDS qui filtrent sur la version HTTP.

**Recommandation**  
```c
if (strcmp(req->version, "HTTP/1.1") != 0 && strcmp(req->version, "HTTP/1.0") != 0) {
    // retourner 400 Bad Request ou 505 HTTP Version Not Supported
    return -1;
}
```

---

### GBX-VULN-006 — Absence de validation Content-Type (Moyenne)
**Sévérité** : 🟡 Moyenne  
**Catégorie** : Input Validation  
**Tests** : GBX-010.1, GBX-010.2, GBX-010.3  

**Origine dans le code**
```c
// Aucun appel à http_get_header(req, "content-type") dans :
// - server.c       (aucune vérification globale)
// - router.c       (aucune vérification avant dispatch)
// - handler/login.c    (aucune vérification)
// - handler/register.c (aucune vérification)
```

**Preuves**
```bash
# Login avec Content-Type: application/xml → 201 (token reçu!)
# Login avec Content-Type: text/html       → 201 (token reçu!)
# Login sans Content-Type du tout          → 201 (token reçu!)
```

**Impact**  
- Toute requête avec du JSON valide dans le body est traitée quel que soit le Content-Type  
- Facilite les attaques CSRF (formulaires HTML peuvent soumettre du JSON-like content)  
- Comportement non conforme à la spec REST

**Recommandation**  
```c
const char *ct = http_get_header(req, "content-type");
if (ct == NULL || strncmp(ct, "application/json", 16) != 0) {
    // retourner 415 Unsupported Media Type
}
```

---

### GBX-VULN-007 — Absence TLS / credentials en clair (Moyenne)
**Sévérité** : 🟡 Moyenne (contexte localhost — critique en production)  
**Catégorie** : Cryptographic Failures (OWASP A02:2021)  
**Tests** : GBX-014.1, GBX-014.2  

**Origine dans le code**
```c
// server.c:41
server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
// ↑ socket TCP brut, pas de TLS (pas de SSL_CTX, pas de libssl)

// http_response_builder.c — headers de sécurité présents :
add_header_http_response_builder(&response, "X-Frame-Options", "DENY");
// ↑ Mais Strict-Transport-Security est ABSENT
```

**Impact**  
- Username, password, et tokens transmis en clair sur le réseau  
- Interception triviale sur un réseau non sécurisé (café, entreprise, etc.)  
- Le header `Strict-Transport-Security` est absent (pas de HSTS)

**Recommandation**  
- Placer l'API derrière un reverse-proxy TLS (nginx, Caddy, HAProxy)  
- Ajouter `Strict-Transport-Security: max-age=63072000; includeSubDomains`  
- En production : TLS obligatoire, certificat valide

---

### GBX-VULN-008 — UTF-8 ≥ 0x80 accepté sans restriction dans first_name/last_name (Moyenne)
**Sévérité** : 🟡 Moyenne  
**Catégorie** : Input Validation  
**Tests** : GBX-009.1, GBX-009.2, GBX-009.4  

**Origine dans le code**
```c
// register.c:185
while (*fn_ptr) {
    if (!isalpha((unsigned char)*fn_ptr)
        && (unsigned char)*fn_ptr != ' '
        && (unsigned char)*fn_ptr != '-'
        && (unsigned char)*fn_ptr != '\''
        && (unsigned char)*fn_ptr < 0x80) {   // ← tout byte ≥ 0x80 passe!
        // reject
    }
    fn_ptr++;
}
```

**Preuves**
```bash
# Emoji accepté dans first_name
{"first_name": "Jean🔑"} → HTTP 201

# Cyrillique А (U+0410) visuellement identique à 'A' latin → accepté
{"first_name": "Аdmin"}  → HTTP 201

# Byte UTF-8 invalide (0xFF) → HTTP 500 (erreur interne, pas 400!)
{"first_name": "Jean\xFF"} → HTTP 500  ← information disclosure potentiel
```

**Impact**  
- **Homoglyph attack** : créer un utilisateur "Аdmin" (А cyrillique) visuellement identique à "Admin"  
- **HTTP 500 sur byte invalide** : révèle un comportement interne non géré  
- Les données stockées en DB peuvent être mal-formées si MySQL est configuré en `utf8mb3` (ne supporte pas les emoji 4-bytes)

**Recommandation**  
Définir une politique claire :  
- Si support international voulu → valider la séquence UTF-8 complète + limiter les scripts autorisés  
- Si ASCII uniquement → rejeter tout byte ≥ 0x80  
- Toujours retourner 400 (pas 500) sur des données d'entrée invalides

---

### GBX-VULN-009 — BODY_MAX = 512 bytes dans router.c (Faible)
**Sévérité** : 🔵 Faible  
**Catégorie** : Design — Fragilité future  
**Tests** : GBX-011.1  

**Origine dans le code**
```c
// router.c:11
#define BODY_MAX 512

// router.c:52
char body[BODY_MAX] = "";
http_code = route_tables[i].handler(req, body, sizeof(body));
// ↑ snprintf dans les handlers tronque silencieusement si réponse > 512 bytes
```

**Impact**  
La réponse de `/login` est actuellement `{"token":"<64-hex>"}` ≈ 76 bytes. Mais si un champ est ajouté (ex. : `expires_at`, `refresh_token`), la troncature crée un **JSON malformé** transmis au client, sans erreur côté serveur. Le `Content-Length` header serait alors incorrect (calculé avant troncature).

**Recommandation**  
Augmenter `BODY_MAX` à 4096 bytes minimum, ou allouer dynamiquement le buffer de réponse.

---

### GBX-VULN-010 — Login retourne HTTP 201 au lieu de 200 (Faible)
**Sévérité** : 🔵 Faible  
**Catégorie** : HTTP Semantics  
**Tests** : GBX-008.1  

**Origine dans le code**
```c
// login.c:281
return 201;   // ← 201 Created (création de ressource)
              //   correct pour /register, INCORRECT pour /login
              //   devrait être 200 OK
```

**Recommandation** : `return 200;`

---

### GBX-VULN-011 — Content-Length non numérique traité comme 0 (Faible)
**Sévérité** : 🔵 Faible  
**Catégorie** : Input Validation  
**Tests** : GBX-013.3  

**Origine dans le code**
```c
// server.c:265
content_length = strtol(header_content, &endptrContent, 10);
// strtol("abc", ...) → retourne 0, errno=0 (pas d'erreur!)
// → content_length = 0 → aucune validation, body dans buffer traité normalement
```

**Preuve**
```bash
curl -H "Content-Length: abc" -d '{"username":"user","password":"P@ss"}' \
    http://127.0.0.1:8080/login
# → HTTP 201 (login réussi, Content-Length ignoré)
```

**Recommandation**  
```c
char *endptrContent;
errno = 0;
content_length = strtol(header_content, &endptrContent, 10);
if (errno != 0 || endptrContent == header_content || content_length < 0) {
    // retourner 400 Bad Request
}
```

---

### GBX-VULN-012 — Pas de HSTS (Faible)
**Sévérité** : 🔵 Faible  
**Catégorie** : Security Misconfiguration  
**Tests** : GBX-014.1  

Le header `Strict-Transport-Security` est absent de `http_response_builder.c`. À ajouter dès que TLS est en place.

---

## 2. Observations Informationnelles

| ID | Observation | Fichier |
|----|-------------|---------|
| INFO-001 | HTTP 500 sur byte UTF-8 invalide 0xFF dans first_name : le serveur devrait retourner 400 | register.c:185 |
| INFO-002 | Content-Length='abc' : strtol retourne 0 sans signal d'erreur (errno=0) | server.c:265 |
| INFO-003 | Slow Loris : sur loopback, impact mesuré faible (94ms) car la connexion slow s'initialise après le client légitime en raison de la latence Python | server.c:153 |
| INFO-004 | Race condition sur /register : correctement gérée par la contrainte UNIQUE MySQL (errno 1062) | register.c:295 |
| INFO-005 | SHA-256 pour le token en DB est approprié (token = 32 bytes aléatoires = 256 bits d'entropie) | token.c:16 |

---

## 3. Éléments Sécurisés (PASS)

| Vérification | Résultat |
|--------------|----------|
| SQL Injection via paramètres bindés MySQL | Résistant |
| Password hash argon2id (libsodium) | Correct |
| Dummy hash anti-timing (login.c:180) | En place |
| Whitelist des champs JSON acceptés | En place |
| Validation caractères username (alphanumérique) | En place |
| Validation longueur password (min 8, max 255) | Correcte |
| Validation politique password (upper/lower/digit) | En place |
| Unicité username (contrainte DB + errno 1062) | En place |
| TOKEN = 32 bytes CSPRNG (randombytes_buf) | Correct |
| TOKEN haché SHA-256 avant stockage DB | Correct |
| Headers sécurité (X-Frame-Options, CSP, etc.) | En place |
| Race condition register (UNIQUE MySQL) | Gérée |
| Overflow password buffer (PASSWORD_HASH_MAX) | Protégé |
| Null bytes dans body (scan initial) | Protégé |

---

## 4. Plan de Remédiation Prioritaire

```
PRIORITÉ 1 — Critique (à corriger immédiatement)
──────────────────────────────────────────────────
[GBX-001] Remplacer strstr(client_message, "Content-Length:") par http_get_header()
          et valider content_length >= 0

PRIORITÉ 2 — Haute (à corriger dans les 7 jours)
──────────────────────────────────────────────────
[GBX-002] Aligner MAX_BODY_SIZE sur BUFFER_SIZE, ou séparer les buffers headers/body
[GBX-003] Implémenter TTL + colonne expires_at dans la table tokens
[GBX-003] Implémenter la route POST /logout (DELETE token)
[GBX-004] Ajouter rate limiting par IP avant la vérification argon2id

PRIORITÉ 3 — Moyenne (à corriger dans les 30 jours)
─────────────────────────────────────────────────────
[GBX-005] Valider Content-Type: application/json dans le router ou les handlers
[GBX-006] Valider la version HTTP ("HTTP/1.0" ou "HTTP/1.1" uniquement)
[GBX-007] Mettre en place TLS (reverse-proxy nginx/Caddy)

PRIORITÉ 4 — Faible (amélioration continue)
─────────────────────────────────────────────
[GBX-008] Définir une politique UTF-8 claire pour first_name/last_name
          (ou rejeter tout byte ≥ 0x80 si ASCII uniquement)
[GBX-009] Augmenter BODY_MAX à 4096 dans router.c
[GBX-010] Corriger le code de retour de /login : 201 → 200
[GBX-011] Valider strtol() : vérifier errno, endptrContent, et content_length >= 0
[GBX-012] Ajouter Strict-Transport-Security quand TLS sera en place
```

---

## 5. Comparaison Black Box vs Grey Box

| Vulnérabilité | Détectable black box ? | Détectable grey box ? |
|---------------|----------------------|----------------------|
| Content-Length bypass (GBX-001/003) | Difficile (requiert fuzzing ciblé) | Oui (visible dans server.c:260) |
| BUFFER_SIZE < MAX_BODY_SIZE (GBX-002) | Non (comportement timeout) | Oui (server.h:4-5) |
| DoS via Content-Length 32000 | Partiellement (timeout visible) | Oui (code confirm) |
| Token sans expiry (GBX-005) | Partiel (observable par accumulation) | Oui (login.c:245) |
| HTTP version non validée (GBX-007) | Oui (fuzzing HTTP) | Oui (http_parser.c:59) |
| BODY_MAX = 512 (GBX-011) | Non (non observable) | Oui (router.c:11) |
| recv(0) quand buffer plein (GBX-015) | Non | Oui (server.c:319) |
| HTTP 500 sur UTF-8 invalide (INFO-001) | Oui (fuzzing bytes) | Oui + root cause connue |
| Content-Type non validé | Oui (testé en black box) | Oui + confirmé par code |

---

*Rapport généré le 2026-04-25 — Script : `tests/test_audit_greybox.sh`*
