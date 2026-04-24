# Audit de Sécurité — api_server_in_c

| Champ | Valeur |
|---|---|
| Date | 2026-04-24 |
| Auditeur | Claude Sonnet 4.6 (Anthropic) |
| Cible | `http://127.0.0.1:8080` |
| Branch | `feature/resolve_security_bug` |
| Méthode | Tests live (curl + sockets raw) + analyse statique du code source |
| Scripts | `tests/test_audit_validation.sh`, `test_audit_http.sh`, `test_audit_auth.sh`, `test_audit_dos.sh` |

---

## Résumé exécutif

Le serveur API REST en C a été audité sur l'ensemble de ses routes actives (`POST /register`, `POST /login`) et sur sa couche réseau. L'audit combine des tests live contre le serveur en cours d'exécution et une analyse statique du code source.

**Bilan : 9 vulnérabilités confirmées en live, 6 vulnérabilités identifiées par analyse de code.**

| Sévérité | Confirmées en live | Code review | Total |
|---|---|---|---|
| CRITIQUE | 0 | 1 | 1 |
| HAUTE | 4 | 1 | 5 |
| MOYENNE | 2 | 1 | 3 |
| FAIBLE | 3 | 3 | 6 |
| **Total** | **9** | **6** | **15** |

**Points positifs confirmés :** protection timing attack (dummy_hash), préparation SQL (pas d'injection), entropie des tokens (256 bits), hachage Argon2, validation du username (longueur + caractères), rejet des gros buffers.

---

## Périmètre et méthodologie

### Routes testées
| Route | Méthode | Statut |
|---|---|---|
| `POST /register` | Inscription | Implémenté |
| `POST /login` | Authentification | Implémenté |
| `POST /logout` | Déconnexion | Non implémenté (501) |
| `GET /profile` | Profil | Non implémenté (501) |
| `PUT /profile` | Mise à jour profil | Non implémenté (501) |
| `DELETE /profile` | Suppression compte | Non implémenté (501) |

### Catégories testées
1. Validation des entrées (inputs)
2. Protocole HTTP (méthodes, buffers, headers)
3. Authentification (timing, brute force, tokens)
4. Déni de service (DoS)
5. Analyse statique (code review)

---

## Vulnérabilités détaillées

---

### VULN-01 — `first_name` et `last_name` sans validation de longueur
**Sévérité : HAUTE** | **Confirmé en live**

**Fichier :** [handler/register.c:63-89](handler/register.c#L63)

**Description :**  
Les champs `first_name` et `last_name` n'ont aucune vérification de longueur avant le `strncpy`. Un attaquant peut envoyer une valeur de 10 000 caractères : le serveur répond `201 Created` et tronque silencieusement à 100 caractères. Le comportement visible du client diverge du contenu réellement stocké en base.

**Preuve (test live) :**
```bash
# first_name de 200 chars → HTTP 201 (attendu: 400)
curl -s -X POST http://127.0.0.1:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","first_name":"AAAA...200chars","last_name":"T","password":"Pass123!"}'
# → {"message":"User created"}  ← FAILLE : pas de 400
```

**Code vulnérable :**
```c
// handler/register.c:69-75
const char *fn = cJSON_GetStringValue(first_name);
if(fn == NULL){ ... return 400; }
// ← MANQUE : if(strlen(fn) > FIRST_NAME_MAX-1) return 400;
strncpy(register_user.first_name, fn, FIRST_NAME_MAX-1);  // troncature silencieuse
```

**Correction :**
```c
if(strlen(fn) > FIRST_NAME_MAX-1){
    cJSON_Delete(body_json);
    snprintf(body_out, body_out_size, "{\"error\":\"First name too long\"}");
    return 400;
}
```
Appliquer la même correction pour `last_name` ([handler/register.c:83-89](handler/register.c#L83)).

---

### VULN-02 — `first_name` et `last_name` sans validation des caractères
**Sévérité : MOYENNE** | **Confirmé en live**

**Fichier :** [handler/register.c:63-89](handler/register.c#L63)

**Description :**  
Contrairement au `username` ([handler/register.c:50-58](handler/register.c#L50)), les champs `first_name` et `last_name` acceptent n'importe quel caractère : balises HTML, caractères de contrôle, caractères Unicode exotiques.

**Preuve (test live) :**
```bash
# HTML injection dans first_name → HTTP 201
curl -s -X POST http://127.0.0.1:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test_html","first_name":"<script>alert(1)</script>","last_name":"T","password":"P"}'
# → {"message":"User created"}  ← stocké tel quel en DB
```

**Impact :**  
Si une interface frontend affiche `first_name` sans échappement, une XSS stored est possible. En l'état les données corrompues sont stockées en base.

**Correction :**  
Définir un jeu de caractères autorisé pour les noms (lettres Unicode, espaces, tirets, apostrophes) et valider via une boucle similaire à celle du `username`.

---

### VULN-03 — Absence de validation du header `Content-Type`
**Sévérité : FAIBLE** | **Confirmé en live**

**Fichier :** [handler/register.c:18](handler/register.c#L18), [handler/login.c:34](handler/login.c#L34)

**Description :**  
Les handlers appellent `cJSON_Parse(req->body)` sans vérifier que `Content-Type: application/json` est présent. Toute requête sans ce header est quand même parsée et acceptée.

**Preuve (test live) :**
```bash
# Requête sans Content-Type → HTTP 201
curl -s -X POST http://127.0.0.1:8080/register \
  -d '{"username":"test_noct","first_name":"T","last_name":"T","password":"P"}'
# → {"message":"User created"}
```

**Correction :**
```c
const char *ct = http_get_header(req, "content-type");
if(ct == NULL || strstr(ct, "application/json") == NULL){
    snprintf(body_out, body_out_size, "{\"error\":\"Content-Type must be application/json\"}");
    return 415;
}
```

---

### VULN-04 — Absence de rate limiting sur `POST /login`
**Sévérité : HAUTE** | **Confirmé en live**

**Fichier :** [server/server.c](server/server.c), [router/router.c](router/router.c)

**Description :**  
Aucun mécanisme ne limite le nombre de tentatives de connexion par IP ou par compte. Un attaquant peut automatiser des milliers de tentatives sans être ralenti ni bloqué.

**Preuve (test live) :**
```
10 tentatives de brute force → 10 réponses 401 normales, 0 bloquées (pas de 429)
```

**Scénario d'attaque :**  
Un dictionnaire de 100 000 mots de passe courants envoyé en boucle. Avec un temps de réponse de ~75ms, cela représente ~13 tentatives/seconde, soit **1 million de tentatives en 24h sans blocage**.

**Correction :**  
Implémenter un compteur par IP dans le serveur (table hash IP → nb_tentatives, timestamp_premier_echec). Retourner HTTP 429 après N échecs consécutifs avec un header `Retry-After`.

---

### VULN-05 — Accumulation illimitée de tokens par utilisateur
**Sévérité : MOYENNE** | **Confirmé en live**

**Fichier :** [handler/login.c:192-207](handler/login.c#L192)

**Description :**  
Chaque appel à `POST /login` crée un nouveau token en base sans supprimer les anciens ni imposer un maximum. Un attaquant ayant compromis les credentials peut générer des milliers de tokens valides.

**Preuve (test live) :**
```
5 logins → 5 tokens différents insérés en DB, tous valides simultanément
```

**Note :** La colonne `expired_at` existe dans le schéma (`DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 24 HOUR)`) mais n'est jamais vérifiée (voir VULN-10).

**Correction :**  
Avant d'insérer un nouveau token, invalider les anciens :
```sql
DELETE FROM tokens WHERE user_id = ? AND expired_at < NOW();
```
Et/ou limiter à N sessions actives par utilisateur.

---

### VULN-06 — Mauvaise méthode HTTP retourne 404 au lieu de 405
**Sévérité : FAIBLE** | **Confirmé en live**

**Fichier :** [router/router.c:23-92](router/router.c#L23)

**Description :**  
Quand une méthode incorrecte est utilisée sur une route connue (ex: `GET /register`), le serveur retourne `404 Not Found`. La RFC 7231 impose `405 Method Not Allowed` avec un header `Allow: POST`.

**Preuve (test live) :**
```
GET /register → 404  (attendu: 405)
PUT /register → 404  (attendu: 405)
DELETE /login → 404  (attendu: 405)
```

**Correction :**  
Modifier `router_dispatch` pour faire un second passage : si aucune route (méthode + path) ne matche, vérifier si le path seul matche. Si oui, retourner 405 avec `Allow:` header.

---

### VULN-07 — DoS via Content-Length mensonger (blocage ~4s)
**Sévérité : HAUTE** | **Confirmé en live**

**Fichier :** [server/server.c:257-342](server/server.c#L257)

**Description :**  
Si un client annonce `Content-Length: 65535` mais n'envoie que 50 octets de body, le serveur entre dans une boucle `recv()` et attend les octets manquants pendant exactement `SO_RCVTIMEO = 5s`. Pendant ce temps, étant mono-thread, le serveur ne peut pas traiter d'autres clients.

**Preuve (test live) :**
```
1 connexion Content-Length mensonger → réponse suivante retardée de 4054ms
(normal : 83ms)
```

**Code vulnérable :**
```c
// server/server.c:315-342
if (bytes_restants > 0){
    do{
        ssize_t nb_octets_recus = recv(...);  // bloque jusqu'à SO_RCVTIMEO (5s)
        ...
        bytes_restants -= nb_octets_recus;
    } while (bytes_restants > 0);  // le client menteur ne renverra jamais les octets
}
```

**Scénario d'attaque :**  
Avec `max_conn_backlog = 10`, un attaquant maintient 10 connexions permanentes avec Content-Length mensonger. Le serveur est complètement indisponible : chaque connexion tient le serveur 5 secondes, les nouvelles arrivent dans le backlog (max 10), et l'attaquant renouvelle sa connexion dès qu'elle expire.

---

### VULN-08 — DoS via connexion TCP idle (blocage ~4s)
**Sévérité : HAUTE** | **Confirmé en live**

**Fichier :** [server/server.c:188-210](server/server.c#L188)

**Description :**  
Une connexion TCP qui n'envoie aucune donnée bloque le serveur pendant 5 secondes (`SO_RCVTIMEO`). Le `recv()` attend le timeout avant que le serveur puisse passer au client suivant.

**Preuve (test live) :**
```
1 connexion idle → réponse suivante retardée de 4070ms
(normal : 83ms)
```

**Correction (VULN-07 et VULN-08 ensemble) :**  
La solution structurelle est l'architecture multi-thread ou `select()`/`epoll()`. À défaut, réduire `SO_RCVTIMEO` à une valeur plus agressive (ex: 1s) et ajouter un timeout global par connexion (pas seulement par `recv()`).

---

### VULN-09 — DoS par saturation du backlog TCP
**Sévérité : HAUTE** | **Confirmé en live**

**Fichier :** [server/server.c:72](server/server.c#L72)

**Description :**  
Le backlog TCP est limité à 10 connexions (`max_conn_backlog=10`). Combiné au serveur mono-thread et aux délais de 5s par connexion lente, 10 connexions simultanées malveillantes saturent entièrement la file d'attente.

**Preuve (test live) :**
```
10 connexions simultanées Content-Length mensonger → 
réponse légitime retardée de 4081ms (×49 le temps normal)
```

---

### VULN-10 — `db_connect()` appelle `exit(-1)` (crash serveur)
**Sévérité : CRITIQUE** | **Analyse de code**

**Fichier :** [DB/db.c:51-86](DB/db.c#L51)

**Description :**  
Si la connexion MySQL échoue pendant le traitement d'une requête, `db_connect()` appelle `exit(-1)` ce qui termine le processus serveur entier. Un attaquant qui peut provoquer des timeouts MySQL (surcharge DB, coupure réseau) peut tuer le serveur à la demande.

**Code vulnérable :**
```c
// DB/db.c:58-66
const char *db_host = getenv("DB_HOST");
if(db_host == NULL){ LOG_ERROR("DB_HOST NOT SET"); exit(-1); }  // ← exit() !
...
MYSQL *conn = mysql_real_connect(...);
if(conn == NULL){
    LOG_ERROR("...");
    exit(-1);  // ← exit() au lieu de return NULL !
}
```

**Correction :**
```c
// Retourner NULL et laisser le handler gérer l'erreur
if(conn == NULL){
    LOG_ERROR("...");
    mysql_close(conn_init);
    return NULL;  // pas exit()
}
```
Puis dans chaque handler, vérifier que `db_connect()` n'a pas retourné NULL.

---

### VULN-11 — Mot de passe en clair non effacé de la mémoire
**Sévérité : FAIBLE** | **Analyse de code**

**Fichier :** [handler/login.c:89-92](handler/login.c#L89)

**Description :**  
`pwd_buff` contient le mot de passe en clair et n'est pas effacé avec `sodium_memzero` après usage. Le token brut (`token_bytes`) est bien effacé (ligne 227) mais pas le mot de passe.

**Code vulnérable :**
```c
// handler/login.c:86-92
strncpy(pwd_buff, pwd, PASSWORD_HASH_MAX-1);
pwd_buff[PASSWORD_HASH_MAX-1] = '\0';
// ... utilisation de pwd_buff ...
// ← MANQUE: sodium_memzero(pwd_buff, sizeof(pwd_buff));
```

**Correction :**  
Ajouter `sodium_memzero(pwd_buff, sizeof(pwd_buff));` avant chaque `return` dans `login_handler`.

---

### VULN-12 — Tokens `expired_at` jamais vérifiés
**Sévérité : MOYENNE** | **Analyse de code**

**Fichier :** [middleware/auth.c](middleware/auth.c), [DB/migrations/V2__create_tokens.sql](DB/migrations/V2__create_tokens.sql)

**Description :**  
La table `tokens` a une colonne `expired_at` (24h par défaut), mais `middleware/auth.c` est vide. Les tokens ne sont jamais vérifiés ni invalidés. Conséquence : les tokens n'expirent jamais en pratique (la colonne existe mais personne ne la consulte).

**Correction :**  
Implémenter `middleware/auth.c` avec une vérification `SELECT user_id FROM tokens WHERE token_hash=? AND expired_at > NOW()`.

---

### VULN-13 — Absence de headers de sécurité dans les réponses
**Sévérité : FAIBLE** | **Analyse de code**

**Fichier :** [http/http_response_builder.c](http/http_response_builder.c), [router/router.c](router/router.c)

**Description :**  
Les réponses HTTP ne contiennent aucun header de sécurité standard. Pour une API REST, les suivants sont recommandés :

| Header | Valeur recommandée | Rôle |
|---|---|---|
| `Cache-Control` | `no-store` | Empêche la mise en cache des tokens |
| `X-Content-Type-Options` | `nosniff` | Empêche le MIME sniffing |
| `Connection` | `close` | Signale explicitement la fermeture |

---

### VULN-14 — Le `.env` contient des credentials réels
**Sévérité : FAIBLE** | **Analyse de code**

**Fichier :** [.env](.env)

**Description :**  
Le fichier `.env` contient un mot de passe MySQL réel (`7@9QE5pLCgeDTFt!`) et est **présent dans le dépôt git**. Si ce dépôt devient public ou si l'historique git est consulté, les credentials sont exposés.

**Correction :**  
1. Ajouter `.env` au `.gitignore` (vérifier qu'il n'est pas déjà suivi par git)
2. Générer de nouveaux credentials pour la production
3. Garder uniquement `.env.exemple` avec des valeurs vides

---

### VULN-15 — Architecture mono-thread : Argon2 bloque les connexions entrantes
**Sévérité : INFO** | **Analyse de code**

**Fichier :** [server/server.c:147](server/server.c#L147)

**Description :**  
Chaque opération `register` déclenche `crypto_pwhash_str` (Argon2, ~50ms intentionnellement). Pendant ce calcul, le serveur mono-thread ne peut pas appeler `accept()`. Les connexions entrantes s'accumulent dans le backlog (10 max). Avec 10+ clients simultanés sur `/register`, les nouveaux arrivants sont rejetés au niveau TCP.

**Note :** C'est une limitation d'architecture, pas un bug. La solution complète est le multi-threading.

---

## Tableau récapitulatif

| ID | Sévérité | Titre | Confirmé | Fichier |
|---|---|---|---|---|
| VULN-01 | HAUTE | `first_name`/`last_name` sans validation longueur | Live | [handler/register.c:63](handler/register.c#L63) |
| VULN-02 | MOYENNE | `first_name`/`last_name` sans validation caractères | Live | [handler/register.c:63](handler/register.c#L63) |
| VULN-03 | FAIBLE | Pas de validation `Content-Type` | Live | [handler/register.c:18](handler/register.c#L18) |
| VULN-04 | HAUTE | Pas de rate limiting sur `/login` | Live | [server/server.c](server/server.c) |
| VULN-05 | MOYENNE | Accumulation illimitée de tokens | Live | [handler/login.c:192](handler/login.c#L192) |
| VULN-06 | FAIBLE | 404 au lieu de 405 sur mauvaise méthode | Live | [router/router.c:23](router/router.c#L23) |
| VULN-07 | HAUTE | DoS via Content-Length mensonger (~4s) | Live | [server/server.c:315](server/server.c#L315) |
| VULN-08 | HAUTE | DoS via connexion idle (~4s) | Live | [server/server.c:188](server/server.c#L188) |
| VULN-09 | HAUTE | DoS via saturation backlog TCP | Live | [server/server.c:72](server/server.c#L72) |
| VULN-10 | CRITIQUE | `db_connect()` → `exit(-1)` = crash serveur | Code | [DB/db.c:51](DB/db.c#L51) |
| VULN-11 | FAIBLE | `pwd_buff` non effacé mémoire | Code | [handler/login.c:89](handler/login.c#L89) |
| VULN-12 | MOYENNE | Token `expired_at` jamais vérifié | Code | [middleware/auth.c](middleware/auth.c) |
| VULN-13 | FAIBLE | Absence de headers de sécurité | Code | [router/router.c](router/router.c) |
| VULN-14 | FAIBLE | `.env` avec credentials réels dans le repo | Code | [.env](.env) |
| VULN-15 | INFO | Architecture mono-thread (Argon2 blocking) | Code | [server/server.c:147](server/server.c#L147) |

---

## Ce qui est bien fait (points positifs)

| Mécanisme | Implémentation | Fichier |
|---|---|---|
| Protection timing attack | `dummy_hash` pré-calculé au démarrage → 1ms d'écart confirmé | [handler/login.c:16-26](handler/login.c#L16) |
| Anti-énumération | Même message `"Invalid credentials"` pour user inexistant et mauvais mdp | [handler/login.c:135-165](handler/login.c#L135) |
| SQL injection | Requêtes préparées (`MYSQL_BIND`) sur toutes les requêtes | [DB/db.c:93-145](DB/db.c#L93) |
| Hachage mot de passe | Argon2 via `crypto_pwhash_str` (libsodium) | [utils/password.c:13](utils/password.c#L13) |
| Entropie des tokens | `randombytes_buf(32 bytes)` = 256 bits d'entropie | [handler/login.c:171](handler/login.c#L171) |
| Token en DB haché | SHA-256 du token brut stocké (jamais le token clair) | [utils/token.c:16](utils/token.c#L16) |
| Token effacé mémoire | `sodium_memzero(token_bytes)` après usage | [handler/login.c:227](handler/login.c#L227) |
| Validation username | Longueur (≤50) + alphanumérique + `-` `_` uniquement | [handler/register.c:43-58](handler/register.c#L43) |
| Rejet grands buffers | Headers > 8192 → 400, Body > 65536 → 400 | [server/server.c:214-301](server/server.c#L214) |
| UUID aléatoires | IDs utilisateurs et requêtes générés par `uuid_generate_random` | [handler/register.c:27](handler/register.c#L27) |
| Timeout client | `SO_RCVTIMEO = 5s` protège contre les connexions éternelles | [server/server.c:171](server/server.c#L171) |

---

## Plan de remédiation (ordre de priorité)

### Priorité 1 — Corrections immédiates (< 1 jour)

1. **VULN-10** : Remplacer `exit(-1)` par `return NULL` dans `db_connect()` → évite le crash serveur sur erreur DB ok
2. **VULN-01** : Ajouter les vérifications de longueur sur `first_name` et `last_name` ok
3. **VULN-11** : Ajouter `sodium_memzero(pwd_buff, sizeof(pwd_buff))` dans `login_handler` ok

### Priorité 2 — Corrections courantes (< 1 semaine)

4. **VULN-04** : Implémenter un compteur de tentatives par IP (in-memory, table hash)
5. **VULN-12** : Implémenter `middleware/auth.c` pour vérifier `expired_at`
6. **VULN-05** : Supprimer les vieux tokens à la connexion
7. **VULN-02** : Ajouter validation des caractères pour `first_name` / `last_name` ok
8. **VULN-14** : Sortir `.env` du versioning git

### Priorité 3 — Améliorations qualité (< 1 mois)

9. **VULN-07/08/09** : Migrer vers architecture multi-thread (pthreads) ou I/O multiplexée (select/epoll)
10. **VULN-06** : Corriger le routing pour retourner 405 avec header `Allow`
11. **VULN-03** : Ajouter validation du `Content-Type`
12. **VULN-13** : Ajouter `Cache-Control: no-store` et `Connection: close` dans les réponses

---

## Scripts de test

Les scripts sont disponibles dans [`tests/`](tests/) :

| Script | Couverture |
|---|---|
| [`test_audit_validation.sh`](tests/test_audit_validation.sh) | Validation des champs, longueurs, caractères, types |
| [`test_audit_http.sh`](tests/test_audit_http.sh) | Protocole HTTP, buffers, méthodes, paths |
| [`test_audit_auth.sh`](tests/test_audit_auth.sh) | Timing attack, brute force, entropie tokens |
| [`test_audit_dos.sh`](tests/test_audit_dos.sh) | Slow HTTP, Content-Length mensonger, saturation backlog |

**Lancement :**
```bash
bash tests/test_audit_validation.sh
bash tests/test_audit_http.sh
bash tests/test_audit_auth.sh
bash tests/test_audit_dos.sh
```
