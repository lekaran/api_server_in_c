# Rapport d'Audit de Sécurité — api_server_in_c

**Date :** 2026-04-19  
**Branche :** feature/authentification  
**Auditeur :** Claude Security Review  

---

## Résumé Exécutif

| Criticité | Nombre |
|-----------|--------|
| CRITIQUE  | 1      |
| HIGH      | 8      |
| MEDIUM    | 1      |
| **Total** | **10** |

> Seuls les findings avec un score de confiance ≥ 8/10 sont inclus.

---

## Vuln 1 — Authentication Bypass : `router/router.c:26-28`

- **Criticité :** CRITIQUE
- **Confiance :** 10/10
- **Catégorie :** authentication_bypass

**Description :** Le champ `is_protected` sur les routes `/logout`, `/profile` (GET/PUT/DELETE) est positionné à `1` mais le code de vérification est un simple commentaire `// TODO`. Aucune vérification de token n'est effectuée — les routes protégées sont accessibles sans authentification.

**Scénario d'exploitation :** Un développeur branche un `profile_handler` sur `GET /profile` sans remarquer le TODO. Comme `is_protected = 1` n'est jamais appliqué, n'importe quel attaquant peut accéder aux données de profil sans token.

**Recommandation :** Implémenter le middleware auth immédiatement en mode **default-deny** : extraire le header `Authorization`, chercher le token en base (`WHERE token = ? AND expired_at > NOW()`), rejeter avec HTTP 401 si le check échoue. Ne jamais avancer vers le handler si la vérification n'est pas passée.

---

## Vuln 2 — Tokens stockés en clair en base : `DB/migrations/V2__create_tokens.sql:4`

- **Criticité :** HIGH
- **Confiance :** 9/10
- **Catégorie :** crypto_weakness

**Description :** La colonne `token CHAR(64)` stocke le token brut (hex 64 chars). Ce token est un bearer token — quiconque le lit peut s'authentifier en tant que l'utilisateur. Une fuite de la base de données (backup S3 exposé, réplica mal configuré, dump SQL) compromet immédiatement toutes les sessions actives.

**Scénario d'exploitation :** Un attaquant obtient un accès en lecture à la table `tokens` (fuite de backup, réplica non sécurisé). Il extrait tous les tokens non expirés et s'authentifie immédiatement en tant que n'importe quel utilisateur actif — sans brute-force nécessaire.

**Recommandation :** Stocker `SHA-256(token)` en base. À chaque requête, calculer `SHA-256(token_présenté)` et comparer. Le token brut ne doit exister qu'en mémoire et dans la réponse HTTP — jamais en base. Même principe que les hash de mots de passe.

---

## Vuln 3 — Expiration des tokens non vérifiée : `DB/migrations/V2__create_tokens.sql:5`

- **Criticité :** HIGH
- **Confiance :** 9/10
- **Catégorie :** authentication_bypass

**Description :** La colonne `expired_at` définit une TTL de 24h dans le schéma SQL, mais aucun code applicatif ne vérifie cette expiration. Même si le middleware auth était implémenté avec un simple `SELECT * FROM tokens WHERE token = ?`, les tokens resteraient valides indéfiniment.

**Scénario d'exploitation :** Un token volé (via un log, un réseau non chiffré, ou une fuite) reste utilisable à vie du point de vue de l'application, quelle que soit la date d'expiration stockée.

**Recommandation :** La requête de validation du token doit inclure : `WHERE token = ? AND expired_at > NOW()`. Ajouter une tâche de nettoyage périodique : `DELETE FROM tokens WHERE expired_at < NOW()`.

---

## Vuln 4 — NULL deref sur `getenv()` : `server/server.c:35,136` et `DB/db.c:21,55`

- **Criticité :** HIGH
- **Confiance :** 9/10
- **Catégorie :** null_dereference

**Description :** `getenv("SERVER_PORT")` est passé directement à `strtol()` sans vérification de NULL. Si la variable n'est pas définie (`.env` absent, malformé, variable manquante), `getenv()` retourne `NULL` → crash garanti. Même problème avec `atoi(getenv("DB_PORT"))` dans `db.c`.

La ligne 136 est dans la boucle infinie de `server_run` — un crash ici tue le process entier au milieu du traitement d'une connexion client.

**Scénario d'exploitation :** Si le fichier `.env` est corrompu ou absent au redémarrage du container, le serveur crashe immédiatement. Si `SERVER_PORT` disparaît en cours d'exécution (cas rare mais possible), chaque nouvelle connexion crashe le process.

**Recommandation :**
```c
const char *port_str = getenv("SERVER_PORT");
if (port_str == NULL) { LOG_ERROR("SERVER_PORT not set"); return -1; }
int server_port = strtol(port_str, &endptr, 10);
```
Appliquer le même pattern pour tous les `getenv()` sans vérification.

---

## Vuln 5 — `client_addr_len` non initialisé : `server/server.c:131,141`

- **Criticité :** HIGH
- **Confiance :** 9/10
- **Catégorie :** memory_safety

**Description :** `socklen_t client_addr_len` est déclaré mais jamais initialisé avant d'être passé à `accept()`. Le syscall utilise cette valeur comme taille maximale pour écrire l'adresse client. Si la valeur de la pile est supérieure à `sizeof(struct sockaddr_in)`, le kernel peut écrire au-delà du buffer — corruption de pile.

**Scénario d'exploitation :** Sur la plupart des kernels Linux modernes, le kernel clamp la valeur réelle, ce qui atténue le risque. Mais c'est un comportement indéfini en C standard, et sur des kernels embarqués ou non-standards, cela pourrait corrompre les variables adjacentes (`uuid_str`, `server_port`).

**Recommandation :**
```c
socklen_t client_addr_len = sizeof(client_addr);
```

---

## Vuln 6 — Troncature silencieuse du buffer `recv` : `server/server.c:155-158`

- **Criticité :** HIGH
- **Confiance :** 9/10
- **Catégorie :** input_validation

**Description :** `BUFFER_SIZE = 1024` bytes. Un seul appel `recv()` lit au maximum 1023 bytes. Toute requête HTTP avec headers + body dépassant 1023 bytes est **silencieusement tronquée**. Le parser reçoit un message incomplet, `req->body` pointe dans ce buffer tronqué, et `req->body_len` est calculé incorrectement.

**Scénario d'exploitation :** Un attaquant envoie un POST avec un body de 2 KB. Le serveur ne lit que les 1023 premiers bytes. Selon la position du JSON dans le buffer, `cJSON_Parse` peut réussir sur un document partiel, avec des champs ayant des valeurs contrôlées et d'autres vides — comportement imprévisible pour les handlers.

**Recommandation :** Augmenter `BUFFER_SIZE` à 8192 minimum. Implémenter une boucle de lecture jusqu'à trouver `\r\n\r\n`, puis lire exactement `Content-Length` bytes supplémentaires. Valider que `Content-Length` est présent et raisonnable (cap à 64 KB).

---

## Vuln 7 — Buffer de réponse HTTP trop petit : `http/http_response.c:99-100`

- **Criticité :** HIGH
- **Confiance :** 8/10
- **Catégorie :** buffer_overflow

**Description :** La réponse HTTP est construite avec `snprintf` dans un buffer fixe de 1024 bytes. Si le body + les headers HTTP dépassent 1024 bytes, `snprintf` tronque silencieusement. Le header `Content-Length` annonce la taille complète, mais seule une partie du body est envoyée — HTTP response splitting/smuggling.

**Scénario d'exploitation :** Si `BODY_MAX` est augmenté ou qu'un futur handler produit un body plus long, le client reçoit `Content-Length: 600` mais seulement une partie du body. Les clients HTTP qui font confiance à `Content-Length` se bloquent ou misparsent la réponse.

**Recommandation :** Calculer dynamiquement la taille nécessaire : `header_len + body_len + 1`. Vérifier le retour de `snprintf` et retourner une erreur si troncature détectée. Alternative : construire la réponse en deux `send()` (headers puis body).

---

## Vuln 8 — Buffer de hash inconsistant : `handler/login.c:74` et `models/user.h`

- **Criticité :** HIGH
- **Confiance :** 8/10
- **Catégorie :** crypto_weakness

**Description :** `pwd_hashed[256]` dans `login.c` est une constante magique non liée à `PASSWORD_HASH_MAX`. La colonne SQL `password_hash VARCHAR(255)` est à 255 bytes alors que `PASSWORD_HASH_MAX = 256`. Si libsodium augmente `crypto_pwhash_STRBYTES` au-delà de 255 (ce qui est arrivé par le passé), MySQL tronque silencieusement le hash stocké, causant l'échec permanent de `crypto_pwhash_str_verify` pour tous les utilisateurs.

**Scénario d'exploitation :** Une mise à jour de libsodium augmente la taille de sortie. Tous les nouveaux mots de passe hashés sont tronqués en base → tous les nouveaux utilisateurs ne peuvent plus se connecter. Les anciens hashes pourraient aussi être corrompus selon le mécanisme de migration.

**Recommandation :** 
1. Remplacer `char pwd_hashed[256]` par `char pwd_hashed[PASSWORD_HASH_MAX]`
2. Changer la colonne SQL en `VARCHAR(256)` 
3. Ajouter : `_Static_assert(PASSWORD_HASH_MAX >= crypto_pwhash_STRBYTES, "PASSWORD_HASH_MAX trop petit");`

---

## Vuln 9 — `printf` + `exit()` dans dotenv : `dotenv/dotenv.c:11-14`

- **Criticité :** MEDIUM
- **Confiance :** 8/10
- **Catégorie :** sensitive_data_exposure

**Description :** Toutes les erreurs de `dotenv.c` utilisent `printf()` vers stdout au lieu du logger du projet, et appellent `exit()` directement. Cela bypasse le système de logs, peut exposer des messages d'erreur dans des streams capturés (Docker logs, CI), et ne laisse aucune chance au code appelant de gérer l'erreur proprement.

**Scénario d'exploitation :** Dans un environnement Docker avec log driver configuré pour envoyer stdout vers un service de monitoring public, les erreurs de parsing du `.env` (incluant potentiellement des noms de variables sensibles) sont exposées.

**Recommandation :** Remplacer tous les `printf` + `exit()` par `LOG_ERROR` + `return -1`. Une fonction de bibliothèque ne doit jamais appeler `exit()`.

---

## Vuln 10 — Vérification incohérente du résultat INSERT : `handler/login.c:164` vs `handler/register.c:130`

- **Criticité :** MEDIUM
- **Confiance :** 8/10
- **Catégorie :** logic_error

**Description :** `login.c` vérifie `insert <= 0` (correct), mais `register.c` vérifie `insert < 0`, laissant passer le cas `insert == 0` (aucune ligne insérée) sans erreur. Un INSERT qui ne crée aucune ligne est traité comme un succès dans `register.c`, retournant HTTP 201 sans que l'utilisateur soit réellement créé.

**Scénario d'exploitation :** Dans des conditions de race condition ou de contrainte MySQL non capturée par les codes d'erreur explicitement gérés, un INSERT peut retourner 0 rows affected. `register.c` retourne alors 201 à l'utilisateur alors que son compte n'existe pas — il peut ensuite tenter de se logger sans succès.

**Recommandation :** Standardiser les deux handlers sur `if (insert <= 0)`. Documenter le contrat de `db_execute()` : `> 0` = succès, `0` = aucune ligne (erreur), `< 0` = erreur MySQL.

---

## Plan de remédiation priorisé

### Priorité 1 — Avant tout déploiement (CRITIQUE/HIGH)

| # | Action | Fichier |
|---|--------|---------|
| 1 | Implémenter le middleware auth (default-deny) | `middleware/auth.c`, `router/router.c` |
| 2 | Hacher les tokens avant stockage (SHA-256) | `handler/login.c`, `DB/migrations/V2` |
| 3 | Ajouter `AND expired_at > NOW()` dans la validation token | `middleware/auth.c` |
| 4 | Valider tous les `getenv()` avant usage | `server/server.c`, `DB/db.c` |
| 5 | Initialiser `client_addr_len = sizeof(client_addr)` | `server/server.c` |
| 6 | Augmenter `BUFFER_SIZE` + implémenter lecture complète | `server/server.c` |
| 7 | Fixer le buffer de réponse HTTP | `http/http_response.c` |
| 8 | Aligner `PASSWORD_HASH_MAX`, `pwd_hashed[N]` et `VARCHAR(N)` | `login.c`, `user.h`, `V1__create_users.sql` |

### Priorité 2 — Bonne pratique (MEDIUM)

| # | Action | Fichier |
|---|--------|---------|
| 9 | Remplacer `printf`/`exit()` par `LOG_ERROR`/`return -1` | `dotenv/dotenv.c` |
| 10 | Uniformiser la vérification `insert <= 0` | `handler/register.c` |

---

*Rapport généré le 2026-04-19 — À mettre à jour après chaque cycle de corrections.*
