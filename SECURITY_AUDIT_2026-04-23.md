# Rapport de Re-Audit de Sécurité — api_server_in_c

**Date :** 2026-04-23
**Branche :** `feature/authentification`
**Référence :** Re-audit basé sur `SECURITY_AUDIT.md` du 2026-04-19
**Méthodologie :** Analyse statique + filtrage multi-agents (seuil de confiance ≥ 8/10)

---

## Tableau de suivi des 10 vulnérabilités originales

| # | Criticité originale | Titre | Statut |
|---|---|---|---|
| 1 | CRITIQUE | Authentication Bypass — middleware non implémenté | **OUVERT** |
| 2 | HIGH | Tokens stockés en clair | **CORRIGÉ** |
| 3 | HIGH | Expiration des tokens non vérifiée | **OUVERT** |
| 4 | HIGH | NULL deref sur `getenv()` | **CORRIGÉ** |
| 5 | HIGH | `client_addr_len` non initialisé | **CORRIGÉ** |
| 6 | HIGH | Troncature silencieuse du buffer `recv` | **CORRIGÉ** |
| 7 | HIGH | Buffer de réponse HTTP trop petit | **CORRIGÉ** |
| 8 | HIGH | Buffer de hash inconsistant | **CORRIGÉ** |
| 9 | MEDIUM | `printf` + `exit()` dans dotenv | **OUVERT** |
| 10 | MEDIUM | Vérification incohérente résultat INSERT | **OUVERT** |

---

## Corrections confirmées

### Vuln 2 — Tokens stockés en clair : CORRIGÉ
`handler/login.c:146-151` : Le token brut est maintenant hashé via `hash_token()` avant insertion. La colonne en base est renommée `token_hash`. Le token en clair ne quitte plus jamais la mémoire de l'application.

### Vuln 4 — NULL deref sur `getenv()` : CORRIGÉ
`server/server.c:35` et `DB/db.c:17-26` : Tous les appels `getenv()` sont maintenant suivis d'une vérification `NULL` avec `LOG_ERROR` et `return -1`.

### Vuln 5 — `client_addr_len` non initialisé : CORRIGÉ
`server/server.c:132` : `socklen_t client_addr_len = sizeof(client_addr);` — correctement initialisé.

### Vuln 6 — Troncature silencieuse du buffer `recv` : CORRIGÉ
`server/server.c:163-280` : `BUFFER_SIZE` porté à 8192 bytes. La lecture s'effectue en deux boucles (headers jusqu'à `\r\n\r\n`, puis body sur `Content-Length` bytes). La contrainte `BUFFER_SIZE-total_recu-1` dans chaque `recv()` garantit l'absence de dépassement.

### Vuln 7 — Buffer de réponse HTTP trop petit : CORRIGÉ
`http/http_response_builder.c:131-133` : La réponse est maintenant construite dans un buffer alloué dynamiquement avec `malloc(http_respon_len+1)`, calculé précisément en fonction de la taille réelle des headers et du body. Plus de troncature possible.

---

## Vulnérabilités confirmées encore ouvertes

### Vuln 1 — Middleware d'authentification inexistant : OUVERT
- **Criticité :** CRITIQUE
- **Confiance :** 9/10
- **Fichiers :** `middleware/auth.c`, `middleware/auth.h`, `router/router.c:27-49`

**État actuel :** `auth.c` contient uniquement `#include "auth.h"`. `auth.h` contient uniquement les guards. La vérification du token dans `router.c` est un commentaire `// TODO`. Les routes protégées (`/logout`, `/profile` GET/PUT/DELETE) retournent actuellement 501.

**Risque immédiat :** Dès qu'un handler sera branché sur une route protégée, il sera accessible sans aucune vérification de token. Le `is_protected = 1` ne fait rien.

**Recommandation :**
```c
// Dans router_dispatch(), remplacer le TODO par :
int auth_result = auth_verify_token(req, &user_id);
if (auth_result != 0) {
    // envoyer 401 Unauthorized
    return 401;
}
// puis appeler le handler
```
La requête SQL de validation doit être : `SELECT user_id FROM tokens WHERE token_hash=? AND expired_at > NOW()`

---

### Vuln 3 — Expiration des tokens jamais vérifiée : OUVERT
- **Criticité :** HIGH
- **Confiance :** 9/10
- **Fichier :** `DB/migrations/V2__create_tokens.sql`

**État actuel :** La colonne `expired_at DATETIME DEFAULT (DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 24 HOUR))` existe bien en base, mais aucun code applicatif ne vérifie cette valeur. Dépend directement de Vuln 1.

**Recommandation :** La requête de validation dans le middleware (Vuln 1) doit impérativement inclure `AND expired_at > NOW()`. Ajouter aussi un nettoyage périodique : `DELETE FROM tokens WHERE expired_at < NOW()`.

---

### Vuln 8 — Buffer de hash inconsistant : CORRIGÉ
- **Fichiers :** `handler/login.c:75`, `models/user.h`, `DB/migrations/V1__create_users.sql`

Les trois corrections sont en place :
- `login.c:75` : `char pwd_hashed[PASSWORD_HASH_MAX]={0}` — la constante magique `256` remplacée par `PASSWORD_HASH_MAX`
- `models/user.h:13` : `_Static_assert(PASSWORD_HASH_MAX >= crypto_pwhash_STRBYTES, ...)` — bloque la compilation si libsodium grossit
- `V1__create_users.sql:6` : `password_hash VARCHAR(256)` — aligné avec `PASSWORD_HASH_MAX`

---

### Vuln 9 — `printf` + `exit()` dans dotenv : OUVERT
- **Criticité :** MEDIUM
- **Confiance :** 8/10
- **Fichier :** `dotenv/dotenv.c:13-14`, `dotenv/dotenv.c:20-22`, `dotenv/dotenv.c:41-43`

**État actuel :** Cinq appels `exit()` dans `load_env_file()`. Une fonction de bibliothèque qui appelle `exit()` empêche tout nettoyage (`log_close()`, fermeture des sockets, des connexions DB), bypasse le système de logs, et rend le module non testable unitairement.

**Recommandation :** Remplacer chaque `printf(...); exit(N);` par `LOG_ERROR(...); return -1;`. L'appelant (`server_init`) gère déjà le retour d'erreur de `load_env_file()`.

---

### Vuln 10 — Vérification incohérente du résultat INSERT : OUVERT
- **Criticité :** MEDIUM
- **Confiance :** 9/10
- **Fichier :** `handler/register.c:130`

**État actuel :**
```c
// register.c ligne 130 — INCORRECT
if (insert < 0) { ... }

// login.c ligne 173 — CORRECT
if (insert <= 0) { ... }
```

`db_execute()` retourne `mysql_stmt_affected_rows()` qui vaut `0` si aucune ligne n'est insérée. Avec `insert < 0`, le cas `insert == 0` passe silencieusement : le serveur retourne HTTP 201 "User created" alors que l'utilisateur n'a pas été créé en base.

**Recommandation :** Changer ligne 130 de `register.c` en `if (insert <= 0)`.

---

## Plan de remédiation mis à jour

### Priorité 1 — Avant tout merge (CRITIQUE/HIGH)

| # | Action | Fichier | Effort |
|---|---|---|---|
| 1 | Implémenter le middleware auth (default-deny) | `middleware/auth.c`, `router/router.c` | Élevé |
| 2 | Ajouter `AND expired_at > NOW()` dans la validation token | `middleware/auth.c` | Faible |
| 3 | Vérifier et commiter le changement `VARCHAR(256)` dans la migration SQL | `DB/migrations/V1__create_users.sql` | Faible |

### Priorité 2 — Bonne pratique (MEDIUM)

| # | Action | Fichier | Effort |
|---|---|---|---|
| 4 | Remplacer `printf`/`exit()` par `LOG_ERROR`/`return -1` | `dotenv/dotenv.c` | Faible |
| 5 | Uniformiser `insert <= 0` | `handler/register.c:130` | Trivial |

---

## Résumé exécutif

| Statut | Nombre |
|---|---|
| **Corrigés** depuis le dernier audit | **6** (Vulns 2, 4, 5, 6, 7, 8) |
| **Partiellement corrigés** | **0** |
| **Encore ouverts** | **4** (Vulns 1, 3, 9, 10) |

La branche a progressé significativement. Les deux corrections les plus structurantes restantes sont l'implémentation du middleware d'authentification (Vuln 1 + 3) et la vérification de la migration SQL (Vuln 8).

---

*Re-audit du 2026-04-23 — branche `feature/authentification`*
