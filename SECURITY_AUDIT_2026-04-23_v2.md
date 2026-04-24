# Rapport d'Audit de Sécurité — api_server_in_c

**Date :** 2026-04-23
**Version :** 2 (après corrections)
**Branche :** `feature/authentification`
**Méthodologie :** Analyse statique exhaustive + filtrage multi-agents (seuil de confiance ≥ 8/10)

---

## Résumé Exécutif

| Criticité | Nombre |
|-----------|--------|
| CRITIQUE  | 0      |
| HIGH      | 0      |
| MEDIUM    | 0      |
| **Total** | **0**  |

> Aucune vulnérabilité exploitable n'a été confirmée dans l'état actuel du code.
> Les 5 candidats identifiés ont tous été écartés après filtrage rigoureux des faux positifs.

---

## Candidats analysés et écartés

### Candidat 1 — Token en clair dans la réponse HTTP
- **Fichier :** `handler/login.c:190`
- **Verdict :** FAUX POSITIF (confiance 1/10)
- **Raison :** Envoyer le token en clair dans la réponse de login est le comportement **attendu** d'une API bearer token. Le token n'est ni loggé, ni écrit sur disque. L'absence de `sodium_memzero()` sur `token_hex` est une mesure de durcissement facultative, pas une vulnérabilité concrète.

### Candidat 2 — Pas d'authentification sur les routes protégées
- **Fichier :** `router/router.c:27-50`
- **Verdict :** FAUX POSITIF (confiance 3/10)
- **Raison :** Les routes protégées retournent 501 et ont toutes `handler = NULL`. Aucune donnée n'est accessible aujourd'hui. Il s'agit d'une implémentation incomplète, pas d'un bypass exploitable dans l'état actuel.

### Candidat 3 — NULL deref sur le résultat MySQL dans login.c
- **Fichier :** `handler/login.c:121`
- **Verdict :** FAUX POSITIF (confiance 2/10)
- **Raison :** Le buffer `pwd_hashed` est initialisé à `{0}`. La colonne `password_hash` est définie `NOT NULL` en base (`V1__create_users.sql:6`), ce qui rend le scénario impossible. Même théoriquement, cela provoquerait un échec de vérification, pas un bypass.

### Candidat 4 — `strchr()` non borné dans dotenv
- **Fichier :** `dotenv/dotenv.c:36`
- **Verdict :** EXCLU D'OFFICE (confiance 0.75 < seuil 0.80)
- **Raison :** `fgets()` borne déjà la lecture. Pas de chemin d'exploitation concret.

### Candidat 5 — Taille du buffer mot de passe dans login.c
- **Fichier :** `handler/login.c:56-57`
- **Verdict :** FAUX POSITIF (confiance 2/10)
- **Raison :** `strncpy()` avec `PASSWORD_HASH_MAX-1` empêche tout débordement. `crypto_pwhash_str_verify()` gère des mots de passe de longueur arbitraire en toute sécurité. Il s'agit d'une politique de sécurité, pas d'une vulnérabilité.

---

## État global du projet

### Ce qui a été corrigé depuis l'audit initial (2026-04-19)

| # | Vulnérabilité | Statut |
|---|---|---|
| 2 | Tokens stockés en clair en base | **CORRIGÉ** — `hash_token()` + colonne `token_hash` |
| 4 | NULL deref sur `getenv()` | **CORRIGÉ** — vérifications NULL + `return -1` partout |
| 5 | `client_addr_len` non initialisé | **CORRIGÉ** — `sizeof(client_addr)` |
| 6 | Troncature silencieuse du buffer `recv` | **CORRIGÉ** — `BUFFER_SIZE` = 8192 + boucle de lecture complète |
| 7 | Buffer de réponse HTTP trop petit | **CORRIGÉ** — `malloc(http_respon_len+1)` dynamique |
| 8 | Buffer de hash inconsistant | **CORRIGÉ** — `PASSWORD_HASH_MAX` + `_Static_assert` + `VARCHAR(256)` |
| 9 | `printf` + `exit()` dans dotenv | **CORRIGÉ** — `LOG_ERROR` + `return -1` + cleanup mémoire |
| 10 | Vérification incohérente INSERT | **CORRIGÉ** — cas `insert == 0` géré ligne 151 |

### Ce qui reste à implémenter (non exploitable aujourd'hui)

| # | Sujet | Fichiers concernés |
|---|---|---|
| 1 | Middleware d'authentification (TODO) | `middleware/auth.c`, `router/router.c` |
| 3 | Vérification expiration token (`expired_at > NOW()`) | `middleware/auth.c` |

> Ces deux points ne sont pas des vulnérabilités dans l'état actuel du code (routes retournent 501, aucun handler connecté). Ils deviendront des vulnérabilités CRITIQUES dès qu'un handler sera branché sur une route protégée sans que le middleware soit implémenté.

---

## Recommandation avant merge

**Une seule action bloquante :** implémenter le middleware `auth_verify_token()` dans `middleware/auth.c` avec la requête :

```sql
SELECT user_id FROM tokens WHERE token_hash = ? AND expired_at > NOW()
```

Et l'appeler dans `router/router.c` à la place du `// TODO` ligne 29, **avant** de connecter tout handler sur une route protégée.

---

*Audit du 2026-04-23 v2 — branche `feature/authentification`*
