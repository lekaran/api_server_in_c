# Rapport d'Audit de Sécurité — Black Box (v2)
**Cible** : `http://127.0.0.1:8080`  
**Routes** : `POST /register`, `POST /login`  
**Base de données** : MySQL  
**Date** : 2026-04-25  
**Méthode** : Black-box (aucun accès au code source pendant les tests)  
**Script** : `tests/test_audit_blackbox.sh`  
**Version** : 2 — après corrections du 2026-04-25

---

## Résumé Exécutif

| Sévérité      | Nombre |
|---------------|--------|
| 🔴 Critique    | 0      |
| 🟠 Haute       | 1      |
| 🟡 Moyenne     | 1      |
| 🔵 Faible      | 1      |
| ℹ️ Informatif  | 2      |
| ✅ Corrigé depuis v1 | 7 vulnérabilités |

**Score de maturité : 56 PASS / 0 FAIL / 3 vulnérabilités réelles sur 62 tests.**

L'API a progressé de façon significative depuis le premier audit. Les 7 vulnérabilités précédentes ont été corrigées (politique de mot de passe, mass assignment, null bytes, headers de sécurité, case sensitivity, route 501, messages d'erreur). Le seul risque majeur restant est l'**absence totale de rate limiting**, qui rend le service vulnérable au brute force et à la création massive de comptes.

---

## Résultats des tests par section

| Section | Tests | PASS | VULN | Notes |
|---------|-------|------|------|-------|
| 1. SQL Injection | 7 | 5 | 2* | *2 faux positifs dans le script |
| 2. Security Headers | 6 | 6 | 0 | Tous les headers requis présents |
| 3. CORS | 2 | 2 | 0 | |
| 4. Mass Assignment | 3 | 1 | 0 | +2 INFO |
| 5. Command/SSTI | 4 | 4 | 0 | |
| 6. Null bytes & Encoding | 4 | 2 | 0 | +2 INFO |
| 7. Case Sensitivity | 2 | 2 | 0 | |
| 8. HTTP Verb Tunneling | 3 | 0 | 0 | +3 INFO (comportement attendu) |
| 9. Host Header | 3 | 2 | 0 | +1 INFO |
| 10. Route Discovery | 1 | 1 | 0 | |
| 11. Password Policy | 9 | 9 | 0 | |
| 12. Response Analysis | 4 | 4 | 0 | |
| 13. Brute Force / Rate Limiting | 3 | 1 | 2 | **Vulnérabilité réelle** |
| 14. Champs manquants / JSON malformé | 5 | 5 | 0 | |
| 15. Oversized Payloads | 3 | 3 | 0 | |
| 16. Content-Type Bypass | 4 | 2 | 1 | +1 INFO |
| 17. Sécurité du Token | 4 | 4 | 0 | +1 INFO |
| 18. Type Confusion JSON | 4 | 4 | 0 | |

---

## 1. Vulnérabilités Trouvées

---

### VULN-BB-008 — Absence de Rate Limiting (Brute Force / Account Spam)
**Sévérité** : 🟠 Haute  
**Catégorie** : Authentication Weakness (OWASP A07:2021), DoS (OWASP A05:2021)  
**Tests** : 13.1, 13.3

**Description**  
Aucun mécanisme de limitation de débit n'est en place sur `/login` ni sur `/register`. Un attaquant peut faire autant de requêtes qu'il souhaite sans être ralenti, bloqué ou averti.

**Preuve**
```bash
# Test 13.1 : 20 tentatives de login avec mauvais mot de passe
for i in $(seq 1 20); do
    curl -s -X POST http://127.0.0.1:8080/login \
        -d '{"username":"target","password":"wrong_N"}'
done
# → HTTP 401 indéfiniment, jamais 429 ni 423

# Test 13.3 : 50 créations de comptes en rafale
for i in $(seq 1 50); do
    curl -s -X POST http://127.0.0.1:8080/register \
        -d '{"username":"flood_X","password":"Str0ng@Npass"}'
done
# → HTTP 201 pour chacun, aucun blocage
```

**Impact**
- **Brute force sur `/login`** : un attaquant peut tester des millions de mots de passe contre un compte cible. Sans bcrypt fatigue (bcrypt est lent mais pas infini), et sans blocage, une attaque par dictionnaire est faisable.
- **Account spam sur `/register`** : création massive de faux comptes (bots, pollution de base de données, épuisement des ressources MySQL).
- **Sans rate limiting IP**, le header `X-Forwarded-For: 127.0.0.1` (test 9.3) permet potentiellement de spoofer l'IP source si le serveur se base dessus pour compter les tentatives.

**Remédiation**  
Plusieurs niveaux de protection, du plus simple au plus robuste :

1. **Niveau 1 — Délai progressif** : augmenter le temps de réponse exponentiellement après N échecs
2. **Niveau 2 — Lockout temporaire** : bloquer le compte après 5 échecs pendant 15 minutes
3. **Niveau 3 — Rate limiting IP** : max 10 requêtes/minute par IP (attention au X-Forwarded-For)
4. **Niveau 4 — Token bucket / leaky bucket** : algorithme dédié pour /register et /login

```c
// Exemple simple : compteur en mémoire par username
typedef struct { int attempts; time_t last_attempt; } LoginAttempt;
// Si attempts >= 5 && (now - last_attempt) < 900 → retourner 429
```

---

### VULN-BB-009 — Content-Type non validé sur les endpoints
**Sévérité** : 🟡 Moyenne  
**Catégorie** : Input Validation (CWE-20)  
**Tests** : 16.1, 16.4

**Description**  
Le serveur accepte et traite les requêtes JSON quel que soit le `Content-Type` déclaré par le client. Une requête avec `Content-Type: text/plain` ou sans aucun `Content-Type` est traitée identiquement à `Content-Type: application/json`.

**Preuve**
```bash
# Test 16.4 : Content-Type: text/plain avec body JSON → HTTP 201
curl -s -X POST http://127.0.0.1:8080/login \
    -H "Content-Type: text/plain" \
    -d '{"username":"user","password":"Pass@123!"}'
# → HTTP 201 {"token":"..."}

# Test 16.1 : Aucun Content-Type → HTTP 201
curl -s -X POST http://127.0.0.1:8080/login \
    -d '{"username":"user","password":"Pass@123!"}'
# → HTTP 201 {"token":"..."}
```

**Impact**  
- Comportement non déterministe si d'autres `Content-Type` (multipart, form-urlencoded) provoquent des interprétations différentes côté parser
- Absence de protection contre certaines attaques CSRF où le navigateur n'autorise pas `Content-Type: application/json` pour des requêtes cross-origin simples mais autorise `text/plain`
- Violation du principe de contrat API strict

**Remédiation**  
```c
// Vérifier le Content-Type avant de parser le body
const char *ct = get_header(req, "Content-Type");
if (!ct || strncasecmp(ct, "application/json", 16) != 0) {
    return send_error(conn, 415, "Unsupported Media Type");
}
```

---

### VULN-BB-010 — Faux Positifs dans le Script (Tests 1.5 et 1.6)
**Sévérité** : 🔵 Faible (qualité du script, non une vulnérabilité serveur)  
**Catégorie** : Script / Test Quality

**Description**  
Les tests 1.5 et 1.6 détectent à tort une « SQL error disclosure » car le grep recherche la chaîne `"error"` qui est présente dans la clé JSON `{"error":"Invalid request"}` et `{"error":"Invalid credentials"}` — ce n'est pas une fuite MySQL, c'est le nom du champ JSON lui-même.

**Réponses réelles (aucune fuite) :**
```json
// Test 1.5 — /register avec SQLi dans username
{"error":"Invalid request"}

// Test 1.6 — /login avec SQLi dans password
{"error":"Invalid credentials"}
```

**Remédiation du script** : affiner le pattern grep pour exclure les faux positifs :
```bash
# Remplacer
if echo "$RESP" | grep -qiE "mysql|syntax|sql|query|table|column|errno|exception|stack|trace|warning"; then
# Par un test qui exclut les réponses JSON standards :
if echo "$RESP" | grep -qiE "mysql_|syntax error|You have an error in your SQL|errno:|at line [0-9]"; then
```

---

## 2. Points Informatifs (non bloquants)

---

### INFO-01 — Password avec Emoji accepté (test 6.4)
**Risque** : Très faible  

Un password contenant un emoji (`Pass🔑123`) est accepté avec HTTP 201. Techniquement, bcrypt tronque les inputs à **72 bytes**. Un emoji UTF-8 occupe 4 bytes, donc un password très long avec des emojis pourrait créer des collisions (deux passwords différents → même hash si les 72 premiers bytes sont identiques). Le risque est quasi-nul en pratique car les emojis dans les passwords sont rares, mais le comportement mérite d'être documenté.

---

### INFO-02 — Token hex opaque stocké en clair possible (test 17.2)
**Risque** : Faible (black-box, non confirmé)  

Le token retourné est un hex de 256 bits — format sain. Cependant, si ce token est stocké **en clair en base de données** (plutôt que hashé), une compromission de la DB exposerait directement toutes les sessions actives. Recommandation : stocker le hash SHA-256 du token en DB, comparer les hashes lors de la validation.

---

## 3. Corrections Confirmées Depuis l'Audit v1

| ID v1 | Vulnérabilité | Statut | Preuve |
|-------|--------------|--------|--------|
| VULN-BB-001 | Politique mot de passe inexistante | ✅ Corrigé | Tous les passwords faibles → HTTP 400 |
| VULN-BB-002 | Mass assignment (champs extras) | ✅ Corrigé | `role`, `is_admin`, `id` extras → HTTP 400 |
| VULN-BB-003 | Null byte dans username | ✅ Corrigé | ` ` → HTTP 400 |
| VULN-BB-004 | Username case-insensitive | ✅ Corrigé | Usernames mixte-casse rejetés → HTTP 400 |
| VULN-BB-005 | Headers de sécurité absents | ✅ Corrigé | Tous présents : X-Frame-Options, X-Content-Type-Options, CSP, Cache-Control, Referrer-Policy |
| VULN-BB-006 | Route /profile → HTTP 501 | ✅ Corrigé | → HTTP 404 désormais |
| VULN-BB-007 | Message d'erreur révèle le filtre | ✅ Corrigé | Tous uniformisés → `{"error":"Invalid request"}` |

---

## 4. Ce Qui Résiste Bien

| Vecteur testé | Résultat | Détail |
|---|---|---|
| SQL injection login bypass (`' OR '1'='1`) | ✅ Bloqué | HTTP 400 |
| SQL injection commentaire (`admin'--`) | ✅ Bloqué | HTTP 400 |
| Time-based blind SQLi (`SLEEP(3)`) | ✅ Bloqué | 24ms — aucun délai induit |
| UNION SELECT | ✅ Bloqué | HTTP 400 |
| Stacked queries (`'; DROP TABLE users; --`) | ✅ Bloqué | Serveur intact |
| Command injection (`;ls /`, `$(id)`) | ✅ Bloqué | HTTP 400 |
| SSTI (`{{7*7}}`) | ✅ Bloqué | HTTP 400 |
| Backtick injection | ✅ Bloqué | HTTP 400 |
| CORS wildcard | ✅ OK | Pas de headers CORS |
| CORS Origin: null | ✅ OK | Non reflété |
| Host header injection | ✅ OK | Non reflété |
| X-Forwarded-Host injection | ✅ OK | Non reflété |
| Route discovery (33 routes) | ✅ OK | Aucune route cachée |
| Password policy | ✅ OK | Tous les passwords faibles rejetés |
| Mass assignment | ✅ OK | Champs extras rejetés (HTTP 400) |
| Null byte dans username | ✅ OK | HTTP 400 |
| Payload 1MB | ✅ OK | HTTP 400 |
| Username 10 000 chars | ✅ OK | HTTP 400 |
| Password 1 000 chars | ✅ OK | HTTP 400 |
| JSON malformé / vide | ✅ OK | HTTP 400 |
| Champs manquants | ✅ OK | HTTP 400 |
| Type confusion (int, null, array, objet) | ✅ OK | HTTP 400 |
| Token entropie | ✅ OK | Hex 256 bits, tokens différents à chaque login |
| Username enumeration (timing) | ✅ OK | Delta ~1ms — timing constant |
| Security headers | ✅ OK | X-Frame-Options, X-Content-Type-Options, CSP, Cache-Control, Referrer-Policy présents |
| Server version disclosure | ✅ OK | Header Server absent |
| Messages d'erreur | ✅ OK | `{"error":"Invalid credentials"}` — générique |

---

## 5. Ordre de Correction Recommandé

| Priorité | Vulnérabilité | Effort | Impact |
|----------|--------------|--------|--------|
| 1 | **VULN-BB-008** — Rate limiting /login et /register | Moyen | Haut |
| 2 | **VULN-BB-009** — Validation Content-Type: application/json | Faible | Moyen |
| 3 | **INFO-02** — Hasher les tokens en DB | Faible | Moyen |
| 4 | **INFO-01** — Limiter la taille du password (ex: 128 chars max) | Faible | Très faible |
| 5 | Corriger les faux positifs des tests 1.5/1.6 dans le script | Faible | Qualité |

---

## 6. Récapitulatif des Scores

```
Tests exécutés : 62
PASS           : 56  (90%)
FAIL           : 0
VULNS          : 5   (dont 2 faux positifs du script)
Vulnérabilités réelles : 3
```

**Évolution depuis v1 :**
```
v1 : 7 vulnérabilités réelles
v2 : 3 vulnérabilités réelles (57% de réduction)
```

---

*Audit réalisé avec `tests/test_audit_blackbox.sh` (18 sections, 62 tests) — 2026-04-25*
