#include "http_parser.h"

#include <string.h>
#include <ctype.h>

// Cherche la séquence \r\n dans un buffer à partir de pos, jusqu'à end.
// Retourne un pointeur sur le \r, ou NULL si non trouvé.
static const char *find_crlf(const char *pos, const char *end) {
    while (pos < end - 1) {
        if (pos[0] == '\r' && pos[1] == '\n')
            return pos;
        pos++;
    }
    return NULL;
}

// Convertit une chaîne en minuscules, en place.
static void to_lowercase(char *s) {
    while (*s) {
        *s = (char)tolower((unsigned char)*s);
        s++;
    }
}

int http_parse_request(const char *buf, int len, http_request_t *req) {
    memset(req, 0, sizeof(*req));

    const char *pos = buf;
    const char *end = buf + len;

    // ── 1. Ligne de requête ───────────────────────────────────────────────
    // Format attendu : "METHOD PATH HTTP/VERSION\r\n"

    const char *line_end = find_crlf(pos, end);
    if (line_end == NULL) return -1;

    // Extraire la méthode (tout jusqu'au premier espace)
    const char *sp = memchr(pos, ' ', line_end - pos);
    if (sp == NULL) return -1;
    int method_len = sp - pos;
    if (method_len >= HTTP_MAX_METHOD) return -1;
    memcpy(req->method, pos, method_len);
    req->method[method_len] = '\0';
    pos = sp + 1;

    // Extraire le path (jusqu'au deuxième espace)
    sp = memchr(pos, ' ', line_end - pos);
    if (sp == NULL) return -1;
    int path_len = sp - pos;
    if (path_len >= HTTP_MAX_PATH) return -1;
    memcpy(req->path, pos, path_len);
    req->path[path_len] = '\0';
    pos = sp + 1;

    // Extraire la version (jusqu'au \r\n)
    int version_len = line_end - pos;
    if (version_len >= HTTP_MAX_VERSION) return -1;
    memcpy(req->version, pos, version_len);
    req->version[version_len] = '\0';
    pos = line_end + 2; // sauter le \r\n

    // ── 2. Headers ────────────────────────────────────────────────────────
    // Format : "Name: Value\r\n", répété jusqu'à la ligne vide "\r\n"

    req->header_count = 0;

    while (pos < end) {
        line_end = find_crlf(pos, end);
        if (line_end == NULL) break;

        // Ligne vide = fin des headers
        if (line_end == pos) {
            pos = line_end + 2;
            break;
        }

        if (req->header_count >= HTTP_MAX_HEADERS) {
            pos = line_end + 2;
            continue;
        }

        // Trouver le ":" qui sépare le nom de la valeur
        const char *colon = memchr(pos, ':', line_end - pos);
        if (colon == NULL) {
            pos = line_end + 2;
            continue;
        }

        // Nom du header (converti en minuscules pour la recherche)
        int name_len = colon - pos;
        if (name_len >= HTTP_MAX_HDR_NAME) { pos = line_end + 2; continue; }
        memcpy(req->headers[req->header_count].name, pos, name_len);
        req->headers[req->header_count].name[name_len] = '\0';
        to_lowercase(req->headers[req->header_count].name);

        // Valeur du header (on saute les espaces après le ":")
        const char *val = colon + 1;
        while (val < line_end && *val == ' ') val++;
        int val_len = line_end - val;
        if (val_len >= HTTP_MAX_HDR_VALUE) val_len = HTTP_MAX_HDR_VALUE - 1;
        memcpy(req->headers[req->header_count].value, val, val_len);
        req->headers[req->header_count].value[val_len] = '\0';

        req->header_count++;
        pos = line_end + 2;
    }

    // ── 3. Body ───────────────────────────────────────────────────────────
    // Tout ce qui reste après la ligne vide.
    // body pointe directement dans buf — pas de copie, pas de malloc.

    req->body     = pos;
    req->body_len = (pos < end) ? (int)(end - pos) : 0;

    return 0;
}

const char *http_get_header(const http_request_t *req, const char *name) {
    // Convertir le nom cherché en minuscules pour la comparaison
    char lower[HTTP_MAX_HDR_NAME];
    strncpy(lower, name, HTTP_MAX_HDR_NAME - 1);
    lower[HTTP_MAX_HDR_NAME - 1] = '\0';
    to_lowercase(lower);

    for (int i = 0; i < req->header_count; i++) {
        if (strcmp(req->headers[i].name, lower) == 0)
            return req->headers[i].value;
    }
    return NULL;
}
