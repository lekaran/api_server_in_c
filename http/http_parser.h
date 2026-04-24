#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

// Limites de taille pour chaque champ.
// Suffisantes pour une API REST classique.
#define HTTP_MAX_METHOD    16
#define HTTP_MAX_PATH      512
#define HTTP_MAX_VERSION   16
#define HTTP_MAX_HDR_NAME  128
#define HTTP_MAX_HDR_VALUE 1024
#define HTTP_MAX_HEADERS   32

// Un header HTTP : une paire clé/valeur.
// Le nom est stocké en minuscules pour faciliter la recherche.
typedef struct {
    char name[HTTP_MAX_HDR_NAME];
    char value[HTTP_MAX_HDR_VALUE];
} http_header_t;

// La structure qui représente une requête HTTP parsée.
typedef struct {
    char method[HTTP_MAX_METHOD];           // "GET", "POST", "PUT", "DELETE"
    char path[HTTP_MAX_PATH];               // "/login", "/profile"
    char version[HTTP_MAX_VERSION];         // "HTTP/1.1"
    http_header_t headers[HTTP_MAX_HEADERS];
    int  header_count;
    const char *body;   // pointeur dans le buffer original — ne pas free()
    int  body_len;
} http_request_t;

// Parse une requête HTTP brute (buf, len) dans la structure req.
// Retourne 0 si OK, -1 si la requête est malformée.
//
// IMPORTANT : req.body pointe DANS buf. buf doit rester valide
// tant que req est utilisé.
int http_parse_request(const char *buf, int len, http_request_t *req);

// Cherche un header par nom (insensible à la casse).
// Retourne la valeur du header, ou NULL s'il n'existe pas.
const char *http_get_header(const http_request_t *req, const char *name);

#endif
