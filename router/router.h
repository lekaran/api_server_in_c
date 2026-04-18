#ifndef ROUTER_H
#define ROUTER_H

#include "../http/http_parser.h"

#include <string.h>

typedef int(*handler_func_t)(http_request_t *req, char *body_out, size_t body_out_size); // standard du handler que le router doit utiliser.

typedef struct {
    char methode[HTTP_MAX_METHOD];
    char path[HTTP_MAX_PATH];
    handler_func_t handler;
    int is_protected; // Nous dis si la route est protéger ou pas.
} route_t;

/**
 * Fonction qui route la requete et lance l'handler coorespondant. 
 */
int router_dispatch(int client_fd, http_request_t *req);

#endif
