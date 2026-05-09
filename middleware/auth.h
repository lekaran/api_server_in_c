#ifndef AUTH_H
#define AUTH_H

#include "../http/http_parser.h"

#include <stddef.h>

/**
 * Function that check the client token and it's validation.
 */
int auth_verify(const http_request_t *req, char *user_id, size_t user_id_len);

#endif
