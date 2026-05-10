#ifndef LOGOUT_H
#define LOGOUT_H

#include "../http/http_parser.h"

#include <string.h>

/**
 * Init the login from hashed a dummy pwd
 */
int logout_handler(http_request_t *req, char *body_out, size_t body_out_size);


#endif 