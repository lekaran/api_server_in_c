#ifndef REGISTER_H
#define REGISTER_H

#include "../http/http_parser.h"

#include <string.h>

int register_handler(http_request_t *req, char *body_out, size_t body_out_size);

#endif