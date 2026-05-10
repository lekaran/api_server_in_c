#ifndef PROFILE_H
#define PROFILE_H

#include "../http/http_parser.h"

#include <string.h>

int get_profile_handler(http_request_t *req, char *body_out, size_t body_out_size);

#endif 