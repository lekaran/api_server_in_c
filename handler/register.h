#ifndef REGISTER_H
#define REGISTER_H

#include "../http/http_parser.h"

int register_handler(int client_fd, http_request_t *req);

#endif