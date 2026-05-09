#ifndef RATE_LIMIT_H
#define RATE_LIMIT_H

#include "cache.h"

/**
 * Fonction that make the rate limite
 */
int rate_limit_check(redisContext *conn, const char *route, const char *client_ip);

#endif