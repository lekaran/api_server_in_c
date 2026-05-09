#ifndef CACHE_H
#define CACHE_H

#include <hiredis/hiredis.h>

/**
 * Fonction qui test la connexion avec le cache Redis
 */
int cache_healthcheck(void);

/**
 * Fonction qui va permetre au handler de se connecter au cache Redis
 */
redisContext *cache_connect(void);

/**
 * Fonction qui execute un query vers le cache Redis
 */
redisReply *cache_execute(redisContext *conn, const char *query);

/**
 * Fonction qui ferme la connection au cache Redis
 */
void cache_close(redisContext *conn);

#endif