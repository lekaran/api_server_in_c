#include "cache.h"
#include "../logger/logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/**
 * Fonction qui test la connexion avec le cache Redis
 */
int cache_healthcheck(void){
    // retrieve environnement variable
    const char *cache_host=getenv("REDIS_HOST");
    if(cache_host == NULL){ LOG_ERROR("REDIS_HOST NOT SET"); return -1;}
    const char *cache_port_tmp=getenv("REDIS_PORT");
	if(cache_port_tmp == NULL){ LOG_ERROR("REDIS_PORT NOT SET"); return -1;}
	const unsigned int cache_port=atoi(cache_port_tmp);

    redisContext *conn = redisConnect(cache_host,cache_port);
    if(conn == NULL){
        LOG_ERROR("Can't allocate redis context");
        return -1;
    } 
    
    if(conn->err){
        LOG_ERROR("Error during the connection to the database : %s ",conn->errstr);
        redisFree(conn);
        return -1;
    }

    redisReply *pingReply = redisCommand(conn, "PING");
    if(pingReply == NULL){
        LOG_ERROR("The ping to the cache redis failed");
        redisFree(conn);
        return -1;
    }
    freeReplyObject(pingReply);

    redisFree(conn);

    return 0;
}

/**
 * Fonction qui va permetre au handler de se connecter au cache Redis
 */
redisContext *cache_connect(void){
    // retrieve environnement variable
    const char *cache_host=getenv("REDIS_HOST");
    if(cache_host == NULL){ LOG_ERROR("REDIS_HOST NOT SET"); return NULL;}
    const char *cache_username=getenv("REDIS_USER");
    if(cache_username == NULL){ LOG_ERROR("REDIS_USER NOT SET"); return NULL;}
    const char *cache_pwd=getenv("REDIS_PASSWORD");
    if(cache_pwd == NULL){ LOG_ERROR("REDIS_PASSWORD NOT SET"); return NULL;}
    const char *cache_port_tmp=getenv("REDIS_PORT");
	if(cache_port_tmp == NULL){ LOG_ERROR("REDIS_PORT NOT SET"); return NULL;}
	const unsigned int cache_port=atoi(cache_port_tmp);

    redisContext *conn = redisConnect(cache_host,cache_port);
    if(conn == NULL){
        LOG_ERROR("Can't allocate redis context");
        return NULL;
    } 
    
    if(conn->err){
        LOG_ERROR("Error during the connection to the database : %s ",conn->errstr);
        redisFree(conn);
        return NULL;
    }

    redisReply *pingReply = redisCommand(conn, "AUTH %s %s", cache_username, cache_pwd);
    if(pingReply == NULL){
        LOG_ERROR("Can't send the query to the Redis Cache");
        redisFree(conn);
        return NULL;
    }else if (pingReply->type == REDIS_REPLY_ERROR){
        LOG_ERROR("Invalid credentials for the connection to the Redis Cache");
        redisFree(conn);
        return NULL;
    }
    
    freeReplyObject(pingReply);

    return conn;
}

/**
 * Fonction qui execute un query vers le cache Redis
 */
redisReply *cache_execute(redisContext *conn, const char *query){

    redisReply *queryReply = redisCommand(conn, query);
    if(queryReply == NULL){
        LOG_ERROR("Can't send the query to the Redis Cache");
        return NULL;
    }

    return queryReply;
}

/**
 * Fonction qui ferme la connection au cache Redis
 */
void cache_close(redisContext *conn){
    redisFree(conn);
}