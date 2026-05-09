#include "rate_limit.h"
#include "../logger/logger.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <hiredis/hiredis.h>

static const int T = 6000000;
static const int burst = 5;
static const int ttl = 30;
static const char *lua_script = "local TAT = tonumber(redis.call('GET', KEYS[1]) or tonumber(ARGV[1])); local now = tonumber(ARGV[1]); local T = tonumber(ARGV[2]); local window = tonumber(ARGV[3]); local ttl = tonumber(ARGV[4]); local new_TAT = ((TAT > now) and TAT or now) + T; if ((new_TAT - now) > window) then return 1; else redis.call('SET', KEYS[1], tostring(new_TAT),'EX', ttl); return 0; end";

/**
 * Fonction that make the rate limite
 */
int rate_limit_check(redisContext *conn, const char *route, const char *client_ip){

    int key_len = snprintf(NULL, 0, "rl:%s:%s", route, client_ip);
    if(key_len<0){
        LOG_ERROR("There is a problem when calculate the lenght of the kye");
        return 1;
    }

    char *key = malloc((size_t)key_len+1);
    if(key == NULL){
        LOG_ERROR("Error during malloc");
        return 1;
    }

    int final_key = snprintf(key, (size_t)key_len+1, "rl:%s:%s", route, client_ip);
    if(final_key != key_len){
        LOG_ERROR("Error during the creation of the key");
        free(key);
        return 1;
    }

    struct timespec ts;
    int time = clock_gettime(CLOCK_REALTIME, &ts);
    if(time == -1){
        LOG_ERROR("Error getting the time");
        free(key);
        return 1;
    }

    int64_t now = (int64_t)ts.tv_sec*1000000+ts.tv_nsec/1000;

    int64_t window = burst*T;

    redisReply *queryReply = redisCommand(conn, "EVAL %s 1 %s %lld %d %lld %d", lua_script, key, now, T, window, ttl);
    if(queryReply == NULL){
        LOG_ERROR("Can't send the query to the Redis Cache");
        free(key);
        return 1;
    }

    if(queryReply->integer == 1 || queryReply->type != REDIS_REPLY_INTEGER){
        LOG_ERROR("The client %s is block", client_ip);
        freeReplyObject(queryReply);
        free(key);
        return 1;
    }

    freeReplyObject(queryReply);
    free(key);
    return 0;
}

