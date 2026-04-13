#include "register.h"
#include "../logger/logger.h"
#include "../models/user.h"

#include <string.h>
#include <stdlib.h>

#include <cjson/cJSON.h>

int register_handler(int client_fd, http_request_t *req){

    cJSON *body_json = cJSON_Parse(req->body);
    if(body_json == NULL){
        return 400;
    }

    user_t register_user={0};
    cJSON *username=cJSON_GetObjectItem(body_json, "username");
    if(username == NULL){
        cJSON_Delete(body_json);
        return 400;
    }
    strncpy(register_user.username,cJSON_GetStringValue(username), USERNAME_MAX-1);

    cJSON *first_name=cJSON_GetObjectItem(body_json, "first_name");
    if(first_name == NULL){
        cJSON_Delete(body_json);
        return 400;
    }
    strncpy(register_user.first_name,cJSON_GetStringValue(first_name), FIRST_NAME_MAX-1);

    cJSON *last_name=cJSON_GetObjectItem(body_json, "last_name");
    if(last_name == NULL){
        cJSON_Delete(body_json);
        return 400;
    }
    strncpy(register_user.last_name,cJSON_GetStringValue(last_name), LAST_NAME_MAX-1);  

    cJSON *password=cJSON_GetObjectItem(body_json, "password");
    if(password == NULL){
        cJSON_Delete(body_json);
        return 400;
    }
    char *pwsd = cJSON_GetStringValue(password);

    // hash the pwsd before put it on the register_user->password_hash

    //strncpy(register_user.password_hash,hash(pwsd), PASSWORD_HASH_MAX-1);

    cJSON_Delete(body_json);
    return 201;
}