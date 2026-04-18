#include "register.h"
#include "../logger/logger.h"
#include "../models/user.h"
#include "../password/password.h"
#include "../DB/db.h"

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>
#include <stdio.h>

#include <cjson/cJSON.h>

int register_handler(http_request_t *req, char *body_out, size_t body_out_size){

    //create a user instance
    cJSON *body_json = cJSON_Parse(req->body);
    if(body_json == NULL){
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid JSON body\"}");
        return 400;
    }

    user_t register_user={0};

    uuid_t uuser_id;
    uuid_generate_random(uuser_id);
    char user_id[ID_MAX];
    uuid_unparse_lower(uuser_id,user_id);
    strncpy(register_user.id,user_id, ID_MAX-1);

    cJSON *username=cJSON_GetObjectItem(body_json, "username");
    if(username == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Username is required\"}");
        return 400;
    }
    const char *uName = cJSON_GetStringValue(username);
    if(uName == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Username must be a string\"}");
        return 400;
    }
    strncpy(register_user.username, uName, USERNAME_MAX-1);

    cJSON *first_name=cJSON_GetObjectItem(body_json, "first_name");
    if(first_name == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"First name is required\"}");
        return 400;
    }
    const char *fn = cJSON_GetStringValue(first_name);
    if(fn == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"First name must be a string\"}");
        return 400;
    }
    strncpy(register_user.first_name,fn, FIRST_NAME_MAX-1);

    cJSON *last_name=cJSON_GetObjectItem(body_json, "last_name");
    if(last_name == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Last name is required\"}");
        return 400;
    }
    const char *ln = cJSON_GetStringValue(last_name);
    if(ln == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Last name must be a string\"}");
        return 400;
    }
    strncpy(register_user.last_name, ln, LAST_NAME_MAX-1);  

    cJSON *password=cJSON_GetObjectItem(body_json, "password");
    if(password == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Password is required\"}");
        return 400;
    }
    const char *pwd = cJSON_GetStringValue(password);
    if(pwd == NULL){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Password must be a string\"}");
        return 400;
    }
    int hash_res = hash_password(pwd, register_user.password_hash, PASSWORD_HASH_MAX);
    if(hash_res != 0){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Password hashing failed\"}");
        return 500;
    }

    //envoyer l'instance du modèle à la base de donnée
    //construire la requete 
    const char *query="INSERT INTO users(id,username,first_name,last_name,password_hash) VALUES (?,?,?,?,?)";

    //créer un tableau de 5 MYSQL_BIND, 5 parce qu'on a 5 ? dans query
    int params_count = 5;
    MYSQL_BIND params[params_count];
    memset(params, 0, sizeof(params));
    params[0].buffer_type=MYSQL_TYPE_STRING;
    params[0].buffer=register_user.id;
    params[0].buffer_length=strlen(register_user.id);

    params[1].buffer_type=MYSQL_TYPE_STRING;
    params[1].buffer=register_user.username;
    params[1].buffer_length=strlen(register_user.username);

    params[2].buffer_type=MYSQL_TYPE_STRING;
    params[2].buffer=register_user.first_name;
    params[2].buffer_length=strlen(register_user.first_name);

    params[3].buffer_type=MYSQL_TYPE_STRING;
    params[3].buffer=register_user.last_name;
    params[3].buffer_length=strlen(register_user.last_name);

    params[4].buffer_type=MYSQL_TYPE_STRING;
    params[4].buffer=register_user.password_hash;
    params[4].buffer_length=strlen(register_user.password_hash);

    //ouvrir une connexion avec la base de donnée
    MYSQL *conn = db_connect();

    //Comme on fait un POST /register (INSERT)
    //envoyer la requete à la base de donnée DONC c'est un DML
    int insert = db_execute(conn, query, params, params_count);

    //fermer la connexion avec la base de donnée
    db_close(conn);

    if (insert < 0){
        switch (-insert){
        case 1062: 
            cJSON_Delete(body_json);
            snprintf(body_out, body_out_size, "{\"error\":\"Username already exists\"}");
            return 409;
        case 1048: 
            cJSON_Delete(body_json);
            snprintf(body_out, body_out_size, "{\"error\":\"Missing required field\"}");
            return 400;
        case 1452: 
            cJSON_Delete(body_json);
            snprintf(body_out, body_out_size, "{\"error\":\"Invalid reference\"}");
            return 400;
        default: 
            cJSON_Delete(body_json);
            snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
            return 500;
        }
    }

    if(insert == 0){
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"No rows affected\"}");
        return 500;
    }

    cJSON_Delete(body_json);
    snprintf(body_out, body_out_size, "{\"message\":\"User created\"}");
    return 201;
}