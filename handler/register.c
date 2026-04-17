#include "register.h"
#include "../logger/logger.h"
#include "../models/user.h"
#include "../password/password.h"
#include "../DB/db.h"

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include <cjson/cJSON.h>

int register_handler(int client_fd, http_request_t *req){

    //create a user instance
    cJSON *body_json = cJSON_Parse(req->body);
    if(body_json == NULL){
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
    const char *pwd = cJSON_GetStringValue(password);
    int hash_res = hash_password(pwd, register_user.password_hash, PASSWORD_HASH_MAX);
    if(hash_res != 0){
        cJSON_Delete(body_json);
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
            return 409;
        case 1048: 
            cJSON_Delete(body_json);
            return 400;
        case 1452: 
            cJSON_Delete(body_json);
            return 400;
        default: 
            cJSON_Delete(body_json);
            return 500;
        }
    }

    if(insert == 0){
        cJSON_Delete(body_json);
        return 500;
    }

    cJSON_Delete(body_json);
    return 201;
}