// My Modules
#include "profile.h"
#include "../DB/db.h"
#include "../models/user.h"
#include "../logger/logger.h"

// Default Modules
#include <string.h>

#define DATETIME_LENGTH 20

int get_profile_handler(http_request_t *req, char *body_out, size_t body_out_size){

    //j'ai user_id dans req->user_id
    const char *query="SELECT id, username, first_name, last_name, created_at, updated_at FROM users WHERE id=?";

    //créer un tableau de 1 MYSQL_BIND param, 1 parce qu'on a 1 ? dans query
    int params_count = 1;
    MYSQL_BIND params[params_count];
    memset(params, 0, sizeof(params));
    params[0].buffer_type=MYSQL_TYPE_STRING;
    params[0].buffer=req->user_id;
    params[0].buffer_length=strlen(req->user_id);

    //créer un tableau de 6 MYSQL_BIND resultat, parce qu'il y a 6 colonnes dans le tableau du résultat.
    char user_id[ID_MAX]={0};
    char username[USERNAME_MAX]={0};
    char first_name[FIRST_NAME_MAX]={0};
    char last_name[LAST_NAME_MAX]={0};
    char created_at[DATETIME_LENGTH]={0};
    char updated_at[DATETIME_LENGTH]={0};

    int results_count = 6;
    MYSQL_BIND results[results_count];
    memset(results, 0, sizeof(results));
    results[0].buffer_type=MYSQL_TYPE_STRING;
    results[0].buffer=(char *)user_id;
    results[0].buffer_length=sizeof(user_id);

    results[1].buffer_type=MYSQL_TYPE_STRING;
    results[1].buffer=(char *)username;
    results[1].buffer_length=sizeof(username);

    results[2].buffer_type=MYSQL_TYPE_STRING;
    results[2].buffer=(char *)first_name;
    results[2].buffer_length=sizeof(first_name);

    results[3].buffer_type=MYSQL_TYPE_STRING;
    results[3].buffer=(char *)last_name;
    results[3].buffer_length=sizeof(last_name);

    results[4].buffer_type=MYSQL_TYPE_STRING;
    results[4].buffer=(char *)created_at;
    results[4].buffer_length=sizeof(created_at);

    results[5].buffer_type=MYSQL_TYPE_STRING;
    results[5].buffer=(char *)updated_at;
    results[5].buffer_length=sizeof(updated_at);


    //ouvrir une connexion avec la base de donnée
    MYSQL *conn = db_connect();
    if(conn == NULL){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        return 500;
    }

    //execute the query 
    MYSQL_STMT *select_resutl = db_select(conn, query, params, params_count, results, results_count);
    if(select_resutl == NULL){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        db_close(conn);
        return 500;
    }

    //tans que mysql_stmt_fetch() ne retourne pas MYSQL_NO_DATA lire les données.
    int result_fetch = mysql_stmt_fetch(select_resutl);
    if(result_fetch == MYSQL_NO_DATA){
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid user\"}");
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        return 401;
    }else if (result_fetch != 0){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        return 500;
    }

    //mettre le resutlat dans le body_out
    snprintf(body_out, body_out_size, "{\"user_id\":\"%s\",\"username\":\"%s\",\"first_name\":\"%s\",\"last_name\":\"%s\",\"created_at\":\"%s\",\"updated_at\":\"%s\"}",user_id, username, first_name, last_name, created_at, updated_at);
    
    int result_close = mysql_stmt_close(select_resutl);
    if (result_close != 0){
        LOG_WARN("mysql_stmt_close failed");
    }
    db_close(conn);
    return 200;
}