// My Modules
#include "logout.h"
#include "../DB/db.h"
#include "../utils/token.h"
#include "../http/http_parser.h"
#include "../logger/logger.h"

// Install Modules
#include <sodium.h>

// Default Modules
#include <string.h>

/**
 * Logout a user to the server
 */
int logout_handler(http_request_t *req, char *body_out, size_t body_out_size){
    //extraire le token des headers
    const char *header_token = http_get_header(req, "Authorization"); //la veleur est Bearer adagg...
    if(header_token == NULL){
        LOG_WARN("The token not founded on the headers");
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid request\"}");
        return 400;
    }

    int res_test_token = strncmp(header_token, "Bearer ", strlen("Bearer "));
    if(res_test_token != 0){
        LOG_WARN("The token not founded");
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid request\"}");
        return 400;
    }

    //token extrait
    const char *token = header_token+strlen("Bearer ");

    //vérifier le token, longueur?
    if(strlen(token) != 64){
        LOG_WARN("Bad token format");
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid request\"}");
        return 400;
    }

    //hash the token avant de l'inserer dans la base de donnée.
    char token_hash[crypto_hash_sha256_BYTES * 2 + 1]={0};
    int token_hash_res = hash_token(token , strlen(token), token_hash, crypto_hash_sha256_BYTES * 2 + 1);
    if(token_hash_res != 0){
        LOG_WARN("Can't hash the token");
        snprintf(body_out, body_out_size, "{\"error\":\"Internal Server Error\"}");
        return 500;
    }

    //SELECT TO MYSQL to retreive the User ID and User Hashed Password
    //construire la requete
    const char *query="DELETE FROM tokens WHERE token_hash=?";

    //créer un tableau de 1 MYSQL_BIND param, 1 parce qu'on a 1 ? dans query
    int params_count = 1;
    MYSQL_BIND params[params_count];
    memset(params, 0, sizeof(params));
    params[0].buffer_type=MYSQL_TYPE_STRING;
    params[0].buffer=token_hash;
    params[0].buffer_length=strlen(token_hash);

    //ouvrir une connexion avec la base de donnée
    MYSQL *conn = db_connect();
    if(conn == NULL){
        LOG_WARN("Can't connect to the database");
        snprintf(body_out, body_out_size, "{\"error\":\"Internal Server Error\"}");
        return 500;
    }

    //execute the query 
    int select_resutl = db_execute(conn, query, params, params_count);
    if(select_resutl < 0){
        LOG_WARN("The request delete more than one row");
        db_close(conn);
        snprintf(body_out, body_out_size, "{\"error\":\"Internal Server Error\"}");
        return 500;
    }else if(select_resutl == 0){
        LOG_WARN("The token don't existe");
        db_close(conn);
        snprintf(body_out, body_out_size, "{\"error\":\"Unauthorized\"}");
        return 401; 
    }
    
    snprintf(body_out, body_out_size, "{\"success\":true,\"message\":\"Logout successful\"}");
    db_close(conn);
    return 200;
}