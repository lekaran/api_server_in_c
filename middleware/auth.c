#include "auth.h"
#include "../http/http_parser.h"
#include "../logger/logger.h"
#include "../utils/token.h"
#include "../DB/db.h"

#include <string.h>
#include <sodium.h>

/**
 * Function that check the client token and it's validation.
 */
int auth_verify(const http_request_t *req, char *user_id, size_t user_id_len){

    //extraire le token des headers
    const char *header_token = http_get_header(req, "Authorization"); //la veleur est Bearer adagg...
    if(header_token == NULL){
        LOG_WARN("The token not founded on the headers");
        return -1;
    }

    int res_test_token = strncmp(header_token, "Bearer ", strlen("Bearer "));
    if(res_test_token != 0){
        LOG_WARN("The token not founded");
        return -1;
    }

    //token extrait
    const char *token = header_token+strlen("Bearer ");

    //vérifier le token, longueur?
    if(strlen(token) != 64){
        LOG_WARN("Bad token format");
        return -1;
    }

    //hash the token avant de l'inserer dans la base de donnée.
    char token_hash[crypto_hash_sha256_BYTES * 2 + 1]={0};
    int token_hash_res = hash_token(token , strlen(token), token_hash, crypto_hash_sha256_BYTES * 2 + 1);
    if(token_hash_res != 0){
        LOG_WARN("Can't hash the token");
        return -1;
    }

    //SELECT TO MYSQL to retreive the User ID and User Hashed Password
    //construire la requete
    const char *query="SELECT user_id FROM tokens WHERE token_hash=? AND expired_at > NOW()";

    //créer un tableau de 1 MYSQL_BIND param, 1 parce qu'on a 1 ? dans query
    int params_count = 1;
    MYSQL_BIND params[params_count];
    memset(params, 0, sizeof(params));
    params[0].buffer_type=MYSQL_TYPE_STRING;
    params[0].buffer=token_hash;
    params[0].buffer_length=strlen(token_hash);

    //créer un tableau de 1 MYSQL_BIND resultat, parce qu'il y a 1 colonnes dans le tableau du résultat.
    char db_user_id[37]={0};//37 parce que c'est la taille max qu'un user_it peu avoir

    int results_count = 1;
    MYSQL_BIND results[results_count];
    memset(results, 0, sizeof(results));
    results[0].buffer_type=MYSQL_TYPE_STRING;
    results[0].buffer=(char *)db_user_id;
    results[0].buffer_length=sizeof(db_user_id);

    //ouvrir une connexion avec la base de donnée
    MYSQL *conn = db_connect();
    if(conn == NULL){
        LOG_WARN("Can't connect to the database");
        return -1;
    }

    //execute the query 
    MYSQL_STMT *select_resutl = db_select(conn, query, params, params_count, results, results_count);
    if(select_resutl == NULL){
        LOG_WARN("Can't execute request to the database");
        db_close(conn);
        return -1;
    }

    //tans que mysql_stmt_fetch() ne retourne pas MYSQL_NO_DATA lire les données.
    int result_fetch = mysql_stmt_fetch(select_resutl);
    if((result_fetch == MYSQL_NO_DATA) || (result_fetch != 0)){
        LOG_WARN("Can't retreive the result of the request");
        //fermer la connexion avec la base de donnée
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        return -1;
    }

    //copier l'user id du resultat dans le paramètre user_id
    snprintf(user_id, user_id_len, "%s", db_user_id);

    //fermer la connexion avec la base de donnée
    int result_close = mysql_stmt_close(select_resutl);
    if (result_close != 0){
        LOG_WARN("mysql_stmt_close failed");
    }
    
    db_close(conn);
    return 0;
}
