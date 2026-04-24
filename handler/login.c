// My Modules
#include "login.h"
#include "../DB/db.h"
#include "../models/user.h"
#include "../logger/logger.h"
#include "../utils/token.h"

// Install Modules
#include <cjson/cJSON.h>
#include <sodium.h>

// Default Modules
#include <string.h>
#include <ctype.h>

static char dummy_hash[PASSWORD_HASH_MAX];

int login_init(void){
    char *pwd_fact = "aF9@kL2#zP!x7Qw$M8vR^tY1&cD*eS0uHjGmN4bC(5)Xy+Z=V?lW3rA-6pTqU:;dO,I.<o>{}[]/|`E9hKfJ2!sB@7n#8g$PQ^R&*y(1)z+M=V?L:;C,A.<Xo>{}[]/|kD3eS0uHjGmN4bC5XyZlW3rA6pTqUOIfJ2!sB7n8gPQR";
    int hash_result = crypto_pwhash_str(dummy_hash, pwd_fact, strlen(pwd_fact), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
    if(hash_result != 0){
        LOG_ERROR("There is a problem during the password hash");
        return -1;
    }
    return 0;
}

int login_handler(http_request_t *req, char *body_out, size_t body_out_size){

    char username_buff[USERNAME_MAX];
    char pwd_buff[PASSWORD_HASH_MAX];

    //create a user instance
    cJSON *body_json = cJSON_Parse(req->body);
    if(body_json == NULL){
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid JSON body\"}");
        return 400;
    }

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
    }else if (strlen(uName) > USERNAME_MAX-1){ // check the length of the username 
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Username too long\"}");
        return 400;
    }

    //check if the username contains null byte
    const char *ptr = uName;

    while (*ptr){
        if((isalnum((unsigned char)*ptr) == 0 && (unsigned char)*ptr != '-' && (unsigned char)*ptr != '_')){
            cJSON_Delete(body_json);
            snprintf(body_out, body_out_size, "{\"error\":\"Username contains bad characters\"}");
            return 400;
        }
        ptr++;
    }

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
    }else if (strlen(pwd) > PASSWORD_HASH_MAX-1){ // check the length of the PASSWORD
        cJSON_Delete(body_json);
        snprintf(body_out, body_out_size, "{\"error\":\"Password too long\"}");
        return 400;
    }

    strncpy(username_buff, uName, USERNAME_MAX-1);
    username_buff[USERNAME_MAX-1]='\0';

    strncpy(pwd_buff, pwd, PASSWORD_HASH_MAX-1);
    pwd_buff[PASSWORD_HASH_MAX-1]='\0';

    cJSON_Delete(body_json);

    //SELECT TO MYSQL to retreive the User ID and User Hashed Password
    //construire la requete
    const char *query="SELECT id, password_hash FROM users WHERE username=?";

    //créer un tableau de 1 MYSQL_BIND param, 1 parce qu'on a 1 ? dans query
    int params_count = 1;
    MYSQL_BIND params[params_count];
    memset(params, 0, sizeof(params));
    params[0].buffer_type=MYSQL_TYPE_STRING;
    params[0].buffer=username_buff;
    params[0].buffer_length=strlen(username_buff);

    //créer un tableau de 2 MYSQL_BIND resultat, parce qu'il y a 2 colonnes dans le tableau du résultat.
    char user_id[37]={0};
    char pwd_hashed[PASSWORD_HASH_MAX]={0};

    int results_count = 2;
    MYSQL_BIND results[results_count];
    memset(results, 0, sizeof(results));
    results[0].buffer_type=MYSQL_TYPE_STRING;
    results[0].buffer=(char *)user_id;
    results[0].buffer_length=sizeof(user_id);

    results[1].buffer_type=MYSQL_TYPE_STRING;
    results[1].buffer=(char *)pwd_hashed;
    results[1].buffer_length=sizeof(pwd_hashed);

    //ouvrir une connexion avec la base de donnée
    MYSQL *conn = db_connect();
    if(conn == NULL){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        //vider la mémoire du mots de passe 
        sodium_memzero(pwd_buff, sizeof(pwd_buff));
        return 500;
    }

    //execute the query 
    MYSQL_STMT *select_resutl = db_select(conn, query, params, params_count, results, results_count);
    if(select_resutl == NULL){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        db_close(conn);
        //vider la mémoire du mots de passe 
        sodium_memzero(pwd_buff, sizeof(pwd_buff));
        return 500;
    }

    //tans que mysql_stmt_fetch() ne retourne pas MYSQL_NO_DATA lire les données.
    int result_fetch = mysql_stmt_fetch(select_resutl);
    // récupérer password_hash qui vient de la BD
    if(result_fetch == MYSQL_NO_DATA){
        
        crypto_pwhash_str_verify(dummy_hash, pwd_buff, strlen(pwd_buff));
        
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid credentials\"}");
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        //vider la mémoire du mots de passe 
        sodium_memzero(pwd_buff, sizeof(pwd_buff));
        return 401;
    }else if (result_fetch != 0){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        //vider la mémoire du mots de passe 
        sodium_memzero(pwd_buff, sizeof(pwd_buff));
        return 500;
    }

    // on a forcément result_fetch == 0 donc une ligne trouvée.
    int test_pwd = crypto_pwhash_str_verify(pwd_hashed, pwd_buff, strlen(pwd_buff));
    if (test_pwd != 0){
        snprintf(body_out, body_out_size, "{\"error\":\"Invalid credentials\"}");
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        //vider la mémoire du mots de passe 
        sodium_memzero(pwd_buff, sizeof(pwd_buff));
        return 401;
    }

    //vider la mémoire du mots de passe 
    sodium_memzero(pwd_buff, sizeof(pwd_buff));

    //Générer un token aléatoire sécurisé (32 bytes -> 64 chars hex)
    //The randombytes_buf() function fills size bytes starting at buf with an unpredictable sequence of bytes.
    unsigned char token_bytes[32];
    randombytes_buf(token_bytes, sizeof(token_bytes)); //return void
    
    /**
     * The sodium_bin2hex() function converts bin_len bytes stored at bin into a hexadecimal string.
     * The string is stored into hex and includes a null byte (\0) terminator.
     * hex_maxlen is the maximum number of bytes that the function is allowed to write starting at hex. It must be at least bin_len * 2 + 1 bytes.
     */
    char token_hex[65]={0};
    sodium_bin2hex(token_hex, sizeof(token_hex), token_bytes, sizeof(token_bytes));

    //hash the token avant de l'inserer dans la base de doonée.
    char token_hash[crypto_hash_sha256_BYTES * 2 + 1];
    int token_hash_res = hash_token(token_bytes , sizeof(token_bytes), token_hash, crypto_hash_sha256_BYTES * 2 + 1);
    if(token_hash_res != 0){
        snprintf(body_out, body_out_size, "{\"error\":\"Token hashing failed\"}");
        db_close(conn);
        return 500;
    }

    // INSERT INTO token (user_id, token)
    //construire la requete
    const char *query_insert="INSERT INTO tokens(user_id, token_hash) VALUES (?,?)";

    //créer un tableau de 1 MYSQL_BIND param, 1 parce qu'on a 1 ? dans query
    int params_insert_count = 2;
    MYSQL_BIND params_insert[params_insert_count];
    memset(params_insert, 0, sizeof(params_insert));
    params_insert[0].buffer_type=MYSQL_TYPE_STRING;
    params_insert[0].buffer=user_id;
    params_insert[0].buffer_length=strlen(user_id);
    
    params_insert[1].buffer_type=MYSQL_TYPE_STRING;
    params_insert[1].buffer=token_hash;
    params_insert[1].buffer_length=strlen(token_hash);

    //envoyer la requete à la base de donnée DONC c'est un DML
    int insert = db_execute(conn, query_insert, params_insert, params_insert_count);

    if (insert <= 0){
        snprintf(body_out, body_out_size, "{\"error\":\"Database error\"}");
        int result_close = mysql_stmt_close(select_resutl);
        if (result_close != 0){
            LOG_WARN("mysql_stmt_close failed");
        }
        db_close(conn);
        return 500;
    }

    //fermer la connexion avec la base de donnée
    int result_close = mysql_stmt_close(select_resutl);
    if (result_close != 0){
        LOG_WARN("mysql_stmt_close failed");
    }
    db_close(conn);

    snprintf(body_out, body_out_size, "{\"token\":\"%s\"}",token_hex);
    sodium_memzero(token_bytes, sizeof(token_bytes));
    return 201;
}