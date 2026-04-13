#include "db.h"
#include "../logger/logger.h"

#include <stdlib.h>

/**
 * Fonction qui va permetre au handler de se connecter à la base de donnée
 */
MYSQL *db_connect(void){
    MYSQL *conn_init = mysql_init(NULL);
    if(conn_init == NULL){
        LOG_ERROR("Error during the initialization for the connection to the database.");
        exit(-1);
    }

    const char *db_host=getenv("DB_HOST");
    const char *db_user=getenv("DB_USER");
    const char *db_password=getenv("DB_PASSWORD");
    const char *db_name=getenv("DB_NAME");
	const unsigned int db_port=atoi(getenv("DB_PORT"));

    /*
     * mysql_real_connect(handle, host, user, password, database, port, unix_socket, client_flag)
     *
     * - handle      : le pointeur initialisé par mysql_init()
     * - host        : adresse IP ou nom d'hôte du serveur MySQL
     * - user        : nom d'utilisateur MySQL
     * - password    : mot de passe MySQL
     * - database    : nom de la base de données à sélectionner
     * - port        : port TCP du serveur (3306 par défaut)
     * - unix_socket : chemin vers un socket Unix — NULL car on se connecte via TCP/IP (Docker)
     * - client_flag : options avancées (SSL, compression...) — 0 = aucune option
     */
    MYSQL *conn = mysql_real_connect(conn_init, db_host, db_user, db_password, db_name, db_port, NULL, 0);
    if(conn == NULL){
        LOG_ERROR("Error during the connection to the database : %s ",mysql_error(conn_init));
        exit(-1);
    }

    return conn;
}

/**
 * Fonction qui exécute une requete dans la base de donnée
 */
MYSQL_RES *db_query(MYSQL *db_conn,const char *query){
    int send_query=mysql_query(db_conn, query);
    if(send_query != 0){
        LOG_ERROR("Error execute the query to the database : %s ",mysql_error(db_conn));
        exit(-1);
    }

    MYSQL_RES *query_result= mysql_store_result(db_conn);
    if(query_result == NULL){
        LOG_ERROR("Error when retreive the result of the query : %s ",mysql_error(db_conn));
        exit(-1);
    }

    return query_result;
}

/**
 * Fonction qui ferme la connection à la base de donnée
 */
void db_close(MYSQL *db_conn){
    mysql_close(db_conn);
}