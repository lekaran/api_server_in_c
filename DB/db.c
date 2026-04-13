#include "db.h"
#include "../logger/logger.h"

#include <stdlib.h>

/**
 * Fonction qui va permetre au handler de se connecter à la base de donnée
 */
MYSQL *db_connect(){
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

    MYSQL *conn = mysql_real_connect(conn_init, db_host, db_user, db_password, db_name, db_port, NULL, 0);
    if(conn == NULL){
        LOG_ERROR("Error during the connection to the database : %s ",mysql_error(conn_init));
        exit(-1);
    }

    return conn;
}