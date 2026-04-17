#include "db.h"
#include "../logger/logger.h"

#include <stdlib.h>
#include <string.h>

/**
 * Fonction qui test la connexion avec la base de donnée.
 */
int db_healthcheck(void){
    MYSQL *conn_init = mysql_init(NULL);
    if(conn_init == NULL){
        LOG_ERROR("Error during the initialization for the connection to the database.");
        return -1;
    }

    const char *db_host=getenv("DB_HOST");
    const char *db_user=getenv("DB_USER");
    const char *db_password=getenv("DB_PASSWORD");
    const char *db_name=getenv("DB_NAME");
	const unsigned int db_port=atoi(getenv("DB_PORT"));

    MYSQL *conn = mysql_real_connect(conn_init, db_host, db_user, db_password, db_name, db_port, NULL, 0);
    if(conn == NULL){
        LOG_ERROR("Error during the connection to the database : %s ",mysql_error(conn_init));
        mysql_close(conn_init);
        return -1;
    }

    int res = mysql_ping(conn);
    if(res!=0){
        LOG_ERROR("Error during the healthcheck to the database : %s ",mysql_error(conn_init));
        mysql_close(conn);
        return -1;
    }

    mysql_close(conn);
    return 0;
}

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
 * Fonction qui exécute une requete de type INSERT, UPDATE, DELETE dans la base de donnée
 */
int db_execute(MYSQL *conn, const char *query, MYSQL_BIND *params, int params_count){
    if(params_count < 0){
        LOG_ERROR("The params BIND must have a number of params more than 0");
        return -1;
    }

    MYSQL_STMT *init_stmt = mysql_stmt_init(conn);
    if(init_stmt == NULL){
        LOG_ERROR("Error during the initialization of the MySQL statement init");
        return -1;
    }

    int prepare = mysql_stmt_prepare(init_stmt, query, strlen(query));
    if (prepare != 0){
        LOG_ERROR("Error during the preparation of the MySQL statement : %s",mysql_stmt_error(init_stmt));
        int err = mysql_stmt_errno(init_stmt);
        if (mysql_stmt_close(init_stmt) != 0){
            LOG_ERROR("Error during the close of the MySQL statement at the statement preparation");
            return -err;
        }
        return -err;
    }

    if(params_count > 0){
        bool bind_result = mysql_stmt_bind_param(init_stmt, params);
        if (bind_result != 0){
            LOG_ERROR("Error during the bind of the params : %s",mysql_stmt_error(init_stmt));
            int err = mysql_stmt_errno(init_stmt);
            if (mysql_stmt_close(init_stmt) != 0){
                LOG_ERROR("Error during the close of the MySQL statement at the bind params");
                return -err;
            }
            return -err;
        }
    }

    int res_execute = mysql_stmt_execute(init_stmt);
    if (res_execute != 0){
        LOG_ERROR("Error during the execution of the MySQL statement : %s",mysql_stmt_error(init_stmt));
        int err = mysql_stmt_errno(init_stmt);
        if (mysql_stmt_close(init_stmt) != 0){
            LOG_ERROR("Error during the close of the MySQL statement at the execute");
            return -err;
        }
        return -err;
    }

    int nb_line_effect = mysql_stmt_affected_rows(init_stmt);

    mysql_stmt_close(init_stmt);

    return nb_line_effect;
}

/**
 * Fonction qui exécute une requete de type SELECT dans la base de donnée
 */
MYSQL_STMT *db_select(MYSQL *conn, const char *query, MYSQL_BIND *params, int params_count, MYSQL_BIND *results, int results_count){
    if(params_count < 0){
        LOG_ERROR("The params BIND must have a number of params more than 0");
        return NULL;
    }

    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    if(stmt == NULL){
        LOG_ERROR("Error during the initialization of the MySQL statement init");
        return NULL;
    }

    int prepare = mysql_stmt_prepare(stmt, query, strlen(query));
    if (prepare != 0){
        LOG_ERROR("Error during the preparation of the MySQL statement : %s",mysql_stmt_error(stmt));
        int err = mysql_stmt_errno(stmt);
        if (mysql_stmt_close(stmt) != 0){
            LOG_ERROR("Error during the close of the MySQL statement at the statement preparation");
            return NULL;
        }
        return NULL;
    }

    if(params_count > 0){
        bool bind_result = mysql_stmt_bind_param(stmt, params);
        if (bind_result != 0){
            LOG_ERROR("Error during the bind of the params : %s",mysql_stmt_error(stmt));
            int err = mysql_stmt_errno(stmt);
            if (mysql_stmt_close(stmt) != 0){
                LOG_ERROR("Error during the close of the MySQL statement at the bind params");
                return NULL;
            }
            return NULL;
        }
    }

    int res_execute = mysql_stmt_execute(stmt);
    if (res_execute != 0){
        LOG_ERROR("Error during the execution of the MySQL statement : %s",mysql_stmt_error(stmt));
        int err = mysql_stmt_errno(stmt);
        if (mysql_stmt_close(stmt) != 0){
            LOG_ERROR("Error during the close of the MySQL statement at the execute");
            return NULL;
        }
        return NULL;
    }

    int store_res = mysql_stmt_store_result(stmt);
    if (store_res != 0){
        LOG_ERROR("Error during the store result of the MySQL statement : %s",mysql_stmt_error(stmt));
        int err = mysql_stmt_errno(stmt);
        if (mysql_stmt_close(stmt) != 0){
            LOG_ERROR("Error during the close of the MySQL statement at the store result");
            return NULL;
        }
        return NULL;
    }

    if(results_count > 0){
        bool res_bind = mysql_stmt_bind_result(stmt, results);
        if (res_bind != 0){
            LOG_ERROR("Error during the bind result of the params : %s",mysql_stmt_error(stmt));
            int err = mysql_stmt_errno(stmt);
            if (mysql_stmt_close(stmt) != 0){
                LOG_ERROR("Error during the close of the MySQL statement at the bind result");
                return NULL;
            }
            return NULL;
        }
    }

    // le handler appelle mysql_stmt_fetch() en boucle
    // le handler appelle mysql_stmt_close() à la fin
    return stmt;
}

/**
 * Fonction qui ferme la connection à la base de donnée
 */
void db_close(MYSQL *db_conn){
    mysql_close(db_conn);
}