#ifndef DB_H
#define DB_H

#include <mysql.h>

/**
 * Fonction qui test la connexion avec la base de donnée.
 */
int db_healthcheck(void);

/**
 * Fonction qui va permetre au handler de se connecter à la base de donnée
 */
MYSQL *db_connect(void);

/**
 * Fonction qui exécute une requete de type INSERT, UPDATE, DELETE dans la base de donnée
 */
int db_execute(MYSQL *conn, const char *query, MYSQL_BIND *params, int params_count);

/**
 * Fonction qui exécute une requete de type SELECT dans la base de donnée
 */
MYSQL_STMT *db_select(MYSQL *conn, const char *query, MYSQL_BIND *params, int params_count, MYSQL_BIND *results, int results_count);

/**
 * Fonction qui ferme la connection à la base de donnée
 */
void db_close(MYSQL *db_conn);

#endif