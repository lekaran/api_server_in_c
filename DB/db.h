#ifndef DB_H
#define DB_H

#include <mysql.h>

/**
 * Fonction qui va permetre au handler de se connecter à la base de donnée
 */
MYSQL *db_connect();

/**
 * Fonction qui exécute une requete dans la base de donnée
 */
MYSQL_RES *db_query(MYSQL *db_conn,const char *query);

/**
 * Fonction qui ferme la connection à la base de donnée
 */
void db_close(MYSQL *db_conn);

#endif