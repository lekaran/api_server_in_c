#ifndef SERVER_H
#define SERVER_H

#define BUFFER_SIZE	8192
#define MAX_BODY_SIZE 65536

/**
 * Fonction qui initie le server
 * La fonction retourne 0 en cas de succès et -1 dans le cas contraire
 */
int server_init(void);

/**
 * Fonction qui lance le server
 * La fonction retourne 0 en cas de succès et -1 dans le cas contraire
 */
int server_run(void);

/**
 * Fonction qui arrète le server proprement
 * La fonction retourne 0 en cas de succès et -1 dans le cas contraire
 */
int server_shutdown(void);

#endif