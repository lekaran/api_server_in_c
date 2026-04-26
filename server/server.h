#ifndef SERVER_H
#define SERVER_H

#define BUFFER_SIZE	16384
#define HTTP_HEADERS_MAX 2048
#define MAX_BODY_SIZE (BUFFER_SIZE-HTTP_HEADERS_MAX-4)

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