#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

/**
 * Fonction qui envoie la réponse d'une requete
 */
int http_response(int client_fd,int code_http, const char *json_body);

#endif