#ifndef HTTP_RESPONSE_BUILDER_H
#define HTTP_RESPONSE_BUILDER_H

#include <string.h>

#define HTTP_HEADER_NAME_MAX 65
#define HTTP_HEADER_VALUE_MAX 513
#define HTTP_RESPONSE_MAX_HEADERS 32

typedef struct {
    char name[HTTP_HEADER_NAME_MAX];
    char value[HTTP_HEADER_VALUE_MAX];
}http_header_response_t;

typedef struct {
    http_header_response_t headers[HTTP_RESPONSE_MAX_HEADERS];
    size_t nb_add_header;
    int http_code;
}http_response_builder_t;

int init_http_response_builder(http_response_builder_t *http_response, int http_code);

int add_header_http_response_builder(http_response_builder_t *http_response, const char *header_name, const char *header_value);

int send_http_response(int client_fd, http_response_builder_t *http_response, const char *http_response_body);

#endif