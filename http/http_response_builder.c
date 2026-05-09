#include "http_response_builder.h"
#include "../logger/logger.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>

static const char *status_phrase(int code){
    switch (code) {
        /* 1xx Inforamtional */
        case 100: return "100 Continue";
        case 101: return "101 Switching Protocols";
        case 102: return "102 Processing";
        case 103: return "103 Early Hints";

        /* 2xx Success */
        case 200: return "200 OK";
        case 201: return "201 Created";
        case 202: return "202 Accepted";
        case 203: return "203 Non-Authoritative Information";
        case 204: return "204 No Content";
        case 205: return "205 Reset Content";
        case 206: return "206 Partial Content";
        case 207: return "207 Multi-Status";
        case 208: return "208 Already Reported";
        case 226: return "226 IM Used";

        /* 3xx Redirection */
        case 300: return "300 Multiple Choices";
        case 301: return "301 Moved Permanently";
        case 302: return "302 Found";
        case 303: return "303 See Other";
        case 304: return "304 Not Modified";
        case 305: return "305 Use Proxy";
        case 306: return "306 (Unused)";
        case 307: return "307 Temporary Redirect";
        case 308: return "308 Permanent Redirect";

        /* 4xx Client Errors */
        case 400: return "400 Bad Request";
        case 401: return "401 Unauthorized";
        case 402: return "402 Payment Required";
        case 403: return "403 Forbidden";
        case 404: return "404 Not Found";
        case 405: return "405 Method Not Allowed";
        case 406: return "406 Not Acceptable";
        case 407: return "407 Proxy Authentication Required";
        case 408: return "408 Request Timeout";
        case 409: return "409 Conflict";
        case 410: return "410 Gone";
        case 411: return "411 Length Required";
        case 412: return "412 Precondition Failed";
        case 413: return "413 Payload Too Large";
        case 414: return "414 URI Too Long";
        case 415: return "415 Unsupported Media Type";
        case 416: return "416 Range Not Satisfiable";
        case 417: return "417 Expectation Failed";
        case 418: return "418 I'm a teapot";
        case 421: return "421 Misdirected Request";
        case 422: return "422 Unprocessable Entity";
        case 423: return "423 Locked";
        case 424: return "424 Failed Dependency";
        case 425: return "425 Too Early";
        case 426: return "426 Upgrade Required";
        case 428: return "428 Precondition Required";
        case 429: return "429 Too Many Requests";
        case 431: return "431 Request Header Fields Too Large";
        case 444: return "444 No Response";
        case 449: return "449 Retry With";
        case 451: return "451 Unavailable For Legal Reasons";

        /* 5xx Server Errors */
        case 500: return "500 Internal Server Error";
        case 501: return "501 Not Implemented";
        case 502: return "502 Bad Gateway";
        case 503: return "503 Service Unavailable";
        case 504: return "504 Gateway Timeout";
        case 505: return "505 HTTP Version Not Supported";
        case 506: return "506 Variant Also Negotiates";
        case 507: return "507 Insufficient Storage";
        case 508: return "508 Loop Detected";
        case 509: return "509 Bandwidth Limit Exceeded";
        case 510: return "510 Not Extended";
        case 511: return "511 Network Authentication Required";
        default:  return "Unknown Status";
    }

}

int init_http_response_builder(http_response_builder_t *http_response, int http_code){
    if(http_response == NULL){ return -1;}

    //init the http_response
    http_response->http_code = http_code;
    http_response->nb_add_header = 0;

    //init the http_response with 0 value
    memset(http_response->headers, 0, sizeof(http_response->headers));

    //ajout des headers de sécurité
    add_header_http_response_builder(http_response, "X-Frame-Options", "DENY");
    add_header_http_response_builder(http_response, "X-Content-Type-Options", "nosniff");
    add_header_http_response_builder(http_response, "Content-Security-Policy", "default-src 'none'");
    add_header_http_response_builder(http_response, "Cache-Control", "no-store");
    add_header_http_response_builder(http_response, "Referrer-Policy", "no-referrer");
    add_header_http_response_builder(http_response, "X-XSS-Protection", "0");

    return 0;
}

int add_header_http_response_builder(http_response_builder_t *http_response, const char *header_name, const char *header_value){

    if(http_response->nb_add_header >= HTTP_RESPONSE_MAX_HEADERS ){
        LOG_ERROR("The headers tab exced the maximum value");
        return -1;
    }

    strncpy(http_response->headers[http_response->nb_add_header].name, header_name, HTTP_HEADER_NAME_MAX-1);
    http_response->headers[http_response->nb_add_header].name[HTTP_HEADER_NAME_MAX-1]='\0';

    strncpy(http_response->headers[http_response->nb_add_header].value, header_value, HTTP_HEADER_VALUE_MAX-1);
    http_response->headers[http_response->nb_add_header].value[HTTP_HEADER_VALUE_MAX-1]='\0';

    http_response->nb_add_header ++;
    return 0;
}

int send_http_response(int client_fd, http_response_builder_t *http_response, const char *http_response_body){
    const char *headerFixResponse = "HTTP/1.1 ";
    const char *codeResponse = status_phrase(http_response->http_code);
    size_t headerFixeLength = strlen(headerFixResponse)+strlen(codeResponse)+strlen("\r\n");
    size_t headerCount=0;
    for (size_t i = 0; i < http_response->nb_add_header; i++){
        headerCount += strlen(http_response->headers[i].name)+strlen(http_response->headers[i].value)+4;
    }
    size_t separator = 2;
    size_t body_len = strlen(http_response_body);
    size_t http_respon_len = headerFixeLength+headerCount+separator+body_len;

    char *http_resp = (char *)malloc(http_respon_len+1);
    if(http_resp == NULL){ 
        LOG_ERROR("Error during malloc");
        return -1;
    }

    int offset = 0;
    int headerFix_res = snprintf(http_resp+offset, headerFixeLength+1, "%s%s\r\n",headerFixResponse, codeResponse);
    if(headerFix_res != headerFixeLength){ 
        LOG_ERROR("Error during write the status line");
        free(http_resp);
        return -1;
    }
    offset += headerFix_res;

    int header_res = 0;
    for (size_t i = 0; i < http_response->nb_add_header; i++){
        size_t header_len = strlen(http_response->headers[i].name)+strlen(http_response->headers[i].value)+4;
        int add_header_res = snprintf(http_resp+offset, header_len+1, "%s: %s\r\n",http_response->headers[i].name, http_response->headers[i].value);
        if(add_header_res != header_len){ 
            LOG_ERROR("Error during write %s header", http_response->headers[i].name);
            free(http_resp);
            return -1;
        }
        header_res += add_header_res;
        offset += add_header_res;
    }
    if(header_res != headerCount){ 
        LOG_ERROR("Error during write headers");
        free(http_resp);
        return -1;
    }

    int add_separator = snprintf(http_resp+offset, 3, "\r\n");
    if(add_separator != 2){ 
        LOG_ERROR("Error during write separator");
        free(http_resp);
        return -1;
    }
    offset += add_separator;

    int add_body = snprintf(http_resp+offset, body_len+1, "%s", http_response_body);
    if(add_body != body_len){ 
        LOG_ERROR("Error during write the body");
        free(http_resp);
        return -1;
    }

    http_resp[http_respon_len]='\0';

    ssize_t send_respond = send(client_fd, http_resp, http_respon_len, 0);
    if(send_respond == -1){
        LOG_ERROR("The respond fail to be sended: %s ", strerror(errno));
        free(http_resp);
        return -1;
    }
    LOG_DEBUG("Response %d sent", http_response->http_code);

    free(http_resp);
    return 0;
}