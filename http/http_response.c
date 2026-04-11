#include "http_response.h"
#include "../logger/logger.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFFER_SIZE	1024

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

int http_response(int client_fd,int code_http, const char *json_body){

    const char *statusPhrase = status_phrase(code_http);
    int contentLength = strlen(json_body);

    char httpResponse[BUFFER_SIZE];
    snprintf(httpResponse, BUFFER_SIZE, "HTTP/1.1 %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",statusPhrase,contentLength,json_body);

    ssize_t send_respond = send(client_fd, httpResponse, strlen(httpResponse), 0);
    if(send_respond == -1){
        LOG_ERROR("The respond fail to be sended: %s ", strerror(errno));
        return -1;
    }
    LOG_DEBUG("Response %d sent", code_http);
    return 0;
}