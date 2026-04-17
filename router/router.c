#include "router.h"
#include "../http/http_response.h"
#include "../logger/logger.h"
#include "../handler/register.h"

#include <string.h>

#define ROUTE_COUNT 6

// table de routes
static route_t route_tables[] = {
    {.methode = "POST", .path = "/register", .handler = register_handler, .is_protected = 0},
    {.methode = "POST", .path = "/login", .handler = NULL, .is_protected = 0},
    {.methode = "POST", .path = "/logout", .handler = NULL, .is_protected = 1},
    {.methode = "GET", .path = "/profile", .handler = NULL, .is_protected = 1},
    {.methode = "PUT", .path = "/profile", .handler = NULL, .is_protected = 1},
    {.methode = "DELETE", .path = "/profile", .handler = NULL, .is_protected = 1}
};

int router_dispatch(int client_fd, http_request_t *req){
    int http_code = 404;
    for(int i=0; i<ROUTE_COUNT; i++){
        if(strcmp(route_tables[i].methode,req->method) == 0 && strcmp(route_tables[i].path,req->path) == 0){
            if(route_tables[i].is_protected){
                // TODO : Vérifier le token (middleware auth)
            }
            if(route_tables[i].handler != NULL){
                http_code = route_tables[i].handler(client_fd, req);
                http_response(client_fd, http_code, "");
            }else{
                http_response(client_fd, 501, "{\"error\":\"Not Implemented\"}");
                http_code = 501;
            }
            break;
        }   
    }
    if (http_code == 404){
        http_response(client_fd, 404, "{\"error\":\"Not Found\"}");
    }

    if (http_code >= 200 && http_code <= 299){
        LOG_INFO("%s %s -> %d", req->method, req->path, http_code);
    }else if(http_code >= 400 && http_code <= 499){
        LOG_WARN("%s %s -> %d", req->method, req->path, http_code);
    }else if(http_code >= 500 && http_code <= 599){
        LOG_ERROR("%s %s -> %d", req->method, req->path, http_code);
    }
    
    return http_code;
}
