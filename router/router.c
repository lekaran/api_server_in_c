#include "router.h"
#include "../http/http_response_builder.h"
#include "../logger/logger.h"
#include "../handler/register.h"
#include "../handler/login.h"
#include "../handler/logout.h"
#include "../handler/profile.h"
#include "../middleware/auth.h"
#include "../models/user.h"

#include <string.h>
#include <stdio.h>

#define ROUTE_COUNT 4 //nombre de route
#define BODY_MAX 1024

// table de routes
static route_t route_tables[] = {
    {.methode = "POST", .path = "/register", .handler = register_handler, .is_protected = 0},
    {.methode = "POST", .path = "/login", .handler = login_handler, .is_protected = 0},
    {.methode = "POST", .path = "/logout", .handler = logout_handler, .is_protected = 1},
    {.methode = "GET", .path = "/profile", .handler = get_profile_handler, .is_protected = 1}
    //{.methode = "PUT", .path = "/profile", .handler = NULL, .is_protected = 1},
    //{.methode = "DELETE", .path = "/profile", .handler = NULL, .is_protected = 1}
};

int router_dispatch(int client_fd, http_request_t *req){
    int http_code = 404;
    for(int i=0; i<ROUTE_COUNT; i++){
        if(strcmp(route_tables[i].methode,req->method) == 0 && strcmp(route_tables[i].path,req->path) == 0){
            
            if(route_tables[i].is_protected){// routes protected

                //Vérification du token de l'utilisateur
                char user_id[ID_MAX]="";
                int res_authent = auth_verify(req, user_id, ID_MAX);
                if(res_authent == -1){
                    LOG_WARN("The user try to connect");
                    http_response_builder_t response_not_implemented;
                    char *body = "{\"error\":\"Unauthorized\"}";
                    char body_len_not_implemented[16];
                    snprintf(body_len_not_implemented, sizeof(body_len_not_implemented), "%zu", strlen(body));
                    init_http_response_builder(&response_not_implemented, 401);

                    //add headers
                    add_header_http_response_builder(&response_not_implemented, "Content-Type", "application/json");
                    add_header_http_response_builder(&response_not_implemented, "Content-Length", body_len_not_implemented);
                    
                    //send response
                    int serverSendRespond = send_http_response(client_fd, &response_not_implemented, body);
                    if(serverSendRespond == -1){
                        LOG_ERROR("Error during send response for 401 code");
                        return 401;
                    }

                    http_code = 401;
                    return http_code;
                }

                // mettre l'user_id dans la variable req
                strncpy(req->user_id, user_id, ID_MAX-1);

                //l'utilisateur est vérifié
                LOG_INFO("The user %s connected", user_id);
                char body[BODY_MAX]="";
                http_code = route_tables[i].handler(req, body, sizeof(body));

                http_response_builder_t response_protected;
                char body_len_protected[16];
                snprintf(body_len_protected, sizeof(body_len_protected), "%zu", strlen(body));
                init_http_response_builder(&response_protected, http_code);

                //add headers
                add_header_http_response_builder(&response_protected, "Content-Type", "application/json");
                add_header_http_response_builder(&response_protected, "Content-Length", body_len_protected);
                
                //send response
                int serverSendRespond = send_http_response(client_fd, &response_protected, body);
                if(serverSendRespond == -1){
                    LOG_ERROR("Error during send response for %d code", http_code);
                    return http_code;
                }
                

            }else{ // routes unprotected
                
                char body[BODY_MAX]="";
                http_code = route_tables[i].handler(req, body, sizeof(body));

                http_response_builder_t response_not_protected;
                char body_len_not_protected[16];
                snprintf(body_len_not_protected, sizeof(body_len_not_protected), "%zu", strlen(body));
                init_http_response_builder(&response_not_protected, http_code);

                //add headers
                add_header_http_response_builder(&response_not_protected, "Content-Type", "application/json");
                add_header_http_response_builder(&response_not_protected, "Content-Length", body_len_not_protected);
                
                //send response
                int serverSendRespond = send_http_response(client_fd, &response_not_protected, body);
                if(serverSendRespond == -1){
                    LOG_ERROR("Error during send response for %d code", http_code);
                    return http_code;
                }

            }

            break;
        }   
    }
    if (http_code == 404){
        http_response_builder_t response_not_found;
        char *body = "{\"error\":\"Not Found\"}";
        char body_len_not_found[16];
        snprintf(body_len_not_found, sizeof(body_len_not_found), "%zu", strlen(body));
        init_http_response_builder(&response_not_found, 404);

        //add headers
        add_header_http_response_builder(&response_not_found, "Content-Type", "application/json");
        add_header_http_response_builder(&response_not_found, "Content-Length", body_len_not_found);
        
        //send response
        int serverSendRespond = send_http_response(client_fd, &response_not_found, body);
        if(serverSendRespond == -1){
            LOG_ERROR("Error during send response for 404 code");
            return http_code;
        }
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
