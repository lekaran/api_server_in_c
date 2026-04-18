#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sodium.h>

// My module
#include "server.h"
#include "../dotenv/dotenv.h"
#include "../middleware/auth.h"
#include "../router/router.h"
#include "../logger/logger.h"
#include "../http/http_parser.h"
#include "../http/http_response.h"
#include "../DB/db.h"

// Global Variables 
static int server_socket_fd;
static volatile sig_atomic_t should_quit = 0;

static int create_server_socket(void){
    int server_bind, server_listen;
	int max_conn_backlog=10;
	u_int32_t server_ip=INADDR_ANY;

	char *endptr;
	int server_port=strtol(getenv("SERVER_PORT"), &endptr,10);

	LOG_DEBUG("Create the IPv4 socket!");
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket_fd == -1) {
		LOG_ERROR("The IPv4 socket creation failed: %s...", strerror(errno));
		return -1;
	}
		
	LOG_INFO("The IPv4 socket creation sucess!");

    int reuse = 1;
	if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		LOG_ERROR("SO_REUSEADDR failed: %s", strerror(errno));
		return -1;
	}

	LOG_DEBUG("Define the structure who managed the IPv4 connexion!");
	struct sockaddr_in serv_addr = { 
		.sin_family = AF_INET,
		.sin_port = htons(server_port),
		.sin_addr.s_addr = htonl(server_ip)
	};
	
	LOG_DEBUG("Bind the IPv4 socket to server_ip and server_port");
	server_bind = bind(server_socket_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (server_bind != 0) {
		LOG_ERROR("Failed to bind the IPv4 socket to server_ip and server_port : %s", strerror(errno));
		return -1;
	}
	
	LOG_INFO("Success to bind the IPv4 socket to erver_ip and server_port");
	
	LOG_DEBUG("Listen the the IPv4 socket");
	server_listen = listen(server_socket_fd, max_conn_backlog);
	if (server_listen != 0) {
		LOG_ERROR("Listen the IPv4 socket failed: %s", strerror(errno));
		return -1;
	}
	
	LOG_INFO("Success to listen the IPv4 socket");
    return 0;
}

static void handleSIGINT(int sig) {
	(void)sig;
	should_quit = 1;
}

static int setup_signals(void){
	struct sigaction action;

	action.sa_handler = handleSIGINT;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

	int sigaction_return = sigaction(SIGINT, &action, NULL);
	if (sigaction_return == -1) {
		LOG_ERROR("Error during the listing signal: %s", strerror(errno));
        return -1;
    }

	return 0;
}

int server_init(void){
    log_init(LOG_LEVEL_DEBUG, "/var/log/api_c.log");

	if(sodium_init() == -1){
        LOG_ERROR("There is a problem during the sodium init");
        return -1;
    }

	LOG_DEBUG("Load the env variables : ");
	int load_env = load_env_file("../.env"); // the file isn't in the same directory that dotenv module.
	if(load_env != 0){
		LOG_ERROR("There is problem when the program try to load the env file!");
		return -1;
	}

	//make a healthchek to the database
	int db_hc = db_healthcheck();
	if (db_hc != 0) {
		LOG_ERROR("The server can't connect to the Database");
		return -1;
	}

	if (create_server_socket() != 0){ return -1;}
	if (setup_signals() != 0){ return -1;}

    return 0;
}

int server_run(void){
	int client_accepted;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	uuid_t uuid;
	char uuid_str[37];

	char *endptr;
	int server_port=strtol(getenv("SERVER_PORT"), &endptr,10);

	LOG_INFO("Enter in the infinit loop for clients connection");
	while (true){
		LOG_DEBUG("Waiting for a client to connect on the port : %d ", server_port);
		client_accepted = accept(server_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if(client_accepted == -1){
			if(errno == EINTR && should_quit == 1){
				LOG_INFO("Receve a signal (Ctrl+C) then close the socket!");
				return 0;
			}
			LOG_ERROR("The ID client cannot be connected: %s ", strerror(errno));
			return -1;
		}

		// Generate a random UID for each client 
		uuid_generate_random(uuid);
		uuid_unparse_lower(uuid, uuid_str);

		LOG_INFO("The cliend ID : %s, is successefuly connected.", uuid_str);

		char client_message[BUFFER_SIZE];
		ssize_t receved_message = recv(client_accepted, client_message, BUFFER_SIZE-1, 0);
		if(receved_message == -1){
			if(errno == EINTR && should_quit == 1){
				LOG_INFO("Receve a signal (Ctrl+C) then close the socket!");
				return 0;
			}
			LOG_ERROR("There are some trouble when receive some response : %s ",strerror(errno));
		}
		client_message[receved_message]='\0';

		http_request_t req; 

		int parse_result = http_parse_request(client_message,(int)receved_message, &req);

		if(parse_result == -1){
			LOG_ERROR("400 Bad Request");

			int serverSendRespond = http_response(client_accepted, 400, "{\"error\":\"Bad Request\"}");
			if(serverSendRespond == -1){
				LOG_ERROR("The respond fail to be sended: %s ", strerror(errno));
				close(client_accepted);
				continue;
			}

			if(close(client_accepted) == -1){
				LOG_ERROR("The close of the IPv4 socket failed: %s ", strerror(errno));
				continue;
			}
			continue;
		}

		router_dispatch(client_accepted, &req);

		LOG_DEBUG("Close the IPv4 socket after to treat the client command!");
		int close_client_accepted_socket = close(client_accepted);
		if(close_client_accepted_socket == -1){
			LOG_ERROR("The close of the IPv4 socket failed: %s ", strerror(errno));
			return -1;
		}
			
		LOG_DEBUG("The IPv4 socket for ID client is successefuly closed");
	}

	return 0;
}

int server_shutdown(void){

	LOG_INFO("Close the socket!");
	int close_socket = close(server_socket_fd);
	if(close_socket == -1){
		LOG_ERROR("The close socket failed: %s ", strerror(errno));
		return -1;
	}
		
	LOG_INFO("The server end life\n");

	log_close();
	return 0;
}