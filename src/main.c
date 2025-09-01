#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BUFFER_SIZE	1024

int main(int argc, char *argv[]) {
	// TODO Redirecte all log to the appropriate file (timestamp) and Manged the log level
	printf("Init the server!\n");
	int server_socket_fd, server_bind, server_listen, client_accepted;
	int server_port=80, max_conn_backlog=10;
	u_int32_t server_ip=INADDR_ANY;
	struct sockaddr_in client_addr;

	// TODO Managed the arguments 

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Create the IPv4 socket!\n");
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket_fd == -1) {
		printf("The IPv4 socket creation failed: %s...\n", strerror(errno));
		// TODO Managed the error code of the server
		return 1;
	}else{
		printf("The IPv4 socket creation sucess!\n");
	}
	
	// TODO Make the server support IPv6 (idea : dual socket()

	// Since the tester restarts your program quite often, setting REUSE_PORT
	// ensures that we don't run into 'Address already in use' errors
	// int reuse = 1;
	// if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
	// 	printf("SO_REUSEADDR failed: %s \n", strerror(errno));
	// 	return 1;
	// }
	
	printf("Define the structure who managed the IPv4 connexion!\n");
	// TODO il faut laisser l'utilisateur choisir le port 
	struct sockaddr_in serv_addr = { 
		.sin_family = AF_INET,
		.sin_port = htons(server_port),
		.sin_addr.s_addr = htonl(server_ip)
	};
	
	printf("Bind the IPv4 socket to server_ip and server_port\n");
	server_bind = bind(server_socket_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (server_bind != 0) {
		printf("Failed to bind the IPv4 socket to server_ip and server_port : %s \n", strerror(errno));
		return 1;
	}else{
		printf("Success to bind the IPv4 socket to erver_ip and server_port\n");
	}
	
	printf("Listen the the IPv4 socket\n");
	server_listen = listen(server_socket_fd, max_conn_backlog);
	if (server_listen != 0) {
		printf("Listen the IPv4 socket failed: %s \n", strerror(errno));
		return 1;
	}else{
		printf("Success to listen the IPv4 socket\n");
	}
	
	printf("Enter in the infinit loop for clients connection\n");
	while (1){
		printf("Waiting for a client to connect...\n");
		// TODO Generate a random ID for each client 
		printf("Accept the connexion from the ID client\n");
		client_accepted = accept(server_socket_fd, (struct sockaddr *) &client_addr, &client_addr);
		if(client_accepted == -1){
			printf("The ID client cannot be connected: %s \n", strerror(errno));
			return 1;
		}

		// TODO Verification of the header 

		printf("The ID client is successefuly connected\n");
		
		// TODO Treat the client in a Thread

		// TODO Treat the command of the client according to the methode of his command

		printf("Close the IPv4 socket after to treat the client command!\n");
		int close_socket = close(server_socket_fd);
		if(close_socket == -1){
			printf("The close of the IPv4 socket failed: %s \n", strerror(errno));
			exit(1);
		}
			
		printf("The IPv4 socket for ID client is successefuly closed\n");
		
	}

	return 0;
}
