#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <uuid/uuid.h>

// My module
#include "main.h"
#include "dotenv/dotenv.h"
#include "middleware/auth.h"

int main(int argc, char *argv[]) {
	int load_env = load_env_file("../.env"); // the file isn't in the same directory that dotenv module.
	if(load_env != 0){
		printf("There is problem when the program try to load the env file!\n");
		exit(1);
	}

	// TODO Redirecte all log to the appropriate file (timestamp) and Manged the log level
	printf("Init the server!\n");
	int server_socket_fd, server_bind, server_listen, client_accepted;
	int max_conn_backlog=10;
	u_int32_t server_ip=INADDR_ANY;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	uuid_t uuid;
	char uuid_str[37];

	char *endptr;
	int server_port=strtol(getenv("SERVER_PORT"), &endptr,10);

	// TODO Managed the arguments 

	// You can use print statements as follows for debugging, they'll be visible when running tests.
	printf("Create the IPv4 socket!\n");
	server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket_fd == -1) {
		printf("The IPv4 socket creation failed: %s...\n", strerror(errno));
		// TODO Managed the error code of the server
		exit(2);
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
		exit(3);
	}else{
		printf("Success to bind the IPv4 socket to erver_ip and server_port\n");
	}
	
	printf("Listen the the IPv4 socket\n");
	server_listen = listen(server_socket_fd, max_conn_backlog);
	if (server_listen != 0) {
		printf("Listen the IPv4 socket failed: %s \n", strerror(errno));
		exit(4);
	}else{
		printf("Success to listen the IPv4 socket\n");
	}
	
	printf("Enter in the infinit loop for clients connection\n");
	while (true){
		printf("Waiting for a client to connect on the port : %d !\n", server_port);
		client_accepted = accept(server_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);
		if(client_accepted == -1){
			printf("The ID client cannot be connected: %s \n", strerror(errno));
			exit(5);
		}

		struct data_thread *dataToThread = malloc(sizeof(struct data_thread));

		free(dataToThread);

		/*
			- route de mon API 
			- /register pour se créer un compte (PUBLIQUE)
			- /login pour generer un Token valide (PUBLIQUE)
			- /logout pour invalider le Token (PROTEGER)
			- /profile pour que l'utilisateur gère son profile (PROTEGER)
				- récupérer les infos de son profile avec GET
				- modifier les infos de son profile avec PUT
				- supprimer son profile avec DELETE

			- Il faut que je crée une table de routage (une liste de route avec leur protection)
				- il faut penser à faire une structure pour acceullir cela. 
		*/

		/*
			- Je dois mettre chaque connexion dans un thread, 
				- quand on rentre dans le threa on génère un UUID de session pour le client
				- Vérifier son bear token (expiré ou fausse) CETTE VERIFICATION DOIT SE FAIRE À CHAQUE REQUETTE
					- verifier si le token est bien formé
					- verifier si le token est dans la DB
					- verifier si le token n'est pas exipré 
					- verifier si le token appartient bien à l'utilisateur
		*/

		// Generate a random UID for each client 
		uuid_generate_random(uuid);
		uuid_unparse_lower(uuid, uuid_str);

		printf("The cliend ID : %s, is successefuly connected.\n", uuid_str);

		// TODO Verification of the header Bear Token (authentication)
		// TODO Verification of the API Key or Bear Token header
		// TODO The client have to create a account 
		// TODO The client have to login from a specifique path, this login generate a token that we have to give to the client in response of the login call
		char client_message[BUFFER_SIZE];
		ssize_t receved_message = recv(client_accepted, client_message, BUFFER_SIZE, 0);

		printf("Client message length : %zd\n", receved_message);
		printf("Client message : \n%s\n------\n", client_message);

		// TODO Make sure that all methode blocked if there are not a bear token valide

		// TODO Verification of the authorization 
		
		// TODO Treat the client in a Thread according to the methode of his command

		verify_token(client_accepted);

		// Use the sprintf() to create the respond with all informations we have
		char *string = "hello";
		size_t string_len = strlen(string);
		char client_response[BUFFER_SIZE];
		sprintf(client_response, "HTTP/1.1 200 ok\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: %ld\r\n\r\n%s", string_len, string);

		ssize_t server_send_respond = send( client_accepted, client_response, strlen(client_response), 0);
		if(server_send_respond == -1){
			printf("The respond fail to be sended: %s \n", strerror(errno));
		}
		printf("\nResponse : \n Send: %zd \nbytes: \n%s\n------\n", server_send_respond, client_response);


		printf("Close the IPv4 socket after to treat the client command!\n");
		int close_client_accepted_socket = close(client_accepted);
		if(close_client_accepted_socket == -1){
			printf("The close of the IPv4 socket failed: %s \n", strerror(errno));
			exit(6);
		}
			
		printf("The IPv4 socket for ID client is successefuly closed\n");
	}

	printf("Close the socket!\n");
	int close_socket = close(server_socket_fd);
	if(close_socket == -1){
		printf("The close socket failed: %s \n", strerror(errno));
		exit(7);
	}
		
	printf("The server end life\n");

	return 0;
}
