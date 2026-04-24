// My module
#include "server/server.h"

int main(int argc, char *argv[]) {

	if (server_init() != 0){ return -1;}
	if (server_run() != 0){ return -1;}
	if (server_shutdown() != 0){ return -1;}

	return 0;
}
