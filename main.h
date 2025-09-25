#ifndef MAIN_H
#define MAIN_H

#include <signal.h>

#define BUFFER_SIZE	1024
volatile sig_atomic_t should_quit = 0;

struct data_thread {
	int client_socket;
	// int argc;
	// char *dir_path;
};

void handleSIGINT(int sig);

#endif
