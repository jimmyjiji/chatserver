#ifndef SERVER_H
#define SERVER_H 

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <string.h>
#include <time.h>
#include "io.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <semaphore.h>
#include <signal.h>
#include "sqlite3.h"
#include "sfwrite.h"

#define MAX_MSG 1024 /* maximum length of commands */

typedef struct user {
	time_t log_time;
	int socket;
	char name[64];
	char ip[17];
	struct user *next;
	struct user *prev;
} user;

typedef struct login {
	int socket;
	char ip[17];
	struct login *next;
} login;

void cmd_shutdown(int status);

#define USAGE(name) do {                                                                             \
        fprintf(stderr,                                                                              \
            "%s [-hv] [-t THREAD_COUNT] PORT_NUMBER MOTD [ACCOUNTS_FILE]\n"                          \
            "-h                Displays help menu & returns EXIT_SUCCESS.\n"                         \
            "-t THREAD_COUNT   The number of threads used for the login queue.\n"                    \
            "-v                Verbose print all incoming and outgoing protocol verbs & content.\n"  \
            "PORT_NUMBER       Port number to listen on.\n"                                          \
            "MOTD              Message to display to the client when they connnect.\n"               \
            "ACCOUNTS_FILE     File containing username and password data to be loaded upon\n"       \
            "                  execution.\n"                                                         \
            ,(name)                                                                                  \
        );                                                                                           \
    } while(0)

#endif /* SERVER_H */