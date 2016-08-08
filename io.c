/* this file contains implementation of our I/O functions */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "sfwrite.h"


extern void printgreentext(pthread_mutex_t *lock, FILE* term, char* string) {
	char green[200] = "\e[1;32m";
	char* end = "\e[m\n";
	strcat(green, string);
	strcat(green, end);
	sfwrite(lock, term, green);
}

extern void printredtext(pthread_mutex_t *lock, FILE* term, char* string) {
	char red[200] = "\e[1;31m";
	char* end = "\e[m\n";
	strcat(red, string);
	strcat(red, end);
	sfwrite(lock, term, red);
}

void verbose_send(pthread_mutex_t *lock, FILE* term, char* string, int socket) {
	char blue[200];
	sprintf(blue, "\e[1;34m->Outgoing Protocol (Socket %d): ", socket);
	char* end = "\e[m\n";
	strcat(blue, string);
	strcat(blue, end);
	sfwrite(lock, term, blue);
}

void verbose_recv(pthread_mutex_t *lock, FILE* term, char* string, int socket) {
	char blue[200];
	sprintf(blue, "\e[1;34m<-Incoming Protocol (Socket %d): ", socket);
	char* end = "\e[m\n";
	strcat(blue, string);
	strcat(blue, end);
	sfwrite(lock, term, blue);
}

/* returns the number of bytes received, or -1 if an error */
extern ssize_t safe_recv(pthread_mutex_t *lock, FILE* term, int socket, char *buf, int vflag) {
	char c[1];
	int i;
	
	memset(buf, '\0', 1024);
	*c = '\0';

	for(i = 0;(recv(socket, c, 1, 0) == 1);i++) {
		if(*c == '\r') {
			if(recv(socket, c, 1, 0) != 1)
				return -1;
			if(*c == '\n') {				
				if(recv(socket, c, 1, 0) != 1)
					return -1;
				if(*c == '\r') {
					if(recv(socket, c, 1, 0) != 1)
						return -1;
					if(*c == '\n') {
						/* DELIM found */
						i -= 1;
						buf[i] = '\0';
						if(vflag)
							verbose_recv(lock, term, buf, socket);
						return i;
					} else {
						buf[i++] = '\r';
						buf[i++] = '\n';
						buf[i++] = '\r';
						buf[i] = *c;
					}
				} else {
					buf[i++] = '\r';
					buf[i++] = '\n';
					buf[i] = *c;
				}
			} else {
				buf[i++] = '\r';
				buf[i] = *c;
			}			
		} else 
			buf[i] = *c;
	}
	/* if we reached here, sender disconnected or some other error */
	return -1;
}

extern ssize_t safe_send(pthread_mutex_t *lock, FILE* term, int socket, char* verb, char* msg, int vflag) {
	char buf[1024];
	memset(buf, '\0', 1024);
	if(!verb)
		return 0;
	strcpy(buf, verb);
	if(msg) {
		strcat(buf, " ");
		strcat(buf, msg);
	}
	if(vflag)
		verbose_send(lock, term, buf, socket);
	strcat(buf, " \r\n\r\n");
	return send(socket, buf, strlen(buf), 0);
}

extern void perr(pthread_mutex_t *lock, FILE* term, char *func) {
	char red[200] = "\e[1;31m";
	char *end = "\e[m\n";
	char *err = strerror(errno);
	strcat(red, func);
	strcat(red, " error: ");
	strcat(red, err);
	strcat(red, end);
	sfwrite(lock, term, red);
}