#ifndef CLIENT_H
#define CLIENT_H

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netdb.h>
#include <strings.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include "sfwrite.h"

#define PACKET_SIZE 1024
int open_fd_tohost(char* ip, char* port);
bool login_handler(int connected, bool newuser);
void init_multiplex(int connected);
bool server_response_handler(char* command, int connected, bool inchat);
bool command_handler(char* command, int connected);
char** getCommands(char* input, char* delimiters);
void recv_chat(int connected, char* to, char* from, char* msg);
void init_chat(int connected, char* to, char* msg);
void child_handler(int sig);

/*bootleg hash chat list*/
struct chat_list {
	//can hold up a chat with 1000 people 
	char other_users[1000][1024];
	//coressponding index to fd
	int socketpairs[1000][2];
	bool loggedon[1000];
}typedef chat_list;



int hashfunctionstring(char *string) {
	unsigned long hash = 5381;
	int index;

	while ((index = *string++)) {
		hash = ((hash << 5) + hash) + index;
	}
	return hash%1000;
}

int readaudit(int fd, char* filename) {
	close(fd);
	int newfd = open(filename, O_CREAT | O_RDWR | O_APPEND);
	FILE* auditptr; 
	char letter;
	char* letterptr = &letter;
	auditptr = fdopen(newfd, "r");
	if (auditptr == NULL ) {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
   } else {
   	while( (letter = fgetc(auditptr) ) != EOF )
      write(STDOUT_FILENO, letterptr, 1);
   }
   write(STDOUT_FILENO, "\n", 1);
   //fclose(auditptr);
  
   return newfd;
}


char* gettime() {
	char* buffer = (char*) calloc(200, 1);
  	time_t curtime;
  	struct tm *loctime;
 	 /* Get the current time. */
  	curtime = time (NULL);

  	/* Convert it to local time representation. */
  	loctime = localtime (&curtime);
	//put in buffer
	strftime (buffer, 200, "%D-%I:%M %p", loctime);
	

  return buffer;
}

void writetoauditLOGIN(int fd, const char* username, const char* ip, const char* port, bool success, const char* msg) {
	flock(fd, LOCK_EX);
	char* curtime = gettime();
	char buf[1024];
	memset(buf, 0, 1024);
	strcat(buf, curtime);
	strcat(buf, ", ");
	strcat(buf, username);
	strcat(buf, ", ");
	strcat(buf, "LOGIN");
	strcat(buf, ", ");
	strcat(buf, ip);
	strcat(buf, ":");
	strcat(buf, port);
	strcat(buf, ", ");
	if (success) 
		strcat(buf, "success");
	else
		strcat(buf, "failure");
	strcat(buf, ", ");
	strcat(buf, msg);
	strcat(buf, "\n\0");
	write(fd, buf, strlen(buf));
	flock(fd, LOCK_UN);
	free(curtime);
}

void writetoauditCMD(int fd, const char* username, const char* cmd, bool success, bool client) {
	flock(fd, LOCK_EX);
	char* curtime = gettime();
	char buf[1024];
	memset(buf, 0, 1024);
	strcat(buf, curtime);
	strcat(buf, ", ");
	strcat(buf, username);
	strcat(buf, ", ");
	strcat(buf, "CMD");
	strcat(buf, ", ");
	strcat(buf, cmd);
	strcat(buf, ", ");
	if (success) 
		strcat(buf, "success");
	else
		strcat(buf, "failure");
	strcat(buf, ", ");

	if (client)
		strcat(buf, "client");
	else
		strcat(buf, "chat");
	strcat(buf, "\n\0");
	write(fd, buf, strlen(buf));
	flock(fd, LOCK_UN);
	free(curtime);
}

void writetoauditMSG(int fd, const char* username, const char* tofrom, const char* user, const char* msg) {
	flock(fd, LOCK_EX);
	char* curtime = gettime();
	char buf[1024];
	memset(buf, 0, 1024);
	strcat(buf, curtime);
	strcat(buf, ", ");
	strcat(buf, username);
	strcat(buf, ", ");
	strcat(buf, "MSG");
	strcat(buf, ", ");
	strcat(buf, tofrom);
	strcat(buf, ", ");
	strcat(buf, user);
	strcat(buf, ", ");
	strcat(buf, msg);
	strcat(buf, "\0");
	write(fd, buf, strlen(buf));
	flock(fd, LOCK_UN);
	free(curtime);
}

void writetoauditLOGOUT(int fd, const char* username, bool intentional) {
	flock(fd, LOCK_EX);
	char* curtime = gettime();
	char buf[1024];
	memset(buf, 0, 1024);
	strcat(buf, curtime);
	strcat(buf, ", ");
	strcat(buf, username);
	strcat(buf, ", ");
	strcat(buf, "LOGOUT");
	strcat(buf, ", ");
	if (intentional)
		strcat(buf, "intentional");
	else
		strcat(buf, "error");
	strcat(buf, "\n\0");
	write(fd, buf, strlen(buf));
	flock(fd, LOCK_UN);
	free(curtime);
}

void writetoauditERR(int fd, const char* username, const char* errmsg) {
	flock(fd, LOCK_EX);
	char* curtime = gettime();
	char buf[1024];
	memset(buf, 0, 1024);
	strcat(buf, curtime);
	strcat(buf, ", ");
	strcat(buf, username);
	strcat(buf, ", ");
	strcat(buf, "ERR, ");
	strcat(buf, errmsg);
	strcat(buf, "\n\0");
	write(fd, buf, strlen(buf));
	flock(fd, LOCK_UN);
	free(curtime);
}
#endif /* CLIENT_H */