#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "io.h"
#include <stdbool.h>
#include  <fcntl.h>
#include <signal.h>


int main(int argc, char **argv) {
	
	bool firstmessage = true;
	bool loggedoff = false;
	int connected;
	if (argc == 2) {
		connected = atoi(argv[1]);
	} else {
		exit(EXIT_FAILURE);
	}
	
	//printf("%d\n", connected);
	bool close = false;
	char* movedowncursor = " \e[100;0H";
	write(STDOUT_FILENO, movedowncursor, strlen(movedowncursor));

	while(!close) {
		char* buf = calloc(1024,1);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

	    fd_set readfds;

	    FD_ZERO(&readfds);
	    FD_SET(STDIN_FILENO, &readfds);
	    FD_SET(connected, &readfds);

	    if ((select(connected+1, &readfds, NULL, NULL, &tv)< 0)) {
	    	perror("Select error");
	    	exit(EXIT_FAILURE);
	    }
    	
	  
	    for(int i = 0; i <= connected; i++) {
	    	if (FD_ISSET(STDIN_FILENO, &readfds)) {
	    		if(i == STDIN_FILENO) {
	    			//printf("%s\n", "getting command from stdin");
					read(STDIN_FILENO, buf, 1024);
					if (buf != NULL && strcmp(buf, "") != 0 ) {
						if (loggedoff) {
							close = true;
							break;
						}
						if (strcmp(buf, "/close\n") == 0) {
							close = true;
							break;
						} else {
							write(connected, buf, strlen(buf));
						}
						// fflush(stdout);
						// write(STDOUT_FILENO, movetofront, strlen(movetofront));
						// write(STDOUT_FILENO, delete, strlen(delete));
						printf("> %s\n", buf);
					}
				}		
	    	} else if (FD_ISSET(connected, &readfds)) {
	    		if (i == connected) {
	    			//printf("%s\n", "getting command from server");
	    			read(connected, buf, 1024);
	    			if (buf != NULL && strcmp(buf, "") != 0) {
	    				if (strcmp(buf, "close") == 0) {
	    					printf("%s\n", "Received close from parent");
	    					loggedoff = true;
	    					break;
	    				}
	    				if (firstmessage) {
	    					printf("%s\n", buf);
	    					firstmessage = false;
	    				} else {
	    					printf("< %s\n", buf);
	    				}
	    			} 
	    			break;
	    		}
	    	}
	    }
	    memset(buf, 0, 1024);
	    free(buf);
	}
	return 0;
}