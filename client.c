#include "client.h"
#include "io.h"

char* name;
char* ip;
char* port;
char auditfilepath[100];


bool response;
bool closechat;
bool newuser;
bool audit;
bool logoutsafe;

chat_list chatlist;

char* password;

int connected;
int VFLAG;
int socket_counter;
int auditfd;

struct pollfd sockets[1000];

pthread_mutex_t T_lock = PTHREAD_MUTEX_INITIALIZER;

int main(int argc, char **argv) {
	audit = false;
	logoutsafe = false;
	socket_counter = 2;
	VFLAG = 0;
	if (argc >  9 || argc < 1) {
		printredtext(&T_lock, stderr, "Invalid Input");
		/*display help menu here*/
		exit(EXIT_FAILURE);
	} else if (argc == 4) {
		//successful commands 
		name = argv[1];
		ip = argv[2];
		port = argv[3];
	} else {
		int c;
		while ((c = getopt(argc, argv, "hcva")) != -1) {
			switch(c) {
				case 'h': printf("%s\n", "help"); 
					printf("./client [-hcv] [-a FILE] NAME SERVER_IP SERVER_PORT\n");
					printf("-h 				Displays this help menu, and returns EXIT_SUCCESS\n");
					printf("-c 				Requests to server to create a new user\n");
					printf("-v  			Verbose print all incoming and outgoing protocol verbs & content.\n");
					printf("NAME 			This is the username to display when chatting \n");
					printf("SERVER_IP  		The ipaddress of the server to connect to\n");
					printf("SERVER_PORT  	The port to connect to\n\n");
				exit(EXIT_SUCCESS);
				case 'c': newuser = true; break;
				case 'v': VFLAG = 1; break;
				case 'a': audit = true;
			}
		}
		/* Get position arguments */
	    if(optind < argc && (argc - optind) == 3 && !audit) {
	    	/* setting up client arguments without the audit log*/
	    	auditfilepath[0] = 0;
	        name = argv[optind++];
			ip = argv[optind++];
			port = argv[optind++];
	    }  else if (optind < argc && (argc - optind) == 4 && audit){
	    	/*setting up the client arguments with the audit log */
	       	strcpy(auditfilepath,argv[optind++]);
	       	name = argv[optind++];
			ip = argv[optind++];
			port = argv[optind++];
    	} else {
    		printredtext(&T_lock, stderr, "Error");
           	exit(EXIT_FAILURE);
    	}
	}
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	if (auditfilepath[0] == 0) {
		auditfd= open("audit.log", O_CREAT | O_RDWR | O_APPEND, mode);
	} else {
		printf("%s\n", auditfilepath);
		auditfd= open(auditfilepath, O_CREAT | O_RDWR | O_APPEND, mode);
	}

	if (auditfd < 0) {
		perr(&T_lock, stderr, "Audit Log ");
	}
	//printf("%d\n", auditfd);

	connected = open_fd_tohost(ip, port);
	if (connected < 0) {
		printredtext(&T_lock, stderr, "Failed to Connect");
		writetoauditLOGIN(auditfd, name, ip, port, false, "Bad Connection");
		close(auditfd);
		exit(EXIT_FAILURE);
	} else {
		printgreentext(&T_lock, stdout, "Connected to Server!");
	}
	
	if (!login_handler(connected, newuser)){
		printredtext(&T_lock, stderr, "Couldn't log in");
		close(connected);
		close(auditfd);
		exit(EXIT_FAILURE);
	}
	
	sockets[0].fd = STDIN_FILENO;
	sockets[0].events = POLLIN;
	sockets[1].fd = connected;
	sockets[1].events = POLLIN;
	init_multiplex(connected);
	

	return EXIT_SUCCESS;
}

int open_fd_tohost(char* ip, char* port) {
	int clientfd;
	struct addrinfo hints, *server_info;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo(ip, port, &hints, &server_info);

	if ((clientfd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol)) < 0)
	    return -1; 

	/* Establish a connection with the server */
    if (connect(clientfd, server_info->ai_addr, server_info->ai_addrlen) < 0) {
        perr(&T_lock, stderr, "connect");
        return -1;
    }
    return clientfd;
}

bool login_handler(int connected, bool newuser) {
	char msg[1024];
	char HI[1024];
	char HINEW[1024];

	strcpy(HINEW, "HINEW ");
	strcat(HINEW, name);
	strcpy(HI, "HI ");
	strcat(HI, name);

	/* sends wolfie protocol to server */
	safe_send(&T_lock, stdout, connected, "WOLFIE", 0, VFLAG);

	/* waits for response */ 
	safe_recv(&T_lock, stdout, connected, msg, VFLAG);

	if (strcmp(msg, "EIFLOW") == 0) {

		if (newuser) {
			//send new user
			safe_send(&T_lock, stdout, connected, "IAMNEW", name, VFLAG);

			//wait for confirmation here
			safe_recv(&T_lock, stdout, connected, msg, VFLAG);
			if(strcmp(msg, HINEW) == 0) {
				password = getpass("Enter a Password Below: ");

				safe_send(&T_lock, stdout, connected, "NEWPASS", password, VFLAG);

				safe_recv(&T_lock, stdout, connected, msg, VFLAG);
				if (strcmp(msg, "SSAPWEN") == 0) {
					//VALID PASSWORD
					safe_recv(&T_lock, stdout, connected, msg, VFLAG);
					goto checker;
				} else {
					//non valid password 
					goto checker;
				}

			} else {
				//didnt do something right 
				//hinew is invalid 
				goto checker;
			}
		} else {
			char AUTH[1024] = "AUTH ";
			strcat(AUTH, name);
			strcat(AUTH, "\0");
		/* send IAM here */
			safe_send(&T_lock, stdout, connected, "IAM", name, VFLAG);
			//waits for confirmiation here 
			safe_recv(&T_lock, stdout, connected, msg, VFLAG);

			if (strcmp(msg, AUTH) == 0) {
				password = getpass("Enter a Password Below: ");

				safe_send(&T_lock, stdout, connected, "PASS", password, VFLAG);

				safe_recv(&T_lock, stdout, connected, msg, VFLAG);

				if(strcmp(msg, "SSAP") == 0) {
					safe_recv(&T_lock, stdout, connected, msg, VFLAG);
				}
				goto checker;
			}
			else if (strcmp(msg, "ERR 01 USER NOT AVAILABLE") == 0) {
				safe_recv(&T_lock, stdout, connected, msg, VFLAG);
				if (strcmp(msg, "BYE") == 0) {
					printredtext(&T_lock, stderr, "User Not Available");
					safe_send(&T_lock, stdout, connected, "BYE", 0, VFLAG);
				} else {
					printf("%s\n", "wtf just happened");
				}
				writetoauditLOGIN(auditfd, name, ip, port, false, "ERR 01 USER NOT AVAILABLE");
				return false;
			} 
			else if (strcmp(msg, "ERR 00 USER NAME TAKEN") == 0) {
				safe_recv(&T_lock, stdout, connected, msg, VFLAG);
				if (strcmp(msg, "BYE") == 0) {
					printredtext(&T_lock, stderr, "Another user has been logged in");
					safe_send(&T_lock, stdout, connected, "BYE", 0, VFLAG);
				} else {
					printf("%s\n", "wtf just happened");
				}
				writetoauditLOGIN(auditfd, name, ip, port, false, "ERR 00 USER NAME TAKEN");
				return false;
			}

			else {
				printf("%s\n", "error");
				//error
			}



checker:
			if (strcmp(msg, HI) == 0) {
				printgreentext(&T_lock, stdout, "Successful Login");
				/* proper login */
				return true;
			} else if (strcmp(msg, "ERR 00 USER NAME TAKEN") == 0) {
				safe_recv(&T_lock, stdout, connected, msg, VFLAG);
				if (strcmp(msg, "BYE") == 0) {
					printredtext(&T_lock, stderr, "Another user has been logged in");
					safe_send(&T_lock, stdout, connected, "BYE", 0, VFLAG);
				} else {
					printf("%s\n", "wtf just happened");
				}
				writetoauditLOGIN(auditfd, name, ip, port, false, "ERR 00 USER NAME TAKEN");
				return false;
			} else if (strcmp(msg, "ERR 02 BAD PASSWORD") == 0) {
				safe_recv(&T_lock, stdout, connected, msg, VFLAG);
				if (strcmp(msg, "BYE") == 0) {
					printredtext(&T_lock, stderr, "You entered an invalid password");
					safe_send(&T_lock, stdout, connected, "BYE", 0, VFLAG);
				} else {
					printf("%s\n", "wtf just happened");
				}
				writetoauditLOGIN(auditfd, name, ip, port, false, "ERR 02 BAD PASSWORD");
			} else {
				//something went wrong
			}
		}
		return false;
	} else {
		//unsuccessful login
		printredtext(&T_lock, stderr, "Didn't receive proper protocol back from server");
		return false;
	}
}

void init_multiplex(int connected) {
	while(1) {
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

	    fd_set readfds;

	    FD_ZERO(&readfds);
	    FD_SET(STDIN_FILENO, &readfds);
	    FD_SET(connected, &readfds);

	    if ((select(connected+1, &readfds, NULL, NULL, &tv)< 0)) {
	    	perr(&T_lock, stderr, "Select error");
	    	exit(EXIT_FAILURE);
	    }

    	
	    char* cmd = calloc(1024, 1);

	    for(int i = 0; i <= connected; i++) {
	    	if (FD_ISSET(STDIN_FILENO, &readfds)) {
	    		if(i == STDIN_FILENO) {
	    			//printf("%s\n", "getting command from stdin");
					read(STDIN_FILENO, cmd, 1024);
					command_handler(cmd, connected);
				}		
	    	} else if (FD_ISSET(connected, &readfds)) {
	    		if (i == connected) {
	    			//printf("%s\n", "getting command from server");
	    			read(connected, cmd, 1024);
	    			if (cmd != NULL)
	    				server_response_handler(cmd, connected, false);
	    			break;
	    		}
	    	}
	    }
	    memset(cmd, 0, 1024);
	    free(cmd);
	}

}


bool server_response_handler(char* command, int connected, bool inchat) {
	bool handled = false;
	char BYE[PACKET_SIZE] = "BYE \r\n\r\n";
	char commandcopy[strlen(command)];
	strcpy(commandcopy, command); 
	char **arrayofcommands = getCommands(commandcopy, " ");
	if (arrayofcommands[0] != NULL) {
		if (strcmp(command, BYE) == 0) {
			if (logoutsafe)
				writetoauditLOGOUT(auditfd, name, true);
			else
				writetoauditLOGOUT(auditfd, name, false);
			//need to kill all children
			close(connected);
			close(auditfd);
			printgreentext(&T_lock, stdout, "Disconneted from Server"); 
			

			exit(EXIT_SUCCESS);
		} 
		else if (strcmp(arrayofcommands[0], "EMIT") == 0) {
			if (strcmp(arrayofcommands[2], "\r\n\r\n") == 0) {
				int length_time = atoi(arrayofcommands[1]);
				int hours, minutes, seconds;
				minutes = length_time/60;
				seconds = length_time%60;
				hours = minutes/60;
				minutes = minutes%60;
				printf("Connected for %d hour(s), %d minutes(s) and %d second(s)\n", hours, minutes, seconds);
			} else {
				printredtext(&T_lock, stderr, "Invalid Protocol");
			}
			handled = true;
		}
		else if (strcmp(arrayofcommands[0], "MOTD") == 0) {
			char buf[1024] = "Message of The Day: ";
			strcat(buf, arrayofcommands[1]);
			strcat(buf, "\n");
			sfwrite(&T_lock, stdout, buf);
			handled = true;
			writetoauditLOGIN(auditfd, name, ip, port, true, arrayofcommands[1]);
		} 
		else if (strcmp(arrayofcommands[0], "UTSIL") == 0) {
			printgreentext(&T_lock, stdout, "Users Connected");
			char** users = malloc(1024); 
			int i = 1;
			int usercount = 0;
			bool validprotocol = true;
			while (arrayofcommands[i] != NULL) {
				//even
				if (i % 2 == 0) {
					if (strcmp(arrayofcommands[i], "\r\n") != 0 && strcmp(arrayofcommands[i], "\r\n\r\n")!= 0) {
						printredtext(&T_lock, stderr, "Invalid Protocol!");
						validprotocol = false;
						break;
					}
				} else {
					//odd
					users[usercount] = arrayofcommands[i];
					usercount++;
				}
				
				i++;
			}
			if (validprotocol) {
				for (int i = 0; i < usercount; i++) {
					printf("%s\n", users[i]);
				}
			}

			free(users);
			handled = true;
		}
		else if (strcmp(arrayofcommands[0], "\n") == 0) {
			handled = true;
			//do nothing
		}
		else if (strcmp(arrayofcommands[0], "MSG")== 0 && inchat == false) {
			char msg[1024] = "";
			for (int i = 3; strcmp(arrayofcommands[i], "\r\n\r\n") != 0; i++) {
				if (i != 3)
					strcat(msg, " ");
				strcat(msg, arrayofcommands[i]);
			}
			recv_chat(connected, arrayofcommands[1], arrayofcommands[2], msg);
			handled = true;
		} 
		else if (strcmp(arrayofcommands[0], "ERR") == 0) {
			//error occured 
			if (strcmp(arrayofcommands[1], "01") == 0) {
				printredtext(&T_lock, stderr, "USER NOT AVAILABLE");
				writetoauditERR(auditfd, name, "ERR 01 USER NOT AVAILABLE");
			} else if (strcmp(arrayofcommands[1] , "02") == 0) {
				printredtext(&T_lock, stderr, "BAD PASSWORD");
				writetoauditERR(auditfd, name, "BAD PASSWORD");
			} else if (strcmp(arrayofcommands[1], "00") == 0) {
				printredtext(&T_lock, stderr, "USER NAME TAKEN");
				writetoauditERR(auditfd, name, "USER NAME TAKEN");
			} else if (strcmp(arrayofcommands[1], "100") == 0) {
				printredtext(&T_lock, stderr, "INTERNAL SERVER ERROR");
				writetoauditERR(auditfd, name, "INTERNAL SERVER ERROR");
			}
			handled = true;
		} 
	}
	memset(arrayofcommands, 0, 1024);
	free(arrayofcommands);

	return handled;
}

char** getCommands(char* input, char* delimiters) {
  int endposition = 0;
  char** allCommands = malloc(1024);
  char *command = "";
  
  //split commands
  command = strtok(input, delimiters);
  while (command != NULL) {
    allCommands[endposition] = command;
    endposition++;
    command = strtok(NULL, " ");
  }
  allCommands[endposition] = NULL;
  return allCommands;
}

bool command_handler(char* command, int connected) {
	char** arrayofcommands = getCommands(command, " \n");
	if (strcmp(command, "\n") == 0) {
		//do nothing
	}
	else if (strcmp(command, "/help") == 0) {
		printf("Commands Accepted\n");
		printf("%s\n", "/logout           	Client disconnects from server");
		printf("%s\n", "/listu 				Get list of all users ");
		printf("%s\n", "/time 				Returns how long you've been connected");
		writetoauditCMD(auditfd, name, command, true, true);
	}
	else if (strcmp(arrayofcommands[0], "/time") == 0) {
		safe_send(&T_lock, stdout, connected, "TIME", 0, VFLAG);
		writetoauditCMD(auditfd, name, arrayofcommands[0], true, true);
	}
	else if (strcmp(arrayofcommands[0], "/logout") == 0) {
		safe_send(&T_lock, stdout, connected, "BYE", 0, VFLAG);
		logoutsafe = true;
	}
	else if (strcmp(arrayofcommands[0], "/listu") == 0) {
		safe_send(&T_lock, stdout, connected, "LISTU", 0, VFLAG);
		writetoauditCMD(auditfd, name, arrayofcommands[0], true, true);
	}
	else if (strcmp(arrayofcommands[0], "/audit") == 0) {
		int newfd;
		if (auditfilepath[0] == 0)
			newfd = readaudit(auditfd, "audit.log");
		else
			newfd = readaudit(auditfd, auditfilepath);
		auditfd = newfd;	
		writetoauditCMD(auditfd, name, arrayofcommands[0], true, true);
	}
	else if (strcmp(arrayofcommands[0], "/chat") == 0) {
		if (arrayofcommands[1] != NULL && arrayofcommands[2] != NULL) {
			char buf[1024];
			memset(buf, 0, 1024);
			for (int i = 2; arrayofcommands[i] != NULL; i++) {
				if (i != 2)
					strcat(buf, " ");
				strcat(buf, arrayofcommands[i]);
				
			}
			writetoauditCMD(auditfd, name, arrayofcommands[0], true, true);
			init_chat(connected, arrayofcommands[1], buf);
			return true;
		} else {
			writetoauditCMD(auditfd, name, arrayofcommands[0], false, true);
			printredtext(&T_lock, stderr, "Invalid Command");
		}
	}
	else {
		writetoauditCMD(auditfd, name, arrayofcommands[0], false, true);
		printredtext(&T_lock, stderr, "Invalid Command");
	}

	
	free(arrayofcommands);
	return false;
}

void recv_chat(int connected, char* to, char* from, char* msg) {
	int index;
	char otheruser[1024];
	if (strcmp(from, name) == 0){
		strcpy(otheruser, to);
		index = hashfunctionstring(otheruser);
		
	} else {
		strcpy(otheruser, from);
		index = hashfunctionstring(otheruser);
	}
	
	//int index = hashfunctionstring(to);
	char* input = calloc(1024, 1);
	int connect_to_chat[2];
	char fd = 0;
	char ** commands = 0;
	pid_t child;
	bool newchat = false;
	/*1 will be the child. 0 will be the parent*/
	const int parentsocket = 0;
    const int childsocket = 1;
  
	signal(SIGCHLD, child_handler);
	if (strcmp(chatlist.other_users[index],"\0") == 0) {
		strcpy(chatlist.other_users[index], otheruser);
		chatlist.loggedon[index] = true;
	    strcat(input, "xterm -geometry 33x10 -T ");
	    if (strcmp(name, from) == 0) {
	    	strcat(input, from);
	    	strcat(input, "_to_");
	    	strcat(input, to);
	    }
	    else {
	    	strcat(input, to);
	    	strcat(input, "_to_");
	    	strcat(input, from);
	    }
	    strcat(input, " -e ./chat ");


		if ((socketpair(AF_UNIX, SOCK_STREAM, 0, connect_to_chat)< 0)) {
			perr(&T_lock, stderr, "Couldn't create socketpair");
			return;
		}

		sockets[socket_counter++].fd = connect_to_chat[parentsocket];
		sockets[socket_counter-1].events = POLLIN;
		sockets[socket_counter++].fd = connect_to_chat[childsocket];
		sockets[socket_counter-1].events = POLLIN;

		chatlist.socketpairs[index][childsocket] = connect_to_chat[childsocket];
		chatlist.socketpairs[index][parentsocket] = connect_to_chat[parentsocket];


		sprintf(&fd, "%d", connect_to_chat[childsocket]);
		strcat(input, &fd);
		
		commands = getCommands(input, " ");
		
		if (strcmp(name, from) == 0)
			write(connect_to_chat[parentsocket], "<", 1);
		else
			write(connect_to_chat[parentsocket], ">", 1);

		if (strcmp(name, from) != 0)
			writetoauditMSG(auditfd, name, "from", from, msg);

		write(connect_to_chat[parentsocket], msg, strlen(msg));
		//writetoauditMSG(auditfd, name, "from", from, msg);

		
		if ((child = fork()) == 0) { /* child */
		 	 /* Redirect stdout to client */
		    close(connect_to_chat[parentsocket]); /* Close the parent file descriptor */
			execvp(commands[0], commands);
		} 

		goto startchat;
	} else {
	startchat:	

		close(chatlist.socketpairs[index][childsocket]);
		while(1) {

			if((poll(sockets, socket_counter, 1000)) < 0) {
				perr(&T_lock, stderr, "poll");
				exit(EXIT_FAILURE);
			}
			
			if (closechat)
				goto endchat;
		     char* buf = calloc(1024, 1);
		    for(int i = 0; i < socket_counter; i++) {
		    	 if (sockets[i].revents & POLLIN) { 
		    		 if (sockets[i].fd == connected) {
		    			//printf("%s\n", "getting command from server");
		    			memset(buf, 0, 1024);
		    			read(connected, buf, 1024);
		    			if (buf != NULL && strcmp(buf, "") != 0) {
		    				char originalcommand[1024] = "";
		    				strcat(originalcommand, buf);
		    				char** arrayofcommands = getCommands(buf, " ");
		    				if (arrayofcommands[2] != NULL) {
			    				int y = hashfunctionstring(arrayofcommands[2]);
			    				//printf("%d\n", newchat);
			    				if (strcmp(chatlist.other_users[y], "\0") == 0) {
			    					// printf("%s\n", "made new chat true");
			    					chatlist.loggedon[y] = true;
			    					newchat = true;
			    				}
		    				}

		    				if (strcmp(arrayofcommands[0], "UOFF") == 0) {
		    					char* logoff = "Other user has logged off";
								if (strcmp(arrayofcommands[1], otheruser) == 0) {
									int x = hashfunctionstring(otheruser);
									if ((strcmp(arrayofcommands[2], from) != 0 && (strcmp(arrayofcommands[1], to)!= 0))) {
											int finder;
											for (finder = 0; finder < 1000; finder++) {
												if(strcmp(chatlist.other_users[finder], arrayofcommands[2]) == 0){
													break;
												}
											}
											if (finder != 1000) {
												//printf("Found %s\n", arrayofcommands[2]);
												x = finder;
											} else {
												//printf("Looking for %s and didn't find it\n", arrayofcommands[2]);
											}

										}
										//printf("writing to parent socket %d\n", chatlist.socketpairs[x][parentsocket]);
					    							    				

					    				close(chatlist.socketpairs[x][childsocket]);
					    				write(chatlist.socketpairs[x][parentsocket], logoff, strlen(logoff));
					    				chatlist.loggedon[x] = false;
					    				//printf("Wrote this %s to %s\n", msg, chatlist.other_users[x]);

								}
							}

		    				if (!newchat) {
			    				if (!(server_response_handler(originalcommand, connected, true))) {
				    				char msg[1024] = "";
									for (int i = 3; strcmp(arrayofcommands[i], "\r\n\r\n") != 0; i++) {
										if (i!=3)
											strcat(msg, " ");
										strcat(msg, arrayofcommands[i]);
										
									}

									if (strcmp(arrayofcommands[2], name) != 0){
										//where to write 

										int x = hashfunctionstring(otheruser);


										if (((strcmp(arrayofcommands[2], from) != 0) && (strcmp(arrayofcommands[1], to)!= 0))) {
											int finder;
											for (finder = 0; finder < 1000; finder++) {
												if(strcmp(chatlist.other_users[finder], arrayofcommands[2]) == 0){
													break;
												}
											}
											if (finder != 1000) {
												x = finder;
											} 
										} 

					    				//if (strcmp(name, arrayofcommands[1]) == 0 && strcmp(arrayofcommands[2], chatlist.other_users[x]) == 0) {
					    				writetoauditMSG(auditfd, name, "from", chatlist.other_users[x], msg);
					    				//}
										
					    				close(chatlist.socketpairs[x][childsocket]);
					    				write(chatlist.socketpairs[x][parentsocket], msg, strlen(msg));
					    				
					    				
				    				}
				    				memset(msg, 0, 1024);
				    				free(arrayofcommands);
				    				}
				    			memset(buf, 0, 1024);
			    			} else {
			    				server_response_handler(originalcommand, connected, false);
			    				newchat = false;	
			    				memset(buf, 0, 1024);
			    			}
		    				memset(originalcommand, 0, 1024);
		    			}
		    			memset(buf, 0, 1024);

		    			break;
		    		} else if(sockets[i].fd == STDIN_FILENO) {
		    			//printf("%s\n", "getting command from stdin");
		    			memset(buf, 0, 1024);
						read(STDIN_FILENO, buf, 1024);
						newchat = command_handler(buf, connected);
						memset(buf, 0, 1024);
						break;
					} else {
						memset(buf, 0, 1024);
						read(sockets[i].fd, buf, 1024);
						if (buf != NULL && strcmp(buf, "")!= 0) {
							//printf("Received from child %s\n", buf);
							int fd = sockets[i].fd;
							int finder;
							for (finder = 0; finder < 1000; finder++) {
								if (chatlist.socketpairs[finder][parentsocket] == fd) {
									break;
								}
							}
					    	char tosend[1024] = "";
					    	char otheruser[100];
					    	strcpy(otheruser, chatlist.other_users[finder]);
					    	bool otherusertrue;
					    	if (strcmp(name, chatlist.other_users[finder]) == 0){
					    		strcat(tosend, from);
					    		otherusertrue = true;
					    	}
					    	else{
					    		strcat(tosend, chatlist.other_users[finder]);
					    		otherusertrue = false;
					    	}
					    	strcat(tosend, " ");
					    	strcat(tosend, name);
					    	strcat(tosend, " ");
					    	strcat(tosend, buf);
					    	safe_send(&T_lock, stdout, connected, "MSG", tosend, VFLAG);
					    	if (otherusertrue)
					    		writetoauditMSG(auditfd, name, "to", from, buf);
					    	else
					    		writetoauditMSG(auditfd, name, "to", otheruser, buf);
				    	}
				    	memset(buf, 0, 1024);
				    	break;
					}			
		    	} 
		    	memset(buf, 0, 1024);
		    }
		    free(buf);
	}
	
	}
	endchat:
	if (closechat){
		memset(chatlist.other_users[index], 0, 1024);
		close(chatlist.socketpairs[index][parentsocket]);
		close(chatlist.socketpairs[index][childsocket]);
		closechat = false;
	}

	free(input);
	free(commands);
	
	
}


void init_chat(int connected, char* to, char* msg) {
	char verb[1024] = "MSG ";
	strcat(verb, to);
	strcat(verb, " ");
	strcat(verb, name);
	safe_send(&T_lock, stdout, connected, verb, msg, VFLAG);
	writetoauditMSG(auditfd, name, "to", to, msg);
}

void child_handler(int sig) {
	closechat = true;
	pid_t pid;
	pid = wait(NULL);
	printf("Closed Chat Window in Child: %d\n", pid);
	return;
}