#include "server.h"
#include "io.h"

/* global variables to be shared between threads */
struct login LOGIN_Q;
struct user USERS;
sqlite3 *ACCOUNTS;
char MOTD[128];
int VFLAG, ACCEPT_FD, COMM_THREAD;
pthread_mutex_t T_lock = PTHREAD_MUTEX_INITIALIZER;
/* mutex for login queue */
pthread_mutex_t Q_lock = PTHREAD_MUTEX_INITIALIZER;
/* mutex for user list */
pthread_mutex_t U_lock = PTHREAD_MUTEX_INITIALIZER;
/* mutex for account list */
pthread_mutex_t A_lock = PTHREAD_MUTEX_INITIALIZER;
sem_t items_sem;

void db_err() {
	const char *err = sqlite3_errmsg(ACCOUNTS);
	sfwrite(&T_lock, stderr, "\e[1;31msqlite3 error: %s\e[m\n", err);
}

void append_salt(char *password, unsigned char *salt, unsigned char newpass[130]) {
	int i, j;
	/* converting password to unsigned */
	for(i = 0;i < strlen(password);i++) {
		newpass[i] = (unsigned char)password[i];
	}

	/* appending salt to newpass */
	for(j = 0;j < strlen((char*)salt);i++) {
		newpass[i] = salt[j++];
	}
}

/* 
 * I'd like to give some credit to http://stackoverflow.com/a/2458382 for this
 * function, as I based this function closely off the code on that webpage. 
 */
void hash_password(unsigned char *password, char hashout[65]) {
	int i;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, password, strlen((char*)password));
	SHA256_Final(hash, &sha256);
	for(i = 0;i < SHA256_DIGEST_LENGTH;i++) {
		sprintf(hashout + (i*2), "%02x", hash[i]);
	}
	hashout[64] = '\0';
}

/* return 1 if success. -1 if error */
int add_account(char *name, char *password) {
	/* if no name or password provided, return error */
	if(!name || !password)
		return -1;
	char stmt[1024], pass[65], hashpass[65], salt[65], *err;
	unsigned char sbuf[33], newpass[130];
	int ret, i;

	err = 0;
	strcpy(pass, password);

	/* generating salt and adding it to password */
	if(RAND_bytes(sbuf, 32) < 0) {
		printredtext(&T_lock, stdout, "RAND_bytes error: failed");
		return -1;
	}

	/* creating salt string from sbuf random bytes */
	for(i = 0;i < strlen((char*)sbuf);i++) {
		sprintf(salt + (i * 2), "%02x", sbuf[i]);
	}
	/* appending salt to pass and hashing newpass using SHA 256. stored in hashpass */
	append_salt(pass, sbuf, newpass);	
	hash_password(newpass, hashpass);

	/* setting up SQL statement */
	strcpy(stmt, "INSERT INTO ACCOUNTS (NAME, PASSWORD, SALT) VALUES ('");
	strcat(stmt, name);
	strcat(stmt, "', '");
	strcat(stmt, hashpass);
	strcat(stmt, "', '");
	strcat(stmt, salt);
	strcat(stmt, "')");

	pthread_mutex_lock(&A_lock);
	/* executing SQL statement */
	if((ret = sqlite3_exec(ACCOUNTS, stmt, 0, 0, &err)) != SQLITE_OK) {
		db_err();
		sqlite3_free(err);
		pthread_mutex_unlock(&A_lock);
		return -1;
	} else {
		pthread_mutex_unlock(&A_lock);
		return 1;
	}
}

/* return -1 on error. 1 on success */
int init_accounts(const char *database) {
	int ret;
	char *stmt, *err;
	err = 0;	
	stmt = "CREATE TABLE IF NOT EXISTS ACCOUNTS (NAME TEXT PRIMARY KEY NOT NULL, PASSWORD TEXT NOT NULL, SALT TEXT NOT NULL)";

	if(database) {
		if((ret = sqlite3_open(database, &ACCOUNTS)) != SQLITE_OK) {
			db_err();
			sqlite3_free(err);
			return -1;
		}
	} else {
		if((ret = sqlite3_open("accounts.db", &ACCOUNTS)) != SQLITE_OK) {
			db_err();
			sqlite3_free(err);
			return -1;	
		}	
	}	
	if((ret = sqlite3_exec(ACCOUNTS, stmt, 0, 0, &err)) != SQLITE_OK) {
		db_err();
		sqlite3_free(err);
      	return -1;
    } else {
    	return 1;
    }
}

/* return -1 on error. 1 on success */
int remove_user(struct user *u) {
	pthread_mutex_lock(&U_lock);
	close(u->socket);
	struct user *n, *p;
	n = u->next;
	p = u->prev;
	if(n) {		
		n->prev = p;
		p->next = n;
	} else {
	 	p->next = NULL;
	}
	free(u);
	pthread_mutex_unlock(&U_lock);
	return 1;	
}

/* return -1 on error. 1 on success */
int add_user(struct user new_user) {
	struct user *active_user, *ptr;
	/* mallocing space for a new user and copying over info */
	active_user = malloc(sizeof(user));
	active_user->log_time = time(0);
	active_user->socket = new_user.socket;
	active_user->next = NULL;
	strcpy(active_user->name, new_user.name);
	strcpy(active_user->ip, new_user.ip);
	/* popping the new active user into the users list */
	pthread_mutex_lock(&U_lock);
	ptr = USERS.next;	
	if(USERS.next) {
		while(ptr->next) {
			if(strcmp(ptr->name, active_user->name) == 0) {
				pthread_mutex_unlock(&U_lock);
				return -1;
			}
			ptr = ptr->next;
		}
		if(strcmp(ptr->name, active_user->name) == 0) {
			pthread_mutex_unlock(&U_lock);
			return -1;
		}
		ptr->next = active_user;
		active_user->prev = ptr;
	} else {
		USERS.next = active_user;
		active_user->prev = &USERS;
	}
	pthread_mutex_unlock(&U_lock);
	return 1;	
}

/* return -1 for reject/existing user, 1 for free name */
int verify_user(char* name) {
	struct user *ptr;
	/* zero users logged in */
	pthread_mutex_lock(&U_lock);
 	if(!USERS.next) {
 		pthread_mutex_unlock(&U_lock);
 		return 1;
 	}
 	ptr = USERS.next;
	while(ptr) {
		if(ptr->name) {
			if(strcmp(ptr->name, name) == 0) {
				pthread_mutex_unlock(&U_lock);
				/* another user is currently logged in under this name */
				return -1;
			}
		}
		ptr = ptr->next;
	}
	pthread_mutex_unlock(&U_lock);
	/* user name is available */
	return 1;
}

/* return -1 for invalid, 1 for valid */
int valid_password(char *pass) {
	if(!pass)
		return -1;
	int i, len, upper, symbol, number;
	upper = 0;
	symbol = 0;
	number = 0;
	len = strlen(pass);
	/* Criteria: At least 5 characters in length */
	if(len < 5)
		return -1;
	/* Criteria: At least 1 uppercase char, 1 symbol, and 1 number */
	for(i = 0;i < len;i++) {
		if((pass[i] >= 0x41) && (pass[i] <= 0x5A))
			upper++;
		if(((pass[i] >= 0x21) && (pass[i] <= 0x2F)) || ((pass[i] >= 0x3A) && (pass[i] <= 0x40)) ||
			((pass[i] >= 0x5B) && (pass[i] <= 0x60)) || ((pass[i] >= 0x7B) && (pass[i] <= 0x7E)))
			symbol++;
		if((pass[i] >= 0X30) && (pass[i] <= 0X39))
			number++;
	}
	if((!upper) || (!symbol) || (!number))
		return -1;
	else
		return 1;
}

/* return -1 for wrong password - return 1 for correct password */
int verify_password(char *name, char *pass) {
	if(!name || !pass)
		return -1;
	char stmt[1024], password[65], buf[3], salt[65], hashpass[65], *ptr;
	int i, j, un_byte, ret;
	unsigned char newpass[130], sbuf[33];
	sqlite3_stmt* step;

	step = NULL;
	pthread_mutex_lock(&A_lock);
	strcpy(stmt, "SELECT * FROM ACCOUNTS WHERE ACCOUNTS.NAME = '");
	strcat(stmt, name);
	strcat(stmt, "'");

	if(sqlite3_prepare_v2(ACCOUNTS, stmt, -1, &step, 0) != SQLITE_OK) {
		db_err();
		pthread_mutex_unlock(&A_lock);
		return -1;
	}

	/* retrieving hashed password and salt fromm user account */
	if((ret = sqlite3_step(step)) == SQLITE_ROW) {
		strcpy(password, (char*)sqlite3_column_text(step, 1));
		strcpy(salt, (char*)sqlite3_column_text(step, 2));
	} else if(ret == SQLITE_ERROR) {
		db_err();
		pthread_mutex_unlock(&A_lock);
		return -1;
	}
	sqlite3_finalize(step);
	/* converting salt to unsigned char and appending to newpass */
	for(i = 0,j = 0;i < strlen(salt);i++) {
		buf[0] = salt[i++];
		buf[1] = salt[i];
		buf[2] = '\0';
		un_byte = (int)strtol(buf, &ptr, 16);
		sbuf[j] = un_byte;
		j++;
	}

	/* hashing newpass and storing it in hashpass */
	append_salt(pass, sbuf, newpass);
	hash_password(newpass, hashpass);

	/* comparing the passwords */
	if(strcmp(hashpass, password) == 0) {
		pthread_mutex_unlock(&A_lock);
		return 1;
	} else {
		pthread_mutex_unlock(&A_lock);
		return -1;
	}
}

/* return -1 for error - return 0 if no account exists - return 1 if an account exists */
int verify_account(char *name) {
	if(!name)
		return -1;
	char stmt[1024];
	int exists;
	sqlite3_stmt* step;

	step = NULL;
	exists = 1;
	pthread_mutex_lock(&A_lock);
	strcpy(stmt, "SELECT COUNT(*) FROM ACCOUNTS WHERE ACCOUNTS.NAME = '");
	strcat(stmt, name);
	strcat(stmt, "'");
	if(sqlite3_prepare_v2(ACCOUNTS, stmt, -1, &step, 0) != SQLITE_OK) {
		db_err();
		pthread_mutex_unlock(&A_lock);
		return -1;
	}
	/* should return 1 row with the either 1 or 0 as count */
	if(sqlite3_step(step) == SQLITE_ROW)
		exists = sqlite3_column_int(step, 0);
	else {
		db_err();
		pthread_mutex_unlock(&A_lock);
		return -1;
	}	
	sqlite3_finalize(step);
	if(exists) {
		pthread_mutex_unlock(&A_lock);
		return 1;
	}
	else {
		pthread_mutex_unlock(&A_lock);
		return 0;
	}
}

void* spawn_comm_thread(void *arg) {
	struct user *u, *ulist;
	char listu[1024], msg[1024], timez[1024], buf[1024], name[1024];
	fd_set readfds;
	int maxfd, i, j;
	maxfd = 0;
	struct timeval tv;
	while(1) {
		FD_ZERO(&readfds);

		/* setting a timeout so doesn't hang when new sockets are added */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* add all user sockets to the fd set */
		if(!USERS.next) {
			/* zero users. exit thread */
			COMM_THREAD = 0;
			pthread_exit(0);
			return NULL;
		} else {
			u = USERS.next;
			while(u) {
				FD_SET(u->socket, &readfds);
				if(u->socket > maxfd)
					maxfd = u->socket;
				u = u->next;
			}
		}

		if(select((maxfd + 1), &readfds, NULL, NULL, &tv) < 0) {
			perr(&T_lock, stderr, "select COMM");
		}

		u = USERS.next;
		while(u) {
			/* checking each user to see if their socket is set */
			if(FD_ISSET(u->socket, &readfds)) {
				/* client connection dropped if -1 */
				if(safe_recv(&T_lock, stdout, u->socket, msg, VFLAG) == -1) {
					memset(buf, '\0', strlen(buf));
					strcpy(buf, u->name);
					remove_user(u);
					ulist = USERS.next;
					while(ulist) {
						safe_send(&T_lock, stdout, ulist->socket, "UOFF", buf, VFLAG);
						ulist = ulist->next;
					}
					break;
				}
				/* process messages */
				if(strcmp(msg, "BYE") == 0) {
					safe_send(&T_lock, stdout, u->socket, "BYE", 0, VFLAG);
					ulist = USERS.next;

					while(ulist) {
						if(ulist->socket != u->socket) {
							safe_send(&T_lock, stdout, ulist->socket, "UOFF", u->name, VFLAG);
						}
						ulist = ulist->next;
					}
					ulist = u->next;
					remove_user(u);
					u = ulist;
				} else if (strcmp(msg, "TIME") == 0) {					
					sprintf(timez, "%d", (int)difftime(time(0), u->log_time));
					safe_send(&T_lock, stdout, u->socket, "EMIT", timez, VFLAG);
				} else if (strcmp(msg, "LISTU") == 0) {
					ulist = USERS.next;
					memset(listu, '\0', strlen(listu));
					while(ulist) {
						if(ulist->name) {
							strcat(listu, ulist->name);
							if(ulist->next)
								strcat(listu, " \r\n ");
						}
						ulist = ulist->next;
					}
					safe_send(&T_lock, stdout, u->socket, "UTSIL", listu, VFLAG);					
				} else if((msg[0] == 'M') && (msg[1] == 'S') && (msg[2] == 'G') && (msg[3] == ' ') &&
					(msg[4] != ' ')) {
					memset(buf, '\0', strlen(buf));
					strcpy(name, u->name);
					i = 4;
					j = 0;
					while(msg[i] != ' ') {
						if(msg[i] == '\0')
							break;
						buf[j++] = msg[i];
						i++;
					}

					if(msg[i] == '\0') {
						safe_send(&T_lock, stdout, u->socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
						break;
					}
					if(verify_user(buf) != -1)
						safe_send(&T_lock, stdout, u->socket, "ERR", "01 USER NOT AVAILABLE", VFLAG);
					else {
						safe_send(&T_lock, stdout, u->socket, msg, 0, VFLAG);
						ulist = USERS.next;
						while(ulist) {
							if(ulist->name) {
								if(strcmp(buf, ulist->name) == 0) {
									safe_send(&T_lock, stdout, ulist->socket, msg, 0, VFLAG);
									break;
								}
							}
							ulist = ulist->next;
						}
					}
				}
				/* done processing messages */				
			}
			if(u)
				u = u->next;
		}
	}
	return NULL;
}

void login_request(int client_sock, char *ip) {
	/* creating a new login request */
	struct login *new_login, *ptr;
	pthread_mutex_lock(&Q_lock);
	new_login = malloc(sizeof(login));
	if(!new_login) {
		perr(&T_lock, stderr, "malloc");
		cmd_shutdown(EXIT_FAILURE);
	}
	new_login->socket = client_sock;
	new_login->next = NULL;
	strcpy(new_login->ip, ip);

	/* adding request to back of the queue */
	if(LOGIN_Q.next) {
		ptr = LOGIN_Q.next;
		if(ptr->next) {
			while(ptr->next) {
				ptr = ptr->next;
			}
		}
		ptr->next = new_login;
	}
	else {
		LOGIN_Q.next = new_login;	
	}
	pthread_mutex_unlock(&Q_lock);
	sem_post(&items_sem);
}


void* start_login_thread(void *arg) {
	struct user new_user;
	struct login *new_login;
	char pass[64];
	char verb[MAX_MSG];
	int step, x;
	fd_set readfds;
	
	while(1) {
		sem_wait(&items_sem);
		pthread_mutex_lock(&Q_lock);

		/* consuming a login request*/
		new_login = LOGIN_Q.next;
		LOGIN_Q.next = new_login->next;
		/* extracting login request info then freeing it */
		step = 0;
		memset(new_user.name, '\0', strlen(new_user.name));
		new_user.socket = new_login->socket;
		strcpy(new_user.ip, new_login->ip);
		free(new_login);

		pthread_mutex_unlock(&Q_lock);

		/* start login protocol */		
		while(1) {
			/* setting up readfds */
			FD_ZERO(&readfds);
			FD_SET(new_user.socket, &readfds);
			
			/* Bad protocol stuff or BYE happened */
			if(step == -1) {
				close(new_user.socket);
				break;
			}

			/* Great Success */
			if(step == 4) {
				break;
			}

			/* strange errors occured. oOooOOooO! */
			if(select((new_user.socket + 1), &readfds, NULL, NULL, NULL) < 0) {
				perr(&T_lock, stderr, "select LOGIN");
				break;
			}

			/* connection was dropped */
			if(safe_recv(&T_lock, stdout, new_user.socket, verb, VFLAG) < 0) {
				close(new_user.socket);
				break;
			} 
			/* WOLFIE PROTOCOL */
			if(strcmp(verb, "BYE") == 0) {
				step = -1;
			/* STEP 0: Receive: WOLFIE - Send: EIFLOW */
			} else if(step == 0) {
				step++;
				if(strcmp(verb, "WOLFIE") == 0) {
					safe_send(&T_lock, stdout, new_user.socket, "EIFLOW", 0, VFLAG);
				} else {
					safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
					safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
					step = -1;
				}
			/* STEP 1: Receive IAM <name> or IAMNEW <name> - Login validation process */
			} else if(step == 1) {
				if((verb[0] == 'I') && (verb[1] == 'A') && (verb[2] == 'M') && 
				(verb[3] == ' ') && (verb[4] != ' ')) {
					strcpy(new_user.name, verb + 4);
					/* Login Existing Account Request */
					switch(verify_account(new_user.name)) {
						/* 0: Account doesn't exist */
						case 0:	
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "01 USER NOT AVAILABLE", VFLAG);								
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
						/* 1: Account exists */
						case 1:
							x = verify_user(new_user.name);
							if(x < 0) {
								safe_send(&T_lock, stdout, new_user.socket, "ERR", "00 USER NAME TAKEN", VFLAG);
								safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
								step = -1;
							}
							else {
								step = 3;						
								safe_send(&T_lock, stdout, new_user.socket, "AUTH", new_user.name, VFLAG);;
							}
							break;
						default:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
						}
				} else if((verb[0] == 'I') && (verb[1] == 'A') && (verb[2] == 'M') && 
				(verb[3] == 'N') && (verb[4] == 'E') && (verb[5] == 'W') && 
				(verb[6] == ' ') && (verb[7] != ' ')) {
					strcpy(new_user.name, verb + 7);
					/* New Account Request */
					switch(verify_account(new_user.name)) {
						/* 0: Account doesn't exist */
						case 0:	
							safe_send(&T_lock, stdout, new_user.socket, "HINEW", new_user.name, VFLAG);
							step = 2;
							break;
						/* 1: Account exists */
						case 1:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "00 USER NAME TAKEN", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
						default:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
						}			
				} else {
					safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
					safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
					step = -1;
				}
			/* STEP 2: Only NEWPASS <password> is acceptable */
			} else if(step == 2) {
				if((verb[0] == 'N') && (verb[1] == 'E') && (verb[2] == 'W') && 
				(verb[3] == 'P') && (verb[4] == 'A') && (verb[5] == 'S') && 
				(verb[6] == 'S') && (verb[7] == ' ') && (verb[8] != ' ')) {
					strcpy(pass, verb + 8);
					switch(valid_password(pass)) {
						/* -1: Invalid Password */
						case -1:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "02 BAD PASSWORD", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
						/* 1: Valid Password */
						case 1:
							safe_send(&T_lock, stdout, new_user.socket, "SSAPWEN", 0, VFLAG);
							if(add_account(new_user.name, pass) < 0) {
								safe_send(&T_lock, stdout, new_user.socket, "ERR", "00 USER NAME TAKEN", VFLAG);
								safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
								step = -1;
								break;
							}
							if(add_user(new_user) < 0) {
								safe_send(&T_lock, stdout, new_user.socket, "ERR", "00 USER NAME TAKEN", VFLAG);
								safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
								step = -1;
								break;
							}
							safe_send(&T_lock, stdout, new_user.socket, "HI", new_user.name, VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "MOTD", MOTD, VFLAG);
							step = 4;
							break;
						default:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
					}
				} else {
					safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
					safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
					step = -1;
				}
			/* STEP 3: Only PASS <password> is acceptable */
			} else if(step == 3) {
				if((verb[0] == 'P') && (verb[1] == 'A') && (verb[2] == 'S') && 
				(verb[3] == 'S') && (verb[4] == ' ') && (verb[5] != ' ')) {
					strcpy(pass, verb + 5);
					switch(verify_password(new_user.name, pass)) {
						/* 0: Wrong Password */
						case -1:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "02 BAD PASSWORD", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							break;
						case 1:
							safe_send(&T_lock, stdout, new_user.socket, "SSAP", 0, VFLAG);
							if(add_user(new_user) < 0) {
								safe_send(&T_lock, stdout, new_user.socket, "ERR", "00 USER NAME TAKEN", VFLAG);
								safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
								step = -1;
								break;
							}
							safe_send(&T_lock, stdout, new_user.socket, "HI", new_user.name, VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "MOTD", MOTD, VFLAG);
							step = 4;
							break;
						default:
							safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
							safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
							step = -1;
							break;
					}
				} else {
					safe_send(&T_lock, stdout, new_user.socket, "ERR", "100 INTERNAL SERVER ERROR", VFLAG);
					safe_send(&T_lock, stdout, new_user.socket, "BYE", 0, VFLAG);
					step = -1;
				}
			} 
		}
	}
	return NULL;
}

int open_server(char *port) {
	int accept_sock, status, yes;
	struct addrinfo hints, *info;

	yes = 1;
	/* determines some traits of accept_info */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	/* populating addrinfo struct for call to socket(), IP/port inserted here */ 
	if((status = getaddrinfo(NULL, port, &hints, &info)) != 0) {
		sfwrite(&T_lock, stderr, "\e[1;31mgetaddrinfo error: %s\e[m\n", gai_strerror(status));
		return -1;
	}

	/* creating a socket by referencing the addrinfo struct previously created */
	if((accept_sock = socket(info->ai_family, info->ai_socktype, info->ai_protocol)) < 0) {
		perr(&T_lock, stderr, "socket");
		return -1;
	}

	/* so the kernel stops stealing our bind port */
	if (setsockopt(accept_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
    	perr(&T_lock, stderr, "setsockopt");
    	return -1;
	}

	/* binding the socket to the address */
	if(bind(accept_sock, info->ai_addr, info->ai_addrlen) < 0) {
		perr(&T_lock, stderr, "bind");
		return -1;
	}

	/* setting accept socket to listen for connect requests */
	if(listen(accept_sock, 128) < 0) {
		perr(&T_lock, stderr, "listen");
		return -1;
	}
	freeaddrinfo(info);
	return accept_sock;
}

/* server commands: /users, /accts, /help, /shutdown */

/* return -1 on error. 1 on success */
int cmd_accts() {
	char *stmt;
	int count, ret;
	char name[65];
	char pass[65];
	char salt[65];
	sqlite3_stmt* step;

	step = NULL;
	count = 0;
	pthread_mutex_lock(&A_lock);
	stmt = "SELECT COUNT(*) FROM ACCOUNTS";
	if(sqlite3_prepare_v2(ACCOUNTS, stmt, -1, &step, 0) != SQLITE_OK) {
		db_err();
		pthread_mutex_unlock(&A_lock);
		return -1;
	}
	if((ret = sqlite3_step(step)) == SQLITE_ROW) {
		count = sqlite3_column_int(step, 0);
	} else if(ret == SQLITE_ERROR) {
		db_err();
		pthread_mutex_unlock(&A_lock);
		return -1;
	}
	if(!count) {
		sfwrite(&T_lock, stdout, "No user account information is currently available.\n");
		pthread_mutex_unlock(&A_lock);
		return 1;
	}
	else {
		if(sqlite3_finalize(step) == SQLITE_ERROR) {
			db_err();
			pthread_mutex_unlock(&A_lock);
			return -1;
		}
		stmt = "SELECT * FROM ACCOUNTS"; 
		step = NULL;
		pthread_mutex_lock(&T_lock);
		sfwrite(&T_lock, stdout, "\n|-------------------------USER ACCOUNT INFORMATION-------------------------|\n");
		if(sqlite3_prepare_v2(ACCOUNTS, stmt, -1, &step, 0) != SQLITE_OK) {
			db_err();
			pthread_mutex_unlock(&A_lock);
			return -1;
		}
		while((sqlite3_step(step) == SQLITE_ROW)) {
			strcpy(name, (char*)sqlite3_column_text(step, 0));
			strcpy(pass, (char*)sqlite3_column_text(step, 1));
			strcpy(salt, (char*)sqlite3_column_text(step, 2));
			sfwrite(&T_lock, stdout, "| Name: %-67s|\n", name);
			sfwrite(&T_lock, stdout, "| Pass: %s   |\n", pass);
			sfwrite(&T_lock, stdout, "| Salt: %s |\n", salt);
			sfwrite(&T_lock, stdout, "|--------------------------------------------------------------------------|\n");
		}
		sfwrite(&T_lock, stdout, "\n");
		pthread_mutex_unlock(&T_lock);
		pthread_mutex_unlock(&A_lock);
		sqlite3_finalize(step);		
		return 1;
	}
	
}

/* dumps a list of currently logged in users to stdout */
void cmd_users() {
	struct user *u;
	char timez[128];
	char *nl;	
	if(USERS.next) { 	
		pthread_mutex_lock(&U_lock);	
		u = USERS.next;
		pthread_mutex_lock(&T_lock);
		sfwrite(&T_lock, stdout, "                        CURRENTLY LOGGED IN USERS                       \n");
		sfwrite(&T_lock, stdout, "------------------------------------------------------------------------\n");
		sfwrite(&T_lock, stdout, "|      NAME     |        LOGIN TIME        |    IP ADDRESS    | SOCKET |\n");	
		while(u) {
			strcpy(timez, ctime(&u->log_time));
			nl = strchr(timez, '\n');
			*nl = '\0';
			sfwrite(&T_lock, stdout, "------------------------------------------------------------------------\n");
			sfwrite(&T_lock, stdout, "|%14s | %19s | %16s |   %3d  |\n", u->name, timez, u->ip, u->socket);
			u = u->next;
		}
		pthread_mutex_unlock(&U_lock);
		sfwrite(&T_lock, stdout, "------------------------------------------------------------------------\n\n");
		pthread_mutex_unlock(&T_lock);
	} else {
		sfwrite(&T_lock, stdout, "There are currently no users logged in.\n");
	}
}

/* lists all commands the server accepts and what they do */
void cmd_help() {
	sfwrite(&T_lock, stdout, "Help: Server Commands\n");
	sfwrite(&T_lock, stdout, "/accts     -Dumps a list of all user account information.\n");
	sfwrite(&T_lock, stdout, "/users        -Dumps a list of currently logged in users to stdout.\n");
	sfwrite(&T_lock, stdout, "/help         -Lists all commands the server accepts and what they do.\n");
	sfwrite(&T_lock, stdout, "/shutdown     -Cleanly disconnects all users, saves states, closes all\n");
	sfwrite(&T_lock, stdout, "               sockets and files, and frees any heap memory allocated.\n");
}

/* performs all necessary cleanup and properly shuts down the server */
void cmd_shutdown(int status) {
	pthread_mutex_lock(&U_lock);
	pthread_mutex_lock(&Q_lock);
	struct user *u, *n;
	struct login *l, *nl;
	u = USERS.next;
	/* freeing user list */
	if(u) {
		while(u) {
			safe_send(&T_lock, stdout, u->socket, "BYE", 0, VFLAG);
			n = u->next;
			close(u->socket);
			free(u);
			u = n;
		}
	}
	/* freeing login queue entries */
	l = LOGIN_Q.next;
	if(l) {
		while(l) {
			nl = l->next;
			close(l->socket);
			free(l);
			l = nl;
		}
	}
	close(ACCEPT_FD);
	sqlite3_close(ACCOUNTS);
	exit(status);
}

void prompt() {
	char *prompt;
	prompt = "AHHH NO NOT THE BEES \x1B[1;30m>\x1B[0;31m8\x1B[1;30m]\x1B[1;33m|\x1B[1;30m|\x1B[1;33m)\x1B[1;30m-\x1B[0mServer\x1B[1;30m>\x1B[0m ";
	sfwrite(&T_lock, stdout, prompt);
}

void command_handler() {
	char cmd[1024];
	memset(cmd, '\0', 1024);
	if(read(STDIN_FILENO, cmd, sizeof(cmd)) > 0 && (cmd[0] != '\n')) {
		if(strcmp(cmd, "/users\n") == 0)
			cmd_users();
		else if(strcmp(cmd, "/help\n") == 0)
			cmd_help();
		else if(strcmp(cmd, "/shutdown\n") == 0)
			cmd_shutdown(EXIT_SUCCESS);
		else if(strcmp(cmd, "/accts\n") == 0)
			cmd_accts();
		else {
			sfwrite(&T_lock, stderr, "Invalid cmd: %s\n", cmd);
		}
	}
	prompt();	
}

void sigint_handler(int sig) {
	cmd_shutdown(EXIT_FAILURE);
}

int main(int argc, char **argv) {
	int i, maxthreads, maxfd, client_sock, opt, sel;
	char *ptr, *port_number;
	pthread_attr_t comm_attr;
	fd_set readfds;
	socklen_t a_size;
	struct sockaddr_storage client_addr;
	struct timeval tv;
	struct sockaddr_in *client_in;

	/* HW 6 stuff */
	pthread_t tid;
	pthread_attr_t login_attr;
	pthread_attr_init(&login_attr);
	maxthreads = 2;
	sem_init(&items_sem, 0, 0);
	LOGIN_Q.next = NULL;
	USERS.next = NULL;
	pthread_mutexattr_t mutatt;
	pthread_mutexattr_init(&mutatt);
	pthread_mutexattr_settype(&mutatt, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&T_lock, &mutatt);
	pthread_mutex_init(&U_lock, &mutatt);
	pthread_mutex_init(&A_lock, &mutatt);
	/* end HW 6 stuffs */

	signal(SIGINT, sigint_handler);

	pthread_attr_init(&comm_attr);
	pthread_attr_setdetachstate(&comm_attr, PTHREAD_CREATE_DETACHED);

	while((opt = getopt(argc, argv, "hvt:")) != -1) {
        switch(opt) {
            case 'h':
                /* The help menu was selected */
                USAGE(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                /* Set verbose option */
                VFLAG = 1;
                break;
            case 't':
            	/* The number of threads used for the login queue */
            	maxthreads = (int)strtoul(optarg, &ptr, 10);
        		if((*ptr != '\0') || (maxthreads <= 0)) {
            		printredtext(&T_lock, stdout, "./server: -t option requires an integer greater than 0 as an argument.");
            		USAGE(argv[0]);
            		exit(EXIT_FAILURE);
            	}
            	break;
            case '?':
                /* Let this case fall down to default;
                 * handled during bad option.
                 */
            default:
                /* A bad option was provided. */
                USAGE(argv[0]);
                exit(EXIT_FAILURE);
                break;
        }
    }
    /* Get position arguments */
    if(optind < argc && (((argc - optind) == 2) || ((argc - optind) == 3))) {
    	/* setting up PORT_NUMBER and MOTD */
        port_number = argv[optind++];
		strcpy(MOTD, argv[optind++]);
		if((argc - optind) == 1) {
			init_accounts(argv[optind]);
		} else {
			init_accounts(NULL);
		}
    } else {
        if((argc - optind) <= 0) {
            sfwrite(&T_lock, stderr, "Missing PORT_NUMBER and MOTD.\n");
        } else if((argc - optind) == 1) {
            sfwrite(&T_lock, stderr, "Missing MOTD.\n");
        } else {
            sfwrite(&T_lock, stderr, "Too many arguments provided.\n");
        }
        USAGE(0[argv]);
        exit(EXIT_FAILURE);
    }

    /* need to be able to point to this when calling accept() */
	a_size = sizeof(client_addr);

	/* setting up the accept thread fd and binding it to an address and pport */
	if((ACCEPT_FD = open_server(port_number)) < 0)
		cmd_shutdown(EXIT_FAILURE);

	/* highest fd for looping */
	maxfd = ACCEPT_FD;

	/* spawning login threads */
	for(i = 0;i < maxthreads;i++) {
		if(pthread_create(&tid, &login_attr, &start_login_thread, NULL) == 0) {
			pthread_setname_np(tid, "LOGIN");
			pthread_detach(tid);
		} else {
			perr(&T_lock, stderr, "pthread_create");
			cmd_shutdown(EXIT_FAILURE);
		}
	}
	sfwrite(&T_lock, stdout, "Currently listening on port %s.\n", port_number);
	/* printing a prompt on the server terminal*/
	prompt();

	while(1) { 
		/* emptying fdfds */
		FD_ZERO(&readfds);

		/* setting a timeout so we can spawn comm threads from main */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* setting readfds*/
		FD_SET(ACCEPT_FD, &readfds);
		FD_SET(STDIN_FILENO, &readfds);

		/* spawning comm thread if necessary */
		if(USERS.next && !COMM_THREAD) {
			if(pthread_create(&tid, &comm_attr, &spawn_comm_thread, NULL) != 0) {
				perr(&T_lock, stderr, "pthread");
				cmd_shutdown(EXIT_FAILURE);
			}
			else {
				pthread_setname_np(tid, "COMM");
				pthread_detach(tid);
				COMM_THREAD = 1;
			}
		}

		/* waiting for input */
		if((sel = select((maxfd + 1), &readfds, NULL, NULL, &tv)) < 0) {
			perr(&T_lock, stderr, "select ACCEPT");
			cmd_shutdown(EXIT_FAILURE);
		} else if (sel == 0) {
			/* timeout - do nothing */
		} else {
			/* input on stdin */
			if(FD_ISSET(STDIN_FILENO, &readfds)) {
				command_handler(ACCEPT_FD);
			/* incoming connection request */
			} else {
				if((client_sock = accept(ACCEPT_FD, (struct sockaddr*) &client_addr, &a_size)) < 0) {
					perr(&T_lock, stderr, "accept");
				/* connection accepted. add login to queue */
				} else {
					/* HW 6 - INSERT REQUEST INTO LOGIN QUEUE */
					client_in = (struct sockaddr_in*)&client_addr;
					login_request(client_sock, inet_ntoa(client_in->sin_addr));
				}
			}
		}
	}
	return EXIT_SUCCESS;
}