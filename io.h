#ifndef IO_H
#define IO_H

extern ssize_t safe_recv(pthread_mutex_t *lock, FILE* term, int socket, char *buf, int vflag);
extern ssize_t safe_send(pthread_mutex_t *lock, FILE* term, int socket, char *verb, char *msg, int vflag);
extern void printredtext(pthread_mutex_t *lock, FILE* term, char *string);
extern void printgreentext(pthread_mutex_t *lock, FILE* term, char *string);
extern void perr(pthread_mutex_t *lock, FILE* term, char *func);

#endif /* IO_H */