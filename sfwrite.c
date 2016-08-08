#include "sfwrite.h"

extern void sfwrite(pthread_mutex_t *lock, FILE* stream, char *fmt, ...) {
	va_list ap;

	/* grabbing mutex (or waiting until it is unlocked) */
	if(pthread_mutex_lock(lock) < 0) {
		perror("pthread_mutex_lock");
		return;
	}
	/* holding mutex. do stuff */

	/* creating argument list and printing */
	va_start(ap, fmt);
	vfprintf(stream, fmt, ap);
	va_end(ap);
	fflush(stream);

	/* unlocking mutex for other writers */
	if(pthread_mutex_unlock(lock) < 0) {
		perror("pthread_mutex_unlock");
		return;
	}	
}