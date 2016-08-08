#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <limits.h>
#include <poll.h>
#include <errno.h>

#define MONTH 1
#define DAY 2
#define YEAR 0
#define HOUR 3
#define MINUTE 4


typedef struct data {
	char *line[20000];
	int count;
} data;

typedef struct date {
	int month;
	int day;
	int year;
	int hour;
	int minute;
	char am_or_pm[2];
} date;



