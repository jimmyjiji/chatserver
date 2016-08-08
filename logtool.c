#include "logtool.h"

/* global variable to hold the file descriptor referring to the audit log file */
FILE* ASTREAM;
/* global struct that holds all the text in the audit log */
data D;

void cleanup() {
	fclose(ASTREAM);
}

void init_data() {
	size_t len = 0;
	ssize_t read;

	ASTREAM = fopen("audit.log", "r");

	if(ASTREAM == NULL) {
		perror("fopen");
		exit(EXIT_FAILURE);
	}

	D.count = 0;
	while((read = getline(&D.line[D.count], &len, ASTREAM)) != -1) {
		D.count++;
	}
}

int sort_date_asc(const void *x, const void *y) {
	const char **xi, **yi;
	xi = (const char **)x;
	yi = (const char **)y;
	return strcmp(*xi, *yi);
}

int sort_date_desc(const void *x, const void *y) {
	const char **xi, **yi;
	xi = (const char **)x;
	yi = (const char **)y;
	return (-1 * strcmp(*xi, *yi));
}

int sort_name_asc(const void *x, const void *y) {
	const char **xi, **yi, *xn, *yn;
	xi = (const char **)x;
	yi = (const char **)y;
	xn = strchr(*xi, ',');
	xn+= 2;
	yn = strchr(*yi, ',');
	yn+= 2;
	return strcmp(xn, yn);
}

int sort_name_desc(const void *x, const void *y) {
	const char **xi, **yi, *xn, *yn;
	xi = (const char **)x;
	yi = (const char **)y;
	xn = strchr(*xi, ',');
	xn+= 2;
	yn = strchr(*yi, ',');
	yn+= 2;
	return (-1 * strcmp(xn, yn));
}

int sort_event_asc(const void *x, const void *y) {
	const char **xi, **yi, *xn, *yn;
	xi = (const char **)x;
	yi = (const char **)y;
	xn = strchr(*xi, ',');
	xn = strchr(xn, ',');
	xn+= 2;
	yn = strchr(*yi, ',');
	yn = strchr(yn, ',');
	yn+= 2;
	return strcmp(xn, yn);
}

int sort_event_desc(const void *x, const void *y) {
	const char **xi, **yi, *xn, *yn;
	xi = (const char **)x;
	yi = (const char **)y;
	xn = strchr(*xi, ',');
	xn = strchr(xn, ',');
	xn+= 2;
	yn = strchr(*yi, ',');
	yn = strchr(yn, ',');
	yn+= 2;
	return (-1 * strcmp(xn, yn));
}

/* temp */
void update_data() {
	cleanup();
	init_data();
}

/* commands begin */

void sort_by_column() { 
	/* copy over data */
	char *dat[20000];
	int i;
	size_t len;
	for(i = 0;i <= D.count;i++) {
		dat[i] = malloc(strlen(D.line[i]));
		strcpy(dat[i], D.line[i]);
	}
	len = D.count;	
	qsort(dat, len, sizeof(char *), sort_name_asc);
	for(i = 0;i <= D.count;i++) {
		printf("%s", dat[i]);
	}
}

void exit_tool() {
	cleanup();
	exit(EXIT_SUCCESS);	
}

bool date_during(bool diff[]) {
	for (int i = 0; i < 5; i++) {
		if (diff[i] == true){
			return true;
		}
	}
	return false;
}

date* obtain_date(int index) {
	date* currentdate = malloc(24);
	char* auditline = D.line[index];	
	char buf[17];

	for (int i = 0; auditline[i] != ',' && i < 17; i++) {
		buf[i] = auditline[i];
	}
	
	//printf("Date Obtained: %s\n", buf);
   	sscanf(buf, "%d/%d/%d-%d:%d %s", &currentdate->month, &currentdate->day, &currentdate->year, &currentdate->hour, &currentdate->minute, currentdate->am_or_pm);

	return currentdate;
}

void filterdate() {
	int error;

	printf("%s\n", "Enter a date and time to start filter in mm/dd/yy 00:00 AM/PM Format ");
	date startdate;
	char am_or_pm_start[2];
	error = scanf("%d/%d/%d %d:%d %s", &startdate.month, &startdate.day, &startdate.year, &startdate.hour, &startdate.minute, am_or_pm_start);
	if (error != 6) {
		perror("Incorrect format entered");
		return;
	}

	printf("%s\n", "Enter a date and time to end filter in mm/dd/yy 00:00 AM/PM Format");
	date enddate;
	char am_or_pm_end[2];
	error = scanf("%d/%d/%d %d:%d %s", &enddate.month, &enddate.day, &enddate.year, &enddate.hour, &enddate.minute, am_or_pm_end);

	if (error != 6) {
		perror("Incorrect format entered");
		return;
	}

	bool diff[5] = {false};
	/*
	diff[0] is if year is different
	diff[1] is if month is different
	diff[2] is if day is different
	diff[3] is if hour is different
	diff[4] is if minute is different
	diff[5] is if am/pm is different 
	*/

	if (startdate.month != enddate.month)
		diff[MONTH] = true;
	if (startdate.day != enddate.day)
		diff[DAY] = true;
	if (startdate.year != enddate.year)
		diff[YEAR] = true;
	if (startdate.hour != enddate.hour)
		diff[HOUR] = true;
	if (startdate.minute != enddate.minute)
		diff[MINUTE] = true;


	for (int i = 0; D.line[i] != NULL; i++) {
		date* currentdate = obtain_date(i);
		if (currentdate->year > enddate.year)
			diff[YEAR] = false;
		if (currentdate->month > enddate.month)
			diff[MONTH] = false;
		if (currentdate -> day > enddate.day)
			diff[DAY] = false;
		if (currentdate->hour > enddate.hour && strcmp(am_or_pm_start, currentdate->am_or_pm) == 0)
			diff[HOUR] = false;
		if (currentdate-> minute > enddate.minute && strcmp(am_or_pm_start, currentdate->am_or_pm) == 0)
			diff[MINUTE] = false;

		if (!date_during(diff)) {
			break;
		} else {
			printf("%s", D.line[i]);
		}
		//free(currentdate);
	}
	
}

void findString(char* prompt, bool ifprompt, char* withoutprompt) {
	bool found = false;
	if (ifprompt) {
		printf("%s\n", prompt);	
		char toFind[100];
		scanf("%s", toFind);

		for(int i = 0; D.line[i] != NULL; i++) {
			if(strstr(D.line[i], toFind) != NULL) {
					found = true;
					printf("%s", D.line[i]);
			}
		}
	} else {
		for(int i = 0; D.line[i] != NULL; i++) {
			if(strstr(D.line[i], withoutprompt) != NULL) {
					printf("%s", D.line[i]);
					found = true;
			}
		}
	}
	if (!found) {
		printf("%s\n", "Nothing was found in this field");
	}
}

void filterstring() {
	printf("%s\n", "Enter a field to filter");
	printf("%s\n", "------------------------");
	printf("%s\n", "1) Find a Username");
	printf("%s\n", "2) Find a Command");
	printf("%s\n", "3) Successful Commands");
	printf("%s\n", "4) Unsuccessful Commands");
	printf("%s\n", "5) Login or Logouts");
	printf("%s\n", "6) Errors");
	int filteroption;
	if ((scanf("%d", &filteroption)) < 0) {
		perror("Invalid String");
		return;
	} else {
		switch(filteroption) {
			case 1: 
				findString("Enter a Username:", true, "");
				break;
			case 2:
				findString("Enter a Command:", true, "");
				break;
			case 3:
				findString("", false, "success");
				break;
			case 4:
				findString("", false, "failure");
				break;
			case 5:
				findString("", false, "LOGIN");
				findString("", false, "LOGOUT");
				break;
			case 6:
				findString("", false, "error");
				findString("", false, "ERR");
				break;
			default:
				printf("%s\n", "Invalid Command");
				return;
		}
	}

}

void searchkeyword() {
	printf("%s\n", "Print a keyword you'd like to find:");
	char keyword[100];
	scanf("%s", keyword);
	char* green = "\e[1;32m";
	char* end = "\e[m";

	for(int i = 0; D.line[i] != NULL; i++) {
		char* substring = strstr(D.line[i], keyword);
		if (substring!= NULL) {
			int position = substring - D.line[i];
			write(STDOUT_FILENO, D.line[i], position);
			write(STDOUT_FILENO, green, strlen(green));
			write(STDOUT_FILENO, keyword, strlen(keyword));
			write(STDOUT_FILENO, end, strlen(end));
			D.line[i]+= position + strlen(keyword);
			printf("%s", D.line[i]);
			D.line[i]-= position+strlen(keyword);
		} 
	}
}

/* compare *cmd to determine command and then call the corresponding function */
void command_handler(int cmd) {
	if (cmd) {
		switch (cmd) {
			case 1: sort_by_column(); break;
			case 2: filterdate(); break;
			case 3: filterstring(); break;
			case 4: searchkeyword(); break;
			case 5: exit_tool(); break;
			default: printf("Invalid command\n");
		}
	}
	
}



void menu() {
	printf("\nAudit Log Monitoring Tool\n");
	printf("1) Sort by Column\n");
	printf("2) Filter by Date\n");
	printf("3) Filter by Field\n");
	printf("4) Search for Keyword\n");
	printf("5) Exit\n\n");
}

int main(int argc, char **argv) {
	char *prompt = ">";
	init_data();
	while(1) {
		menu();
		printf("%s", prompt);
		fflush(stdout);
		int cmd;
		scanf("%d", &cmd);
		command_handler(cmd);
	}	
	menu();

	int inotifyFd;
    inotifyFd = inotify_init();                 /* Create inotify instance */
  	inotify_add_watch(inotifyFd, "audit.log", IN_ALL_EVENTS);
    

    struct pollfd fds[2];
    fds[0].fd = STDIN_FILENO;
    fds[1].fd = inotifyFd;
    fds[0].events = POLLIN;
    fds[1].events = POLLIN;

	while (1) {
		if (poll(fds, 2, -1) < 0) {
			break;
			perror("error in poll");
		}
		for (int i = 0; i < 2; i++) {
			if (fds[i].revents & POLLIN) {
       			if (fds[i].fd == STDIN_FILENO) {
       				char cmdstring;
					read(STDIN_FILENO, &cmdstring, 1);
					int cmd = cmdstring - '0';
       				command_handler(cmd);
       				menu();
       				break;
       			} else if (fds[i].fd == inotifyFd) {
       				char buf[10000];
       				if (read(inotifyFd, buf, 10000) > 0)
			        	update_data();
			        break;
       			}
        	} 
		}
	}
}