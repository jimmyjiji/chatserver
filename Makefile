CC = gcc -g
CFLAGS = -Wall -Werror
LIBRARIES = -l:libsqlite3.a -lpthread -ldl -lcrypto

all: client server chat logtool

client: client.c
	$(CC) $(CFLAGS) -g -o client client.c io.c sfwrite.c

server: server.c
	$(CC) $(CFLAGS) -pthread -D_GNU_SOURCE -g -o server server.c io.c sfwrite.c $(LIBRARIES)

chat: chat.c
	$(CC) $(CFLAGS) -g -o chat chat.c io.c sfwrite.c

logtool: logtool.c
	$(CC) $(CFLAGS) -g -o logtool logtool.c

clean:
	rm -f *~ *.o client server chat logtool