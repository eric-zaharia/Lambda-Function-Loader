#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

#define PORT 6969

int create_socket()
{
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        return sock;
}

int connect_socket(int fd)
{
		
		struct sockaddr_un addr;
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, SOCKET_NAME);

		int connection = connect(fd, (struct sockaddr*)&addr, sizeof(addr));

		return connection;
		
}

int bind_socket(int fd) {
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SOCKET_NAME);

	int binded = bind(fd, (struct sockaddr*)&addr, sizeof(addr));

	return binded;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
        int sent = send(fd, buf, len, 0);
        return sent;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
        int bytes = recv(fd, buf, len, 0);

        return bytes;
}

void close_socket(int fd)
{	
	shutdown(fd, SHUT_RDWR);
	close(fd);
}
