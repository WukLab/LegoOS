#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define PORT	12345

void error(char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char *argv[])
{
	int sockfd, portno, n;
	char buffer[256] = "message: hello";
	char *host = "127.0.0.1\0";
	struct sockaddr_in serv_addr;
	struct hostent *server;
	
	if (argc < 2) {
		fprintf(stderr,"usage %s hostname\n", argv[0]);
		exit(0);
	}

	portno = PORT;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
		error("ERROR opening socket");

	server = gethostbyname(argv[1]);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}

      	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	//bcopy(host, (char *)&serv_addr.sin_addr.s_addr, strlen(host));
	serv_addr.sin_port = htons(portno);
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
	    error("ERROR connecting");

	n = write(sockfd,buffer,strlen(buffer));
	if (n < 0) 
	     error("ERROR writing to socket");

	bzero(buffer,256);
	n = read(sockfd,buffer,255);
	if (n < 0) 
	     error("ERROR reading from socket");

	printf("%s\n",buffer);

	return 0;
}
