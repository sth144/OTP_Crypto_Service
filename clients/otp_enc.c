/***************************************************************************************************
 *	Title: One-Time-Pad Encryption Client
 *	Author: Sean Hinds
 *	Date: 03/14/18
 *	Description: Client program which requests encryption service from the server. Uses 
 *			Berkeley sockets API to send plaintext and key to server, and outputs server
 *			response to stdout.
 * ************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <sys/ioctl.h>

void error(const char *msg) { perror(msg); exit(0); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[262144];
	char tempbuffer[262144];
	/* define allowed plaintext characters */
	char* charoptions = " ABCDEFGHIJKLMNOPQRSTUVWXYZ";    

	if (argc < 3) { fprintf(stderr,"USAGE: %s hostname port\n", argv[0]); exit(0); } // Check usage & args

	// Set up the server address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[3]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverHostInfo = gethostbyname("localhost"); // Convert the machine name into a special form of address
	if (serverHostInfo == NULL) { fprintf(stderr, "CLIENT: ERROR, no such host\n"); exit(0); }

	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr_list[0], serverHostInfo->h_length); // Copy in the address

	// Set up the socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (socketFD < 0) error("CLIENT: ERROR opening socket");
	
	// Connect to server
	if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to address
		error("CLIENT: ERROR connecting");

	/* set up fd_set for calls to select() */
	fd_set readFDs;
	struct timeval idle;
	int ret;
	FD_ZERO(&readFDs);
	FD_SET(socketFD, &readFDs);
	/* select() will pause for up to 30 seconds waiting for data */
	idle.tv_sec = 30;
	idle.tv_usec = 0;

	// Send handshake message to the server
	memset(buffer, '\0', sizeof(buffer));
	strcpy(buffer, "encodeProc@@");
	charsWritten = send(socketFD, buffer, strlen(buffer), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	int checkSend = -5;
	do {
		ioctl(socketFD, TIOCOUTQ, &checkSend);
	} while (checkSend > 0);

	// Process handshake response
	memset(buffer, '\0', sizeof(buffer));
	ret = 0;
	while (!ret && (strstr(buffer, "@@") == NULL)) {
		ret = select(socketFD + 1, &readFDs, NULL, NULL, &idle); 
		if (ret) {
			charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0); // Read data from the socket, leaving \0 at end
			if (charsRead < 0) error("CLIENT: ERROR reading from socket");
		}
	}
	if (strstr(buffer, "abort")) { error("CLIENT: tried to connect to wrong server daemon, instructed to abort"); exit(2); }

	/* open plaintext filestream, import data, and send plaintext to the server */
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array

	FILE* plainfile = fopen(argv[1], "r");

	fgets(buffer, sizeof(buffer) - 1, plainfile); // Get input from the user, trunc to buffer - 1 chars, leaving \0
	buffer[strcspn(buffer, "\n")] = '\0'; // Remove the trailing \n that fgets adds
	strcat(buffer, "@@\0");
	//printf("CLIENT: sending this plaintext to the server: \"%s\"\n", buffer); fflush(stdout);
	int plaintextlen = strlen(buffer), goodChar;
	for (int i = 0; i < plaintextlen - 2; i++) {
		goodChar = 0;
		for (int j = 0; j < strlen(charoptions); j++) {
			if (buffer[i] == charoptions[j]) { goodChar++; }		// plaintext[i] is an allowed character
		}
		if (!goodChar) { perror("CLIENT: bad input received\n"); exit(1); }
	}

	// Send message to server
	charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	checkSend = -5;	// Holds amount of bytes remaining in send buffer
	do {
		ioctl(socketFD, TIOCOUTQ, &checkSend);	// Check the send buffer for this socket
		//printf("checkSend: %d\n", checkSend);	// check remaining bytes;
	} while (checkSend > 0);	// loop until send buffer for socket is empty
	//if (checkSend < 0) error("ioctl error");	// Check if we actually stopped loop because of error
	
	/* close plaintext filestream */
	fclose(plainfile);

	/* open key filestream, import data, send key to the server */
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array

	FILE* keyfile = fopen(argv[2], "r");

	fgets(buffer, sizeof(buffer) - 1, keyfile); // Get input from the user, trunc to buffer - 1 chars, leaving \0
	buffer[strcspn(buffer, "\n")] = '\0'; // Remove the trailing \n that fgets adds
	strcat(buffer, "@@\0");
	if (strlen(buffer) < plaintextlen) { perror("CLIENT: key too short to encode plaintext"); exit(1); }

	//printf("CLIENT: sending this key to the server: \"%s\"\n", buffer); fflush(stdout);
	//printf("CLIENT: sending key\n"); fflush(stdout);	

	charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	checkSend = -5;	// Holds amount of bytes remaining in send buffer
	do {
		ioctl(socketFD, TIOCOUTQ, &checkSend);	// Check the send buffer for this socket
		//printf("checkSend: %d\n", checkSend);	// check remaining bytes;
	} while (checkSend > 0);	// loop until send buffer for socket is empty
	//if (checkSend < 0) error("ioctl error");	// Check if we actually stopped loop because of error
	
	fclose(keyfile);

	// Get return message from server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer again for reuse
	memset(tempbuffer, '\0', sizeof(tempbuffer));
	ret = 0;
	while (!ret || (strstr(buffer, "@@") == NULL)) {
		//printf("CLIENT: waiting for server response\n"); fflush(stdout);
		ret = select(socketFD + 1, &readFDs, NULL, NULL, &idle); 
		if (ret) {
			//printf("CLIENT: response text available\n"); fflush(stdout);
			charsRead = recv(socketFD, tempbuffer, sizeof(tempbuffer) - 1, 0); // Read data from the socket, leaving \0 at end
			if (charsRead < 0) error("CLIENT: ERROR reading from socket");
			strcat(buffer, tempbuffer);
			//printf("\n\nCLIENT: charsread %d received some text, put this in the temp buffer: %s\n", charsRead, tempbuffer); fflush(stdout);
			memset(tempbuffer, '\0', sizeof(tempbuffer));
		}
	}
	buffer[strcspn(buffer, "@@\0")] = '\0'; 
	
	//printf("CLIENT done. Here's the message: %s\n", buffer); fflush(stdout);
	printf("%s\n", buffer); 	

	close(socketFD); // Close the socket
	return 0;
}
