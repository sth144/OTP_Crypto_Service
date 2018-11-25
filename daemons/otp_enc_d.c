/***********************************************************************************************************
 *	Title: One-Time-Pad Encryption Daemon
 *	Author: Sean Hinds
 *	Date: 03/14/18
 *	Description: Server program for one-time-pad encryption. Runs in the background in an infinite loop
 *			and can accept up to 5 concurrent encryption requests through the Berkeley Sockets
 *			API.
 * ********************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char *argv[])
{
	int listenSocketFD, establishedConnectionFD, portNumber, charsRead, handShakeLength = 12;
	socklen_t sizeOfClientInfo;
	char* charoptions = " ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char buffer[262144];
	char tempbuffer[262144];
	char plaintext[262144];
	char key[262144];
	char ciphertext[262144];
	struct sockaddr_in serverAddress, clientAddress;

	if (argc < 2) { fprintf(stderr,"USAGE: %s port\n", argv[0]); exit(1); } // Check usage & args

	// Set up the address struct for this process (the server)
	memset((char *)&serverAddress, '\0', sizeof(serverAddress)); // Clear out the address struct
	portNumber = atoi(argv[1]); // Get the port number, convert to an integer from a string
	serverAddress.sin_family = AF_INET; // Create a network-capable socket
	serverAddress.sin_port = htons(portNumber); // Store the port number
	serverAddress.sin_addr.s_addr = INADDR_ANY; // Any address is allowed for connection to this process

	// Set up the socket
	listenSocketFD = socket(AF_INET, SOCK_STREAM, 0); // Create the socket
	if (listenSocketFD < 0) error("ERROR opening socket");

	// Enable the socket to begin listening
	if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) // Connect socket to port
		error("ERROR on binding");
	listen(listenSocketFD, 5); // Flip the socket on - it can now receive up to 5 connections

	/* infinite loop to handle requests. Forks a new process for each request */
	while (1) {
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("ERROR on accept");

		/* set up fd_sets for calls to select() */
        	fd_set readFDs, writeFDs;
        	struct timeval idle;
        	int ret;
        	FD_ZERO(&readFDs); FD_ZERO(&writeFDs);
        	FD_SET(establishedConnectionFD, &readFDs);
		FD_SET(establishedConnectionFD, &writeFDs);
		/* select() will idle for 30 seconds waiting for data */
        	idle.tv_sec = 30;
        	idle.tv_usec = 0;

		/* fork a new process, stat will be used to track child process in the parent */
		int wPid = fork();
		int stat;
		if (establishedConnectionFD >= 0 && !wPid) {
	
			// Handshake protocol. Abort if request comes from program other than otp_enc
			charsRead = sizeof(buffer);
			memset(buffer, '\0', sizeof(buffer));
			memset(tempbuffer, '\0', sizeof(tempbuffer));
			ret = 0;
			while (!ret && (strstr(buffer, "@@") == NULL)) {			// listen for input, ending in @@
				ret = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &idle);
				if (ret) {
					charsRead = recv(establishedConnectionFD, tempbuffer, handShakeLength, 0);
					if (charsRead < 0) error("ERROR reading from socket");
					strcat(buffer, tempbuffer);
					memset(tempbuffer, '\0', sizeof(tempbuffer));
				}
			}
			if (strstr(buffer, "encodeProc") == NULL) {				// request comes from program that is not otp_enc
				perror("SERVER: Wrong client process type (expected otp_enc)");
				memset(buffer, '\0', sizeof(buffer));
				strcpy(buffer, "abort@@");
				/* send a message to client telling it to terminate itself */
				send(establishedConnectionFD, buffer, sizeof(buffer), 0);
				exit(1);
			} else {									// accept the connection
				//printf("SERVER: accepted connection %s\n", buffer); fflush(stdout);
				memset(buffer, '\0', sizeof(buffer));
				strcpy(buffer, "proceed@@");
				send(establishedConnectionFD, buffer, sizeof(buffer), 0);
			}

			// Get the message from the client and display it
			charsRead = sizeof(buffer);		// Read the client's message from the socket
			memset(buffer, '\0', sizeof(buffer));
			memset(tempbuffer, '\0', sizeof(tempbuffer));
			ret = 0;
			while (!ret || (strstr(buffer, "@@") == NULL)) {			// listen for input, ending in @@
				ret = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &idle);
				if (ret) {
					charsRead = recv(establishedConnectionFD, tempbuffer, sizeof(tempbuffer), 0);
					if (charsRead < 0) error("ERROR reading from socket");
					strcat(buffer, tempbuffer);
					//printf("charsRead %d\n", charsRead);
					memset(tempbuffer, '\0', sizeof(tempbuffer));
				}
			} 	
			//printf("SERVER: I received this plaintext from the client: \"%s\"\n", buffer); fflush(stdout);
			memset(plaintext, '\0', sizeof(plaintext));
			strcpy(plaintext, buffer);
			plaintext[strcspn(plaintext, "@@")] = '\0';

			// Get the key from the client
			charsRead = sizeof(buffer);		// Read the client's message from the socket
			memset(buffer, '\0', sizeof(buffer));
			memset(tempbuffer, '\0', sizeof(tempbuffer));
			ret = 0;
			while (!ret || (strstr(buffer, "@@") == NULL)) {
				ret = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &idle);
				if (ret) {
					charsRead = recv(establishedConnectionFD, tempbuffer, sizeof(tempbuffer), 0);
					if (charsRead < 0) error("ERROR reading from socket");
					//printf("charsRead %d\n", charsRead);
					strcat(buffer, tempbuffer);
					memset(tempbuffer, '\0', sizeof(tempbuffer));
				}
			} //while (ret);
			//printf("SERVER: I received this key from the client: \"%s\"\n", buffer); fflush(stdout);
			//printf("SERVER: key received\n"); fflush(stdout);
			memset(key, '\0', sizeof(key));
			strcpy(key, buffer);
			key[strcspn(key, "@@")] = '\0';	

			/* process data */
			memset(ciphertext, '\0', sizeof(ciphertext));
			int plaintextletter, keyletter;
			/* iterate through each char in plaintext */
			for (int i = 0; i < strlen(plaintext); i++) {
				/* iterate through each char option */
				for (int j = 0; j < strlen(charoptions); j++) {
					/* identify indices of plaintext and key letters being examined */
					if (charoptions[j] == plaintext[i]) {plaintextletter = j;}
					if (charoptions[j] == key[i]) {keyletter = j;}
				}
				/* encryption occurs here: */
				ciphertext[i] = charoptions[(plaintextletter + keyletter) % 27];
				//printf("server %d, %d => %d => %d %c\n", plaintextletter, keyletter, 
				//	(plaintextletter + keyletter) % 27, ciphertext[i], ciphertext[i]); fflush(stdout);
			}
			strcat(ciphertext, "@@\0");
			//printf("SERVER: sending this ciphertext to the client %s\n", ciphertext); fflush(stdout);
			
			sleep(1);
			
			//Send ciphertext message back to the client
			charsRead = send(establishedConnectionFD, ciphertext, sizeof(ciphertext), 0); // Send success back
			if (charsRead < 0) error("ERROR writing to socket");
		
		        int checkSend = -5;     // Holds amount of bytes remaining in send buffer
		        do {
		                ioctl(listenSocketFD, TIOCOUTQ, &checkSend);  // Check the send buffer for this socket
		                //printf("checkSend: %d\n", checkSend);   // check remaining bytes;
		        } while (checkSend > 0);        // loop until send buffer for socket is empty
		        //if (checkSend < 0) error("ioctl error");        // Check if we actually stopped loop because of error
			//printf("SERVER: done sending\n");
		}
		else {
			wPid = waitpid(wPid, &stat, 0);	
			close(establishedConnectionFD); // Close the existing socket which is connected to the client
		}
	}

	close(listenSocketFD); // Close the listening socket
	
	return 0; 
}
