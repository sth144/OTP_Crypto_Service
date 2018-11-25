/***************************************************************************************************************************
 *	Title: One-Time-Pad Decryption Daemon
 *	Author: Sean Hinds
 *	Date: 03/14/18
 *	Description: Decryption server daemon which processes up to 5 client decryption requests concurrently using the
 *			Berkeley Sockets API. Accepts a cipher text and key and returns the corresponding plaintext. 
 * ************************************************************************************************************************/

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
	char ciphertext[262144];
	char key[262144];
	char plaintext[262144];
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

	/* infinite loop accepts client connections */
	while (1) {
		// Accept a connection, blocking if one is not available until one connects
		sizeOfClientInfo = sizeof(clientAddress); // Get the size of the address for the client that will connect
		establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo); // Accept
		if (establishedConnectionFD < 0) error("ERROR on accept");

		/* set up fd_set for calls to select() */
		fd_set readFDs;
		struct timeval idle;
		int ret;
		FD_ZERO(&readFDs);
		FD_SET(establishedConnectionFD, &readFDs);
		/* select() will idle for up to 30 seconds waiting for data */
		idle.tv_sec = 30;
		idle.tv_usec = 0;

		/* fork a new process. stat used in parent process to track child */
		int wPid = fork();
		int stat;
		if (establishedConnectionFD >= 0 && !wPid) {

			/* Handshake protocol. Abort if client request comes from program that is not otp_dec */
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
			if (strstr(buffer, "decodeProc") == NULL) {				// client request not coming from otp_dec
				perror("Wrong client process type");
				memset(buffer, '\0', sizeof(buffer));
				strcpy(buffer, "abort@@");
				send(establishedConnectionFD, buffer, sizeof(buffer), 0);
				exit(1);
			} else {
				//printf("SERVER: accepted handshake %s\n", buffer); fflush(stdout);
				memset(buffer, '\0', sizeof(buffer));
				strcpy(buffer, "proceed@@");
				send(establishedConnectionFD, buffer, sizeof(buffer), 0);	
			}	

			// Get the cipher from the client and display it
			charsRead = sizeof(buffer);
			memset(buffer, '\0', sizeof(buffer));
			memset(tempbuffer, '\0', sizeof(tempbuffer));
			ret = 0;
			while (!ret || (strstr(buffer, "@@") == NULL)) {			// accept input, ending in @@
				ret = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &idle);
				if (ret) {
					charsRead = recv(establishedConnectionFD, tempbuffer, sizeof(tempbuffer), 0); // Read the client's message from the socket
					if (charsRead < 0) error("ERROR reading from socket");
					strcat(buffer, tempbuffer);
					memset(tempbuffer, '\0', sizeof(tempbuffer));
				}
			} 
			//printf("SERVER: I received this from the client: \"%s\"\n", buffer); fflush(stdout);
			memset(ciphertext, '\0', sizeof(ciphertext));
			strcpy(ciphertext, buffer);
			ciphertext[strcspn(ciphertext, "@@")] = '\0';

			// Get the key from the client
			charsRead = sizeof(buffer);
			memset(buffer, '\0', sizeof(tempbuffer));
			ret = 0;
			while (!ret || (strstr(buffer, "@@") == NULL)) {
				ret = select(establishedConnectionFD + 1, &readFDs, NULL, NULL, &idle);
				if (ret) {
					charsRead = recv(establishedConnectionFD, tempbuffer, sizeof(tempbuffer), 0);
					if (charsRead < 0) error ("ERROR reading from socket");
					strcat(buffer, tempbuffer);
					memset(tempbuffer, '\0', sizeof(tempbuffer));
				}
			} 
			//printf("SERVER: I received this key from the client: %s\n", buffer); fflush(stdout);
			memset(key, '\0', sizeof(key));
			strcpy(key, buffer);
			key[strcspn(key, "@@")] = '\0';			

			/* process data */
			memset(plaintext, '\0', sizeof(plaintext));
			int ciphertextletter, keyletter;
			/* iterate through each char in ciphertext */
			for (int i = 0; i < strlen(ciphertext); i++) {
				/* check each char in charoptions */
				for (int j = 0; j < strlen(charoptions); j++) {
					/* set indices of key and ciphertext letter */
					if (charoptions[j] == ciphertext[i]) {ciphertextletter = j;}
					if (charoptions[j] == key[i]) {keyletter = j;}
				}
				if ((ciphertextletter - keyletter) < 0) { ciphertextletter += 27; }
				/* decryption occurs here */
				plaintext[i] = charoptions[(ciphertextletter - keyletter) % 27];
				//printf("server %d, %d => %d => %d %c\n", ciphertextletter, keyletter, 
					//(ciphertextletter - keyletter) % 27, plaintext[i], plaintext[i]); fflush(stdout);
			}	
			strcat(plaintext, "@@\0");
			
			sleep(1);		
			
			//printf("SERVER: Sending this decoded message to the client: %s\n", plaintext); fflush(stdout);		
			// Send deciphered plaintext back to the client
			charsRead = send(establishedConnectionFD, plaintext, sizeof(plaintext), 0); // Send success back
			if (charsRead < 0) error("ERROR writing to socket");
	
	        	int checkSend = -5;     // Holds amount of bytes remaining in send buffer
	        	do {
	        	        ioctl(listenSocketFD, TIOCOUTQ, &checkSend);  // Check the send buffer for this socket
	        	        //printf("checkSend: %d\n", checkSend);   // check remaining bytes;
	        	} while (checkSend > 0);        // loop until send buffer for socket is empty
	        	//if (checkSend < 0) error("ioctl error");        // Check if we actually stopped loop because of error
			//printf("SERVER: done sending response\n"); fflush(stdout);
		}
		else {
			wPid = waitpid(wPid, &stat, 0);
			close(establishedConnectionFD);
		} 
	}

	close(listenSocketFD); // Close the listening socket
	
	return 0; 
}
