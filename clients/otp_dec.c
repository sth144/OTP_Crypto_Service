/***************************************************************************************************************************
 *	Title: One-Time-Pad Decryption Client
 *	Author: Sean Hinds
 *	Date: 03/14/18
 *	Description: Client program which requests decryption service from the server. Uses Berkeley sockets API to send
 *			ciphertext and key data to the server.
 * ************************************************************************************************************************/

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
	/* buffers for data storage */
	char buffer[262144];
	char tempbuffer[262144];
	
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
	
	/* define fd_set for use in calls to select() */
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
	strcpy(buffer, "decodeProc@@");
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
			charsRead = recv(socketFD, buffer, sizeof(buffer) - 1, 0);
			if (charsRead < 0) error("CLIENT: ERROR reading from socket");
		}
	}
	if (strstr(buffer, "abort")) { error("CLIENT: tried to connect to wrong server daemon, instructed to abort"); exit(2); }

	// Send message to server
	memset(buffer, '\0', sizeof(buffer)); // Clear out the buffer array
	
	/* open ciphertext filestream, import data, and send */
	FILE* cipherfile = fopen(argv[1], "r");	

	fgets(buffer, sizeof(buffer) - 1, cipherfile); // Get input
	buffer[strcspn(buffer, "\n")] = '\0'; // Remove the trailing \n that fgets adds
	strcat(buffer, "@@\0");
	int ciphertextlen = strlen(buffer);	// store length of ciphertext to compare to key length
	//printf("CLIENT: Sending this message to the server: %s\n", buffer); fflush(stdout);	
	charsWritten = send(socketFD, buffer, strlen(buffer), 0); // Write to the server
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
        checkSend = -5;     // Holds amount of bytes remaining in send buffer
        do {
                ioctl(socketFD, TIOCOUTQ, &checkSend);  // Check the send buffer for this socket
                //printf("checkSend: %d\n", checkSend);   // check remaining bytes;
        } while (checkSend > 0);        // loop until send buffer for socket is empty
        //if (checkSend < 0) error("ioctl error");        // Check if we actually stopped loop because of error
	
	fclose(cipherfile);

	/* key processing */
	memset(buffer, '\0', sizeof(buffer));

	/* open key filestream and import data */
	FILE* keyfile = fopen(argv[2], "r");

	fgets(buffer, sizeof(buffer) - 1, keyfile);
	buffer[strcspn(buffer, "\n")] = '\0';
	strcat(buffer, "@@\0");
	/* ensure that key is long enought to decode cipher */
	if (strlen(buffer) < ciphertextlen) { perror("CLIENT: key too short to decode ciphertext"); exit(1); }	

	//printf("CLIENT: sending this key to the server: %s\n", buffer); fflush(stdout);

	charsWritten = send(socketFD, buffer, strlen(buffer), 0);
	if (charsWritten < 0) error("CLIENT: ERROR writing to socket");
	if (charsWritten < strlen(buffer)) printf("CLIENT: WARNING: Not all data written to socket!\n");
	checkSend = -5;
	do {
		ioctl(socketFD, TIOCOUTQ, &checkSend);
	} while (checkSend > 0);

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
			//printf("CLIENT: I received this from the server: \"%s\"\n", buffer); fflush(stdout);
			memset(tempbuffer, '\0', sizeof(tempbuffer));
		}
	}
	buffer[strcspn(buffer, "@@")] = '\0';

	//printf("CLIENT: response from the server: %s", buffer);
	printf("%s\n", buffer);

	close(socketFD); // Close the socket
	return 0;
}
