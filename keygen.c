/**********************************************************************************
 *	Title: Key Generator 
 *	Author: Sean Hinds
 *	Date: 03/14/18
 *	Description: Key generator for one-time-pad encryption server.
 * *******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char** argv) {

	/* seed random number */
	srand(time(NULL));

	char* options = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

	if (argc > 1) {
		/* parse argument from command line which specifies key length */
		int bufferSize = atoi(argv[1]);
		char* buffer = malloc(bufferSize * sizeof(char));
		for (int i = 0; i < bufferSize; i++) {
			buffer[i] = options[rand() % (strlen(options))];
		}
		/* output the key to stdout */
		printf("%s\n", buffer);
		free(buffer);
	}
	return 0;

}
