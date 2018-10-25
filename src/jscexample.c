#include <stdio.h>
#include <stdlib.h>
#include "jscrypt.h"

/**
 * simple demo for the jsccrypt functions
 */
int main( int argc, char **argv ) {
	char *res;
	int len;

	if ( argc != 4 ) {
		printf("%s <-e|-d> <msg> <pass>\n", argv[0] );
		return -1;
	}

	if( argv[1][0] != '-' ) {
		printf("Syntax Error!\nReady.\n");
		return -1;
	}

	if( argv[1][1] == 'e' ) {
		len=jsencryptAES( argv[2], argv[3], &res );
		if( len == -1 ) {
			printf("Encryption error!\n");
			return -1;
		}
		if( res == NULL ) {
			printf("Empty reply!\n");
			return -1;
		}
		printf("%s\n", res );
	}
	else {
		len=jsdecryptAES( argv[2], argv[3], &res );
		if( len == -1 ) {
			printf("Decryption error!\n");
			return -1;
		}
		if( res == NULL ) {
			printf("Empty reply!\n");
			return -1;
		}
		printf("%s\n", res );
	}
	free( res );
	return EXIT_SUCCESS;
}
