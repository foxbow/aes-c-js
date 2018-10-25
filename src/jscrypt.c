/*
 * simple AES front end to create strings that can be used in a web
 * connection to a JavaScript client.
 * The aim is to just use the subtlecrypto API.
 */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <errno.h>
#include "jscrypt.h"

static void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	exit(-1);
}

/*
 * generate a sha256 hash to create a key from a password
 * msg: the password
 * digest: an indirect pointer to a buffer containing the digest
 *         this will be autamaticatty allocated and filled.
 *
 * Returns -1 on failure and the length of the digest otherwise
 */
int jssha256(const char *msg,  unsigned char **digest ) {
	EVP_MD_CTX *mdctx;
	unsigned int len;

	if((mdctx = EVP_MD_CTX_create()) == NULL)
		handleErrors();

	if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
		handleErrors();

	if(1 != EVP_DigestUpdate(mdctx, msg, strlen( msg) ) )
		return -1;

	if((*digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()))) == NULL)
		return -1;

	if(1 != EVP_DigestFinal_ex(mdctx, *digest, &len))
		return -1;

	EVP_MD_CTX_destroy(mdctx);

	return len;
}

/**
 * takes the text in plaintext, encrypts it with the key generated from
 * passwd and stores the BASE64 encoded stream of IV+crypt in ciphertext.
 *
 * returns -1 on error and the length of ciphertext otherwise.
 *
 * since this is just a simple demonstration the key is not buffered
 * and the IV will be generated new on every call. So it is not the
 * most performant way but the simples use case.
 *
 * error handling is a mess too.
 */
int jsencryptAES( const char *plaintext, const char *passwd, char **ciphertext )
{
	EVP_CIPHER_CTX *ctx;
	int len, clen, plen=strlen( plaintext )+1;
	unsigned char *key=NULL;
	unsigned char *crypto=NULL;
	int retval=-1;

	/* initialize the crypto stream with a new IV and add a block to round up */
	crypto=(unsigned char *)calloc( plen+32, 1 );
	if( crypto == NULL ) {
		return -1;
	}

	/* create a random IV */
	if( RAND_bytes( crypto, 16 ) != 1 ) {
		return -1;
	}

	/* generate the key from the password */
	if( jssha256( passwd, &key ) == -1 ) {
		return -1;
	}

	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	if(1 != EVP_EncryptInit_ex( ctx, EVP_aes_256_cbc(), NULL, key, crypto ) )
		handleErrors();

	/* Mind the null-byte at the end */
	if(1 != EVP_EncryptUpdate(ctx, crypto+16, &len, (unsigned char *)plaintext, plen ) ) {
		goto cleanup;
	}
	clen = len;
	if(1 != EVP_EncryptFinal_ex(ctx, crypto+16+clen, &len) ) {
		goto cleanup;
	}
	clen += len;

	/* encode the result in BASE64 */
	*ciphertext=(char *)calloc( (clen+16)*2, 1 );
	if( *ciphertext == NULL ) {
		goto cleanup;
	}
	EVP_EncodeBlock( (unsigned char *)*ciphertext, crypto, clen+16 );
	retval=strlen( *ciphertext );

cleanup:
	free( key );
	free( crypto );
	EVP_CIPHER_CTX_free(ctx);

	return retval;
}

/**
 * takes the BASE64 encoded IV+ciphertext, decrypts it with the key generated
 * from passwd and stores the text in plaintext.
 *
 * returns -1 on error and the length of the original text otherwise.
 *
 * since this is just a simple demonstration the key is not buffered
 * and the IV will be generated new on every call. So it is not the
 * most performant way but the simples use case.
 *
 * error handling is a mess too.
 */
int jsdecryptAES( const char *ciphertext, const char *passwd, char **plaintext ) {
	EVP_CIPHER_CTX *ctx;
	int len, clen, reslen=-1;
	unsigned char *crypto=NULL;
	unsigned char *key=NULL;

	/* generate the key from the password */
	if( jssha256( passwd, &key ) == -1 ) {
		return -1;
	}

  /* buffer to store the binary stream in */
	crypto=(unsigned char *)calloc( strlen( ciphertext ), 1 );
	if( crypto == NULL ) {
		return -1;
	}

	/* get the binary stream from the ciphertext */
	clen=EVP_DecodeBlock( crypto, (unsigned char *)ciphertext, strlen( ciphertext ) );
	if( clen == -1 ) {
		return -1;
	}

	/* correct BASE64 padding into proper AES blocksize + IV */
	clen=(clen/16)*16;

	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* crypto starts with the IV */
	if( EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, crypto ) != 1 ) {
		goto cleanup;
	}

	/* allocate room for the plaintext buffer */
	*plaintext=(char *)calloc( clen, 1 );
	if( *plaintext == NULL ) {
		goto cleanup;
	}

	if( EVP_DecryptUpdate( ctx, (unsigned char *)*plaintext, &len, crypto+16, clen-16) != 1 ) {
		free( *plaintext );
		*plaintext=NULL;
		goto cleanup;
	}
	reslen = len;

	if(1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)(*plaintext)+reslen, &len) ) {
		handleErrors();
		reslen=-1;
		free( *plaintext );
		*plaintext=NULL;
		goto cleanup;
	}
	reslen += len;
	(*plaintext)[reslen]=0;

cleanup:
	free( key );
	free( crypto );
	EVP_CIPHER_CTX_free(ctx);
	return reslen;
}
