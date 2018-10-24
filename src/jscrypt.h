int jssha256(const char *msg,  unsigned char **digest );
int jsencryptAES( const char *plaintext, const char *passwd, char **ciphertext );
int jsdecryptAES( const char *ciphertext, const char *passwd, char **plaintext );
