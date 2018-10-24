# aes-c-js
A set of simple functions to implement AES encrypted data exchange between C and Javascript

To check out the demo, rum 'make' in the top level directory, this will create the jscexample binary in the demo directory. To use the demo, open the demo/jsdemo.html file in a modern browser. This will allow to en- and decrypt text via javascript.

The jscdemo executable takes either some plaintext or an encoded text and a password and en- or decodes it according to the flag. For example:

$ jscdemo -e "This is a super secret text!" password

The encrypted output can be decoded in javascript and with the jscdemo utility. The encrypted blob is BASE64 encoded so it can easily be exchanged without having to take special care of text encoding issues.

No warranties, no promises, use at will.

The javascript part is based on https://gist.github.com/chrisveness/43bcda93af9f646d083fad678071b90a by @chrisveness the OpenSSL part is based on the API documentation https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
