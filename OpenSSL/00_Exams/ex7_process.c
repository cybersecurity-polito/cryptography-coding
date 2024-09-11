// A server is listening on a given port where it receives raw bytes
// When a client establishes a connection and sends some data, the server calls
// its internal function process(), which produces the output to send back to the
// client. The prototype of the function is the following one:

// char *process(char *data, int length, RSA *rsa_priv_key)

// The function process():
// Checks if data can be decrypted with rsa_priv_key; if possible,
// obtains decrypted_data by decrypting the data variable (by "manually" implementing
// the RSA decryption algorithm);
// Computes the hash h of decrypted_data using SHA256

// If data can be decrypted, process() returns three bytes:

// As a first byte, the least significant bit of decrypted_data
// As a second byte, the least significant bit of the hash h;
// As a third byte, the XOR of the previous two bytes

// Otherwise, it returns NULL.

// Implement in C the function process() described above using the OpenSSL library.

#include <stdio.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#include <openssl/evp.h>


#define KEY_LENGTH  2048


void handle_errors(){
    ERR_print_errors_fp(stderr);
    return NULL;
}


char *process(char *data, int length, RSA *rsa_priv_key){
	// Note that "RSA" data structure is from OpenSSL version 1.1
	// Assume data is in binary

	// Get values from the provided rsa_priv_key
	BIGNUM *n=BN_new();
  	BIGNUM *d=BN_new();

	// Get n and d:					RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
	RSA_get0_key(rsa_priv_key, &n, NULL, &d);

	// Convert data into BN: 		BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
	BIGNUM *data_bn = BN_new();
	BN_bin2bn(data, length, data_bn);

	// Check and compute the decryption: data^d mod n
	BN_CTX *ctx=BN_CTX_new();
	BIGNUM *dec=BN_new();

	if(!BN_mod_exp(dec, data_bn, d, n, ctx))
		handle_errors();

	// Decryption has been done 
	// Convert dec (BN) into binary : 	BN_bn2bin(const BIGNUM *a, unsigned char *to);
	unsigned char decrypted_data[RSA_size(keypair)] = "";
	BN_bn2dec(dec, decrypted_data);



	// Computes the hash h of decrypted_data using SHA256
	EVP_MD_CTX *md = EVP_MD_CTX_new();
    if(!EVP_DigestInit(md, EVP_sha256()))
        handle_errors();

     if(!EVP_DigestUpdate(md, decrypted_data, strlen(decrypted_data))
     	handle_errors();

    unsigned char md_value[EVP_MD_size(EVP_sha256())];       
    int md_len;

    if(!EVP_DigestFinal(md, md_value, &md_len))
    	handle_errors();

	EVP_MD_CTX_free(md);
    RSA_free(keypair);

    // All OK => return 3 bytes
    unsigned char return_value[3] = "";

	// As a first byte, the least significant bit of decrypted_data
	return_value[0] = decrypted_data[strlen(decrypted_data)-1];
	// As a second byte, the least significant bit of the hash h;
	return_value[1] = md_value[md_len-1];
	// As a third byte, the XOR of the previous two bytes
	return_value[2] = return_value[0] ^ return_value[1];

	return return_value;
}
