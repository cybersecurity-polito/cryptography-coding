/*
The specification of the NONCENSE protocol includes the following operations:
1) generate a random 256-bit number, name it r1
2) generate a random 256-bit number, name it r2
3) obtain a key by XOR-ing the two random numbers r1 and r2, name it key_symm
4) generate an RSA keypair of at least 2048 bit modulus
5) Encrypt the generated RSA keypair using AES-256 with key_symm and obtain the payload.
Implement in C the protocol steps described above, make the proper decisions when the protocol omits information.
*/


#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define BYTES 16		// = 256 bit
#define MAX_ENC_LEN 10000
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(){
	unsigned char r1[BYTES];
	unsigned char r2[BYTES];
	unsigned char key_symm[BYTES];

    if(RAND_load_file("/dev/random", 64) != 64) //optional on Linux
        handle_errors();

    if(!RAND_bytes(r1, BYTES))
        handle_errors();

    if(!RAND_bytes(r2, BYTES))
        handle_errors();

    // XOR operation
    for(int i=0; i < BYTES; i++)
    	key_symm[i] = r1[i] ^ r2[i];
    	// key_symm[i] = (r1[i] + r2[i]) % 2;


   	// Part 4
   	EVP_PKEY *rsa_keypair = NULL;
    int bits = 2048;

    if((rsa_keypair = EVP_RSA_gen(bits)) == NULL ) 
        handle_errors();


    // Part5 encrypt RSA keypair using AES-256 with key_symm
    In this way I export just the private key.
    if(!PEM_write_PrivateKey(stdout, rsa_keypair, EVP_aes_256_cbc(), key_symm, strlen(key_symm), NULL, NULL))
        handle_errors();
	
    /*
	// Alternative part5: Write in a file both public and private key and encrypt them
	FILE *rsa_keys = NULL;
    if((rsa_keys = fopen("keys.pem","w")) == NULL) {
        fprintf(stderr,"Couldn't create the keys file.\n");
        abort();
    }

    if(!PEM_write_PUBKEY(rsa_keys, rsa_keypair))
        handle_errors();

 	if(!PEM_write_PrivateKey(rsa_keys, rsa_keypair, NULL, NULL, 0, NULL, NULL))
 		handle_errors();

    fclose(rsa_keys);
    EVP_PKEY_free(rsa_keypair);


    // Assume key and IV are already known
    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[]  = "1111111111111111";

    if((rsa_keys = fopen("keys.pem","r")) == NULL) {
        fprintf(stderr,"Couldn't read the keys file.\n");
        abort();
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, 1))
		handle_errors();


	unsigned char payload[MAX_ENC_LEN];

    int update_len, final_len;
    int ciphertext_len=0;
    int n_read;
    unsigned char buffer[MAX_BUFFER];


    while((n_read = fread(buffer,1,MAX_BUFFER,rsa_keys)) > 0){
        if(ciphertext_len > MAX_ENC_LEN - n_read - EVP_CIPHER_CTX_block_size(ctx)){ //use EVP_CIPHER_get_block_size with OpenSSL 3.0+ instead
            fprintf(stderr,"The file to cipher is larger than I can manage\n");
            abort();
        }
    
        if(!EVP_CipherUpdate(ctx,payload+ciphertext_len,&update_len,buffer,n_read))
            handle_errors();
        ciphertext_len+=update_len;
    }

    if(!EVP_CipherFinal_ex(ctx,payload+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    // In the variable payload I have the encrypted RSA keypair
    printf("Payload length = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", payload[i]);
    printf("\n");
    */

    EVP_CIPHER_CTX_free(ctx);
    fclose(rsa_keys);

	return 0;
}