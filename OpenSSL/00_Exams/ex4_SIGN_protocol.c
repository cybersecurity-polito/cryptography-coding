/**
 * The specification of the SIGN protocol includes the following operations:
 * - Generate a random 128-bit number, name it r1
 * - Generate a random 128-bit number, name it r2
 * - Concatenate them to obtain a 256-bit AES key name k
 * - Encrypt the content of the FILE *f_in; with AES and k and save it on the file FILE *f_out
 *   (assume both files have been properly opened)
 * 
 * - Generate the signature of the encrypted file FILE *f_out with the RSA keypair available
 *   as EVP_PKEY* rsa_key (properly loaded in advance).
 *
 *  Implement the protocol steps above in C, and make the proper decisions when the protocol omits
 *  information.
 **/ 


#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string.h>

#define BYTE 256/8
#define MAX 128/8
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
	unsigned char r1[MAX];
	unsigned char r2[MAX];

    if(RAND_load_file("/dev/random", 64) != 64) //optional on Linux
        handle_errors();

    if(!RAND_bytes(r1, MAX))
        handle_errors();

    if(!RAND_bytes(r2, MAX))
        handle_errors();



    // Concat to obtain k
    unsigned char key[32];
    for(int i=0; i<32; i++){
    	if(i<16)
    		key[i] = r1[i];
    	else
    		key[i] = r2[i-16];
    }


    // Files already opened and encrypt it with key
    FILE *f_in;
    FILE *f_out;

    // Generate IV
    unsigned char iv[BYTE];
    if(!RAND_bytes(iv, BYTE))
        handle_errors();


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if(!EVP_CipherInit(ctx,EVP_aes_256_cbc(), key, iv, 1))
        handle_errors();

    int length;
    unsigned char ciphertext[MAX_BUFFER+16];

    int n_read;
    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer,1,MAX_BUFFER,f_in)) > 0){

        if(!EVP_CipherUpdate(ctx,ciphertext,&length,buffer,n_read))
            handle_errors();

        if(fwrite(ciphertext, 1, length,f_out) < length){
            fprintf(stderr,"Error writing the output file\n");
            abort();
        }
    }
            
    if(!EVP_CipherFinal_ex(ctx,ciphertext,&length))
        handle_errors();

    printf("lenght=%d\n",length);

    if(fwrite(ciphertext, 1, length, f_out) < length){
        fprintf(stderr,"Error writing in the output file\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    fclose(f_in);
    fclose(f_out);



    // Generate signature
    EVP_PKEY* rsa_key; // (properly loaded in advance)


    FILE *f_in_encrypted;
    if((f_in = fopen("f_out_encrypted","r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

  	EVP_MD_CTX  *sign_ctx = EVP_MD_CTX_new();

    if(!EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, rsa_key))
            handle_errors();
    
    size_t n_read;
    unsigned char buffer[MAXBUFFER];
    while((n_read = fread(buffer,1,MAXBUFFER,f_in)) > 0){
        if(!EVP_DigestSignUpdate(sign_ctx, buffer, n_read))
            handle_errors();
    }

    
    size_t sig_len;
    if(!EVP_DigestSignFinal(sign_ctx, NULL, &sig_len))
        handle_errors();

    unsigned char signature[sig_len];

    // size_t sig_len = digest_len;
    if(!EVP_DigestSignFinal(sign_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(sign_ctx);
	EVP_PKEY_free(rsa_key);

	fclose(f_in_encrypted);
	return 0;
    
}