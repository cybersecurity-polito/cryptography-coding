/**
 * Alice wants to confidentially send Bob the content of a 1MB file through an insecure
 * channel.
 * 
 * Write a program in C, using the OpenSSL library, which Alice can execute to send
 * Bob the file.
 * 
 * Assume that:
 * - Bob's public key is stored into the RSA *bob_pubkey data structure;
 * - The file to send is available in the FILE *file_in data structure;
 * - Alice cannot establish TLS channels or resort to other protocols 
 * - You have access to a high-level communication primitive that sends and receives data
 * and probably format them (e.g., based on a BIO), so that you don't have to think about
 * the communication issues for this exercise
 *
 **/



// Note that: RSA can only encrypt data smaller than (or equal to) the key length (max 4096 bits).

// If you don't want to chunk the file, an approach is HYBRID ENCRYPTION:
// - Creating a random symmetric key R
// - Encrypting the large file with the symmetric key R
// - Encrypting the symmetric key R with an asymmetric RSA public key
// - Transmit both the encrypted key and the encrypted file

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>


#define MAX_BUFFER 1024
#define FILE_SIZE 1024*1024
#define BYTES 16

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
    // EVP_PKEY *bob_pubkey = ... ;     already loaded
    // FILE *file_in = fopen(...);      already loaded

    // Generate a Key and IV of 128 bits
    unsigned char key[BYTES];
    unsigned char iv[BYTES];

    if(RAND_load_file("/dev/random", 64) != 64) //optional on Linux
        handle_errors();

    if(!RAND_bytes(key, BYTES))
        handle_errors();

    if(!RAND_bytes(iv, BYTES))
        handle_errors();


    // Encrypt the file with symmetric encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL)
        handle_errors();

    if(!EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, 1))
        handle_errors();

    

    unsigned char ciphertext[FILE_SIZE];

    int update_len, final_len;
    int ciphertext_len=0;
    int n_read;

    unsigned char buffer[MAX_BUFFER];

    while((n_read = fread(buffer,1,MAX_BUFFER,file_in)) > 0){
        if(ciphertext_len > FILE_SIZE - n_read - EVP_CIPHER_CTX_block_size(ctx)){
            fprintf(stderr,"The file to cipher is larger than I can manage\n");
            abort();
        }
    
        if(!EVP_CipherUpdate(ctx,ciphertext+ciphertext_len,&update_len,buffer,n_read))
            handle_errors();
        ciphertext_len+=update_len;
    }

    fclose(file_in);
    
    if(!EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len))
        handle_errors();

    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);



    // Encrypt the key with asymetric encryption
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(bob_pubkey, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_errors();
    
    size_t encrypted_key_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_key_len, key, strlen(key)) <= 0) 
        handle_errors();
    
    unsigned char encrypted_key[encrypted_key_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_key, &encrypted_key_len, key, strlen(key)) <= 0)
        handle_errors();


    // Send all to Bob
    send_bob(encrypted_key);    // Key encrypted (ASYM)
    send_bob(ciphertext);       // File encrypted with the encrypted_key
    send_bob(iv)

    return 0;
}