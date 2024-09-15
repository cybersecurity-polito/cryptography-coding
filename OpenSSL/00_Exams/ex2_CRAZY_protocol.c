/**
 * The specification of the CRAZY protocol includes the following operations:
 * 
 * 1. Generate two strong random 128-bit integers, name them rand1 and rand2
 * 
 * 2. Obtain the first key as
 * k1 = (rand1 + rand2) * (rand1 - rand2) mod 2^128
 * 
 * 3. Obtain the second key as
 * k2 = (rand1 * rand2) / (rand1 - rand2) mod 2^128
 * 
 * 4. Encrypt k2 using k1 using a stron encryption algorithm (and mode) of your choice
 * call it enc_k2.
 * 
 * 5. Generate an RSA keypair with a 2048 bit modulus.
 * 
 * 6. Encrypt enc_k2 using the just generated RSA key.
 * 
 * Implement in C the protocol steps described above, make the proper decisions when
 * the protocol omits information.
 * 
 **/

#include <stdio.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>    
#include <openssl/err.h>
#include <openssl/evp.h>


#define BITS 128

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){
    OpenSSL_add_all_algorithms();


// PART: 1
    BIGNUM *rand1=BN_new();
    BIGNUM *rand2=BN_new();
    BN_CTX *ctx=BN_CTX_new();

    // Generate randoms
    BN_rand(rand1,BITS,0,1);
    BN_rand(rand2,BITS,0,1);

    printf("Done part 1\n");

// PART 2
    BIGNUM *sum=BN_new();
    BN_add(sum,rand1,rand2);
  
    BIGNUM *sub=BN_new();
    BN_sub(sub,rand1,rand2);

    BIGNUM *mod=BN_new();
    BIGNUM *base=BN_new();
    BIGNUM *exp=BN_new();
    BN_set_word(base,2);
    BN_set_word(exp,128);
    BN_exp(mod,base,exp,ctx);

    BIGNUM *k1=BN_new();
    BN_mod_mul(k1, sum, sub, mod, ctx);

    printf("Done part 2\n");


// PART 3
    BIGNUM *mul=BN_new();
    BN_mul(mul,rand1,rand2, ctx);

    BIGNUM *div=BN_new();
    BN_div(div, NULL, mul, sub, ctx);

    BIGNUM *k2=BN_new();
    BN_mod(k2, div, mod, ctx);



    printf("Done part 3\n");

// PART 4: Encrypt k2 using k1
    unsigned char k1_bin[16];
    unsigned char k2_bin[16];
    unsigned char enc_k2[16]; 

    
    BN_bn2bin(k1, k1_bin);
    BN_bn2bin(k2, k2_bin);

    BN_free(k1);
    BN_free(k2);
    BN_CTX_free(ctx);

    // Random initialization of the IV in pedantic mode
    unsigned char iv[] = "1111111111111111";


    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(aes_ctx,EVP_aes_128_cbc(), k1, iv, 1);


    int update_len, final_len;
    int ciphertext_len=0;

    EVP_CipherUpdate(aes_ctx,enc_k2,&update_len, k2_bin,strlen(k2_bin));
    ciphertext_len+=update_len;

    EVP_CipherFinal_ex(aes_ctx,enc_k2+ciphertext_len,&final_len);
    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(aes_ctx);

    printf("Done part 4\n");



// Part 5: Generate an RSA keypair with a 2048-bit modulus.
    EVP_PKEY *keypair = NULL;

    if((keypair = EVP_RSA_gen(2048)) == NULL ) 
        handle_errors();

    printf("Done part 5\n");

// PArt 6: Encrypt enc_k2 using the just generated RSA key.
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) 
        handle_errors();
  
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        handle_errors();
    
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_msg_len, enc_k2, strlen(enc_k2)) <= 0)
        handle_errors();
   

    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_msg, &encrypted_msg_len, enc_k2, strlen(enc_k2)) <= 0)
        handle_errors();
    
    EVP_PKEY_free(keypair);

    printf("Done part 6\n");

    printf("Ciphertext length = %d\n", encrypted_msg_len);
    for(int i = 0; i < encrypted_msg_len; i++)
        printf("%02x", encrypted_msg[i]);
    printf("\n");

    return 0;
}