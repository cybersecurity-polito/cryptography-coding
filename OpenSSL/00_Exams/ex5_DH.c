/*

Sketch the Diffie-Hellman key agreement protocol in C using the OpenSSL library.
Imagine you have a client CARL that starts communicating with a server SARA. 
CARL initiates the communication and proposes the public parameters.
Assume you have access to a set of high-level communication primitives that allow 
you to send and receive big numbers and to properly format them (e.g., based on a BIO), 
so that you don't have to think about the communication issues for this exercise.

void send_to_sara(BIGNUM b)
BIGNUM receive_from_sara()
void send_to_carl(BIGNUM b)
BIGNUM receive_from_carl)

Finally answer the following question: 
what CARL and SARA have to do if they want to generate an AES-256 key?

*/

#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}



int main_carl(){

	// Carl select a module p
	BIGNUM *p=BN_new();
	BIGNUM *gen=BN_new();
	BN_CTX *ctx=BN_CTX_new();

	int rc = RAND_load_file("/dev/random", 64);
  	if(rc != 64)
		handle_errors();
  	
    if (!BN_generate_prime_ex(p, 256*8, 0, NULL, NULL, NULL)) 
    	handle_errors();

    send_to_sara(p);

    // Carl choose a generator
	if (!BN_generate_prime_ex(gen, 256*8, 0, NULL, NULL, NULL)) 
		handle_errors();
	BN_mod(gen, gen, p, ctx);	// gen in {1, ..., p-1}

    send_to_sara(gen);

    printf("Prime module and generator selected\n");


    // Carl choose c (private)
	BIGNUM *c=BN_new();
	BIGNUM *C=BN_new();

    BN_rand(c,256*8,0,1);
    BN_mod(c, c, p, ctx);	// c in {1, ..., p-1}

	// Carl compute C (public)
    BN_mod_exp(C, gen, c, p, ctx);
    send_to_sara(C);

    // Carl receive S from Sara
    BIGNUM *S=BN_new();
    S = receive_from_sara();

    // Carl can compute the shared key: S^b
	BIGNUM *K=BN_new();
    BN_mod_exp(K, S, c, p, ctx);

	BN_free(p);
	BN_free(gen);

	BN_free(c);
	BN_free(C);
	BN_free(S);

	BN_CTX_free(ctx);
	return 0;
}



int main_sara(){
	BIGNUM *p=BN_new();
	BIGNUM *gen=BN_new();
	BIGNUM *C=BN_new();

	BN_CTX *ctx=BN_CTX_new();

	p = receive_from_carl();
	gen = receive_from_carl();
	C = receive_from_carl();

	// Sara choose s and compute S
	BIGNUM *s=BN_new();
	BIGNUM *S=BN_new();

    BN_rand(s,256*8,0,1);
    BN_mod(s, s, p, ctx);	// s in {1, ..., p-1}
    BN_mod_exp(S, gen, s, p, ctx);

    send_to_carl(S);

    // Sara can compute the shared key
	BIGNUM *K=BN_new();
    BN_mod_exp(K, C, s, p, ctx);

	BN_free(p);
	BN_free(gen);
	BN_free(s);
	BN_free(S);
	BN_free(C);

	BN_CTX_free(ctx);
	return 0;
}

// Finally answer the following question: what CARL and SARA have to do if they want to generate an AES-256 key?
// 1) Use a Key Dervation Function to derive a key from the shared K
// 2) Otherwise I can choose one of the user which will generate the key, encrypt it with the 
// 		DH shared secret and shared to the other party.

