/*
Implement, using the C programming language, the following function envelop_MACIRSA(), which implements the following operations:
1) double_SHA256 of the concatenation of a message with a symmetric key;
2) RSA encrypt the result of the last step;
3) retums 0 in case of success, 1 in case of errors, and the result of the RSA encryption by reference.
In other words, the function has to implement the following transformation:

RSA_encrypt(public_key, SHA_256 ( SHA_256 ( message || key)))

*/

int envelop_MAC(RSA *rsa keypair, char *message, int message_len, char *key, int keylenght, char *result){
	int error = 0;

	// First SHA and concatenation
	EVP_MD_CTX *md = EVP_MD_CTX_new();

 	if(!EVP_DigestInit(md, EVP_sha256()))
        return 1;
	
	if(!EVP_DigestUpdate(md, message, strlen(message)))
        return 1;

	if(!EVP_DigestUpdate(md, key, strlen(key)))
        return 1;

	// unsigned char md_value[16];	// 256 bit = 16 byte
	unsigned char md_value[EVP_MD_size(EVP_sha256())];
    int md_len;

    EVP_DigestFinal(md, md_value, &md_len);
	EVP_MD_CTX_free(md);



	// Second SHA
	EVP_MD_CTX *md2 = EVP_MD_CTX_new();

 	if(!EVP_DigestInit(md2, EVP_sha256()))
        return 1;
	
	if(!EVP_DigestUpdate(md2, md_value, md_len))
        return 1;

	// unsigned char double_sha[16];	// 256 bit = 16 byte
	unsigned char double_sha[EVP_MD_size(EVP_sha256())];
    int double_sha_len;

    EVP_DigestFinal(md2, double_sha, &double_sha_len);
	EVP_MD_CTX_free(md2);



	// RSA Encryption
    EVP_PKEY_CTX* enc_ctx = EVP_PKEY_CTX_new(keypair, NULL);
    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0)
        return 1;
   
    // Specific configurations can be performed through the initialized context
    if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        return 1;

    // Determine the size of the output
    size_t encrypted_msg_len;
    if (EVP_PKEY_encrypt(enc_ctx, NULL, &encrypted_msg_len, double_sha, double_sha_len) <= 0)
        return 1;
  
    unsigned char encrypted_msg[encrypted_msg_len];
    if (EVP_PKEY_encrypt(enc_ctx, encrypted_msg, &encrypted_msg_len, double_sha, double_sha_len) <= 0)
        return 1;
    

	result = encrypted_msg;
	return 0;
}