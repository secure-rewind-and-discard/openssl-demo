#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sdrad_api.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifndef OPENSSL_INIT_NO_ATEXIT
#define OPENSSL_INIT_NO_ATEXIT 0
#endif


#define OPENSSL_UDI 2
#define OPENSSL_DATA_UDI 3




/* 256 bit (32 bytes) key length definition */
#define AES_GCM_KEY_LEN      32
/* 96 bit (12 bytes) IV (nonce to be exact) length definition */
#define AES_GCM_IV_LEN       12
/* 128 bit (16 bytes) authentication tag data length definition */
#define AES_GCM_AUTHTAG_LEN  16

/* 64 bytes plaintext data */
static const unsigned char g_ae_plain[] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73
};

static const unsigned char gcm_aad[] = {
	0x4d,0x23,0xc3,0xce,0xc3,0x34,0xb4,0x9b,0xdb,0x37,0x0c,0x43,
	0x7f,0xec,0x78,0xde
};

void handleErrors()
{
    printf("exited");
}

/*https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption*/ 

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return EXIT_FAILURE;

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return EXIT_FAILURE;

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        return EXIT_FAILURE;

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return EXIT_FAILURE;

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) 
        return EXIT_FAILURE;

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return EXIT_FAILURE;
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return EXIT_FAILURE;
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        return EXIT_FAILURE;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
         return EXIT_FAILURE;

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
         return EXIT_FAILURE;

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
         return EXIT_FAILURE;

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
         return EXIT_FAILURE;

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
         return EXIT_FAILURE;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
         return EXIT_FAILURE;
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
         return EXIT_FAILURE;

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

/* Initialise OpenSSL and draw the key/IV inside the OpenSSL domain so that
 * all of OpenSSL's global state lives in that domain's heap. */
static int rand_in_openssl_domain(unsigned char *key, unsigned char *iv)
{
    register unsigned char *k asm ("r13");
    register unsigned char *v asm ("r14");
    register int ok asm ("r12");
    k = key; v = iv;
    sdrad_enter(OPENSSL_UDI);
    OPENSSL_init_crypto(OPENSSL_INIT_NO_ATEXIT, NULL);
    ok  = RAND_bytes(k, AES_GCM_KEY_LEN);
    ok += RAND_bytes(v, AES_GCM_IV_LEN);
    sdrad_exit();
    return ok == 2;
}

int worker()
{
    unsigned char *key; 
    unsigned char *iv;
    unsigned char *cipher; 
    unsigned char *plain;
    unsigned char *authtag; 
    unsigned char *add; 



    if(sdrad_init(OPENSSL_UDI, SDRAD_EXECUTION_DOMAIN| SDRAD_ISOLATED_DOMAIN| SDRAD_RETURN_TO_CURRENT) !=  SDRAD_SUCCESSFUL_RETURNED){
        handleErrors(); return EXIT_FAILURE;
    }
    if(sdrad_init(OPENSSL_DATA_UDI, SDRAD_DATA_DOMAIN) != SDRAD_SUCCESSFUL_RETURNED){
        handleErrors(); return EXIT_FAILURE;
    }
    sdrad_dprotect(OPENSSL_UDI, OPENSSL_DATA_UDI, 0x0);

    /* buffers shared with the OpenSSL domain */
    key = sdrad_malloc(OPENSSL_DATA_UDI, AES_GCM_KEY_LEN); 
    iv = sdrad_malloc(OPENSSL_DATA_UDI, 12); 
    cipher = sdrad_malloc(OPENSSL_DATA_UDI, 256);
    plain = sdrad_malloc(OPENSSL_DATA_UDI, 256);
    authtag = sdrad_malloc(OPENSSL_DATA_UDI, 16); 
    add = sdrad_malloc(OPENSSL_DATA_UDI, 8);
    printf("domains ready: openssl=%d openssl_data=%d\n", OPENSSL_UDI, OPENSSL_DATA_UDI);

    if (!rand_in_openssl_domain(key, iv)){
        printf("RAND_bytes failed..\n");
        return EXIT_FAILURE;
    }

    int ciphertext_len = gcm_encrypt(g_ae_plain, sizeof(g_ae_plain), gcm_aad, sizeof(gcm_aad), key, iv, AES_GCM_IV_LEN, cipher, authtag);
    gcm_decrypt(cipher, ciphertext_len, gcm_aad, sizeof(gcm_aad), authtag, key, iv, AES_GCM_IV_LEN, plain); 

    if (memcmp(plain, g_ae_plain, sizeof(g_ae_plain))== 0){
        printf("PASS: Plaintext values match!  (\"%.*s\")\n", (int)sizeof(g_ae_plain), plain);
    } else {
        printf("FAIL: Plaintext values don't match!\n");
    }
    return EXIT_SUCCESS;
}

int main()
{ 
    int a; 


    setvbuf(stdout, NULL, _IONBF, 0);

    a = worker();

    /* clean up OpenSSL inside its own domain before exit */
    sdrad_enter(OPENSSL_UDI);
    OPENSSL_cleanup();
    sdrad_exit();
    printf("OpenSSL domain cleaned up\n");
    return a;
 
}





