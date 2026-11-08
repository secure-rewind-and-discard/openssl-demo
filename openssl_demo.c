#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sdrad_api.h"

#define SDRAD_CALL(sub_active_domain,fun, ...)  \
sdrad_enter(OPENSSL_UDI);         \
fun( __VA_ARGS__ );                             \
sdrad_exit();          \


#define OPENSSL_UDI 2
#define OPENSSL_DATA_UDI 3

EVP_PKEY_CTX *__real_EVP_PKEY_CTX_new_id(int id, ENGINE *e); 

EVP_PKEY_CTX *__wrap_EVP_PKEY_CTX_new_id(int id, ENGINE *e)
{
    register EVP_PKEY_CTX *ret asm ("r12");
    register int id_child asm ("r13");
    id_child = id;
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_CTX_new_id(id_child, NULL); 
    sdrad_exit(); 
    return ret;
}

int __real_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx); 

int __wrap_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
{
    register int ret asm ("r12");
    register EVP_PKEY_CTX *ctx_parent asm ("r13");
    ctx_parent = ctx;
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_keygen_init(ctx_parent) ; 
    sdrad_exit(); 
    return ret;
}

BIGNUM *__real_BN_new();

BIGNUM *__wrap_BN_new()
{
    register BIGNUM *ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_BN_new(); 
    sdrad_exit(); 
    return ret;
}

int __real_BN_set_word(BIGNUM *a, unsigned long w); 

int __wrap_BN_set_word(BIGNUM *a, unsigned long w)
{
    register int ret asm ("r12");
    register BIGNUM *a_child asm("r13");
    register unsigned long w_child asm("r14");
    a_child = a; 
    w_child = w;
    sdrad_enter(OPENSSL_UDI);
    ret = __real_BN_set_word(a_child, w_child) ; 
    sdrad_exit(); 
    return ret;
}
/*
typedef struct {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *type;
    ENGINE *impl;
    unsigned char *key;
    unsigned char *iv;
 } EVP_EncryptInit_ex_t;

int __real_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, 
                        const EVP_CIPHER *type,
                        ENGINE *impl, 
                        const unsigned char *key, 
                        const unsigned char *iv);

int __wrap_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, 
                        const EVP_CIPHER *type,
                        ENGINE *impl, 
                        const unsigned char *key, 
                        const unsigned char *iv)
{
    register int ret asm ("r12");
    register EVP_EncryptInit_ex_t *out_data asm ("r13");
    out_data = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(EVP_EncryptInit_ex_t));
    out_data -> ctx = ctx;
    out_data -> type = type; 
    out_data -> impl = impl;
    if(key){
        out_data -> key = sdrad_malloc(OPENSSL_DATA_UDI, 32);
        memcpy(out_data -> key,key,32);
    }
    else{
        out_data -> key = key;
    }
    if(iv){
        out_data -> iv = sdrad_malloc(OPENSSL_DATA_UDI, 12);
        memcpy(out_data -> iv,iv,12);
    }
    else{
        out_data -> iv = iv;
    }

    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_EncryptInit_ex(out_data -> ctx, 
                                    out_data -> type, 
                                    out_data -> impl, 
                                    out_data -> key, 
                                    out_data -> iv); 
    sdrad_exit(); 
    return ret;
}
*/

int __real_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, 
                        const EVP_CIPHER *type,
                        ENGINE *impl, 
                        const unsigned char *key, 
                        const unsigned char *iv);

typedef struct {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *type; 
    unsigned char *key; 
    unsigned char *iv; 
    ENGINE *impl; 
    int ret;
 } EVP_EncryptInit_ex_t;


int __wrap_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, 
                        const EVP_CIPHER *type,
                        ENGINE *impl, 
                        const unsigned char *key, 
                        const unsigned char *iv)
{
    register EVP_EncryptInit_ex_t *input_arg asm ("r13");
    input_arg = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(EVP_EncryptInit_ex_t));
    register int ret asm ("r12");
    input_arg -> ctx = ctx; 
    input_arg -> impl = impl; 
    input_arg -> type = type; 
    input_arg -> key = key; 
    input_arg -> iv = iv; 

    sdrad_enter(OPENSSL_UDI);

    ret  = __real_EVP_EncryptInit_ex(input_arg -> ctx, input_arg -> type, input_arg -> impl,  input_arg -> key, input_arg -> iv); 
    sdrad_exit(); 
    return ret;
}

int __real_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv);

int __wrap_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv)
{
    register EVP_EncryptInit_ex_t *input_arg asm ("r13");
    input_arg = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(EVP_EncryptInit_ex_t));
    register int ret asm ("r12");
    input_arg -> ctx = ctx; 
    input_arg -> impl = impl; 
    input_arg -> type = type; 
    input_arg -> key = key; 
    input_arg -> iv = iv; 

    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_DecryptInit_ex(input_arg -> ctx, input_arg -> type, input_arg -> impl,  input_arg -> key, input_arg -> iv);  
    sdrad_exit(); 
    return ret;
}


typedef struct {
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cmd;
    int p1;
    void *p2;
 } EVP_CIPHER_CTX_ctrl_t;

 int __real_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, 
                                int cmd, int p1, void *p2);
 int __wrap_EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx,
                                int cmd, int p1, void *p2)
 {
    
    register int ret asm ("r12");
    register EVP_CIPHER_CTX_ctrl_t *out_data asm ("r13");
    out_data = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(EVP_CIPHER_CTX_ctrl_t));
    out_data -> ctx = ctx; 
    out_data -> cmd = cmd; 
    out_data -> p1 = p1; 

   if(p2)
    {
        out_data -> p2 = sdrad_malloc(OPENSSL_DATA_UDI, p1);
        memcpy(out_data -> p2, p2,p1); 
        
    }
    else
    {
        out_data -> p2 = p2;
    } 

    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_CIPHER_CTX_ctrl(out_data -> ctx, out_data -> cmd, out_data -> p1, out_data -> p2); 
    sdrad_exit(); 
    if(p2) memcpy(p2, out_data -> p2, p1);  /* copy results (e.g. GCM tag) back */
    return ret;
 }

void __real_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
void __wrap_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx)
{
    register EVP_CIPHER_CTX *ctx_out asm ("r12");
    ctx_out = ctx;
    sdrad_enter(OPENSSL_UDI);
    __real_EVP_CIPHER_CTX_free(ctx_out); 
    sdrad_exit(); 

}


typedef struct {
    EVP_CIPHER_CTX *ctx;
    int ret; 
    unsigned char *out_arg;
    unsigned char outl;
 } evp_encrypt_final_ex_t;

int __real_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
        int *outl);
int __wrap_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
        int *outl)
{
    register int ret asm ("r12");
    register evp_encrypt_final_ex_t *out_ptr asm ("r13");
    out_ptr = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(evp_encrypt_final_ex_t));
    out_ptr -> ctx = ctx;
    out_ptr -> out_arg = sdrad_malloc(OPENSSL_DATA_UDI,*outl);
    out_ptr -> outl = *outl;
    memcpy(out_ptr -> out_arg, outm, *outl);
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_DecryptFinal_ex(out_ptr -> ctx, out_ptr -> out_arg, &(out_ptr -> outl)); 
    sdrad_exit(); 
    return ret;
    
}


 
int __real_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int __wrap_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    register int ret asm ("r12");
    register evp_encrypt_final_ex_t *out_ptr asm ("r13");
    out_ptr = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(evp_encrypt_final_ex_t));
    out_ptr -> ctx = ctx;
    out_ptr -> out_arg = sdrad_malloc(OPENSSL_DATA_UDI,*outl);
    out_ptr -> outl = *outl;
    memcpy(out_ptr -> out_arg, out, *outl);
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_EncryptFinal_ex(out_ptr -> ctx, out_ptr -> out_arg, &(out_ptr -> outl)); 
    sdrad_exit(); 
    memcpy(out, out_ptr -> out_arg, *outl);
    outl = out_ptr -> outl;
    return ret;
}




/*
int __real_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int __wrap_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    register int ret asm ("r12");
    unsigned char *out_data_domain;
    unsigned char *in_data_domain;
    if(out){ //
        out_data_domain = sdrad_malloc(OPENSSL_DATA_UDI, (size_t)*outl); 
        in_data_domain = in; 
    }
    else
    {
        in_data_domain = sdrad_malloc(OPENSSL_DATA_UDI, (size_t)inl); 
        memcpy(in_data_domain, in, inl); 
    }

    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_EncryptUpdate(ctx, out_data_domain,
                                    outl, in_data_domain, inl);
    sdrad_exit(); 

    if(out)
    {
        memcpy(out, out_data_domain,(size_t)*outl); 
    }
    
    return ret;
} */

/*
typedef struct {
    int outl;
    unsigned char out[30];
 } evp_encrypt_update_out_data_t;
int __real_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int __wrap_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    register int ret asm ("r12");
    evp_encrypt_update_out_data_t *out_data;
    unsigned char *in_data;
    unsigned char *out_data_ex;
    int block_size;
    /* The amount of data written to outlen according to the OpenSSL API documentation at 
     * https://www.openssl.org/docs/man3.0/man3/EVP_EncryptUpdate.html (included above for
     * convenience) is (inl + cipher_block_size). We therefore need to obtain the block 
     * size from the provided ctx in order to be calculated the expected *outl in order to 
     * be able to allocate an appropriately sized buffer from the openssl_data domain
     * 
     * Technically we should check the return value of sdrad_enter() and
     * sdrad_exit() but I will omit that here to brevity. We can probably get
     * away with that in the listing as well to keep the listing short. */
/*    sdrad_enter(OPENSSL_UDI);
    ret = EVP_CIPHER_CTX_block_size(ctx);
    sdrad_exit();
    // Save block_size for later...
    block_size = ret;
    // .. and set ret zero, which indicates error (see above) so we can use it
    // as a return value in case we need to return early.
    ret = 0;
    /* Macros (that are not function-like macros) are commonly written in all
     * caps to distinguish them from variables. Therefore capitalizing
     * OPENSSL_DATA_UDI here improves readibility. 
     * 
     * Explicitly compare to NULL to improve readability and avoid ambiguity in
     * case of bugs where the comparison operator and operand are
     * unintentionally omitted.
     * 
     * We also need to do this allocation unconditionally now as it always
     * carries at least outl.
     * 
     * Total size of the allocation is 4 bytes for out_data.outl + inl + block_size obtained above. 
     * 
     * This is not a safe if the wrapper is called incorrectly with a negative
     * inl, but we can probably live without that check to keep the size of the
     * listing down.
     * */
/*    out_data = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(evp_encrypt_update_out_data_t) + inl + block_size+5);
    if (out_data == NULL) {
        goto err_out;
    }
    /* We allocate a separate buffer for in_data to ensure the wrapper works
     * even if it doesn't have access to the parent domain memory, e.g., if it's
     * called from a nested domain rather than the root domain. 
     * 
     * We make the decision whether the allocate the inbuf indepently of out
     * since we can simply check whether the caller provides a valid pointer and
     * a positive inlen. This is more robust than trying to infer whether or not
     * to expect a valid in value (the caller might call the wrapper
     * incorrectly, we don't want to SEGFAULT here due to a dereferencing a
     * null-pointer).
     * */
/*    if (in != NULL && inl >= 0) {
        in_data = sdrad_malloc(OPENSSL_DATA_UDI, (size_t)inl); 
        /* If sdrad_malloc() fails the eventual memcpy will dereference a null
         * pointer so we need to bail out here not to segfault. */
/*        if (in_data == NULL) {
            goto err_free;  // We might have allocated out_data earlier, need check whether we need to free it.
        }
        memcpy(in_data, in, inl); 
    }
    if(out)
    {
        out_data_ex = out_data -> out;
    }
    else
    {
        out_data_ex = NULL;
    }
    // Caps for macros.
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_EncryptUpdate(ctx,
                                   out_data_ex, &(out_data->outl),
                                   in_data, inl);
    sdrad_exit();
    if (out != NULL) {  // Let's use K&R brace placement to save a few newlines in the listing
        memcpy(out, out_data_ex,(size_t)out_data->outl);    
    }
    *outl = out_data->outl;  // Copy out outl
    /* Need to make sure we free in_data and in_data (below) if we
     * made allocations in the data domain earlier. Otherwise we leak memory
     * in the data domain as out_data and in_data go out of scope at the end
     * of the function. */
/*    if (in != NULL) {
        sdrad_free(OPENSSL_DATA_UDI, in_data);
    }
err_free:
    sdrad_free(OPENSSL_DATA_UDI, out_data);
err_out:
    return ret;
}

*/


typedef struct {
    EVP_CIPHER_CTX *ctx;
    int ret; 
    unsigned char *in_arg;
    unsigned char *out_arg;
    int outl;
    int inl; 
    unsigned char out[];
 } evp_decrypt_update_data_t;

int __real_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl, unsigned char *in, int inl);

int __wrap_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
        int *outl, unsigned char *in, int inl)
{
    register int ret asm ("r12");
    register evp_decrypt_update_data_t *data_ptr asm ("r13");
    data_ptr = sdrad_malloc(OPENSSL_DATA_UDI, sizeof(evp_decrypt_update_data_t));

    if(out)
        data_ptr -> out_arg = sdrad_malloc(OPENSSL_DATA_UDI, inl);
    else 
        data_ptr -> out_arg = out;
    data_ptr -> ctx = ctx;
    data_ptr -> in_arg = sdrad_malloc(OPENSSL_DATA_UDI, inl);
    data_ptr -> outl = outl; 
    data_ptr -> inl = inl; 
    memcpy(data_ptr -> in_arg, in, inl); 
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_DecryptUpdate(data_ptr -> ctx, data_ptr -> out_arg, &(data_ptr -> outl), data_ptr -> in_arg, data_ptr -> inl ); 
    sdrad_exit(); 
    *outl = data_ptr->outl;  // Copy out outl
    if(out)
        memcpy(out, data_ptr -> out_arg, *outl); 
    return ret;

}




typedef struct {
    int ret; 
    unsigned char *out_arg;
    int outl;
    unsigned char out[];
 } evp_encrypt_update_data_t;
int __real_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
int __wrap_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    register int ret  asm ("r12");
    register evp_encrypt_update_data_t *data_ptr asm ("r13");
    int cipher_block_size;
    /* The amount of data written to outlen according to the OpenSSL API documentation at 
     * https://www.openssl.org/docs/man3.0/man3/EVP_EncryptUpdate.html (included above for
     * convenience) is (inl + cipher_block_size). We therefore need to obtain the block 
     * size from the provided ctx in order to be calculated the expected *outl in order to 
     * be able to allocate an appropriately sized buffer from the openssl_data domain
     * 
     * Technically we should check the return value of sdrad_enter() and
     * sdrad_exit() but I will omit that here to brevity. We can probably get
     * away with that in the listing as well to keep the listing short. */
  
    sdrad_enter(OPENSSL_UDI);
    ret = EVP_CIPHER_CTX_block_size(ctx);
    sdrad_exit();
    // Save block_size for later...
    cipher_block_size = ret;
    // .. and set ret zero, which indicates error (see above) so we can use it
    // as a return value in case we need to return early.
    ret = 0;
    /* Macros (that are not function-like macros) are commonly written in all
     * caps to distinguish them from variables. Therefore capitalizing
     * OPENSSL_DATA_UDI here improves readibility. 
     * 
     * Explicitly compare to NULL to improve readability and avoid ambiguity in
     * case of bugs where the comparison operator and operand are
     * unintentionally omitted.
     * 
     * We also need to do this allocation unconditionally now as it always
     * carries at least outl.
     * 
     * Total size of the allocation is 4 bytes for out_data.outl + inl + block_size obtained above. 
     * 
     * This is not a safe if the wrapper is called incorrectly with a negative
     * inl, but we can probably live without that check to keep the size of the
     * listing down.
     * */
    int out_data_len = (out != NULL && inl >= 0) ? sizeof(evp_encrypt_update_data_t) + cipher_block_size + inl: sizeof(evp_encrypt_update_data_t);
    data_ptr = sdrad_malloc(OPENSSL_DATA_UDI, out_data_len);
    if (data_ptr == NULL) {
        goto err_out;
    }

    /* We allocate a separate buffer for in_data to ensure the wrapper works
     * even if it doesn't have access to the parent domain memory, e.g., if it's
     * called from a nested domain rather than the root domain. 
     * 
     * We make the decision whether the allocate the inbuf indepently of out
     * since we can simply check whether the caller provides a valid pointer and
     * a positive inlen. This is more robust than trying to infer whether or not
     * to expect a valid in value (the caller might call the wrapper
     * incorrectly, we don't want to SEGFAULT here due to a dereferencing a
     * null-pointer).
     * */
    // if (in != NULL && inl >= 0) {
    //     data_ptr -> in_arg = sdrad_malloc(OPENSSL_DATA_UDI, (size_t)inl); 
    //     /* If sdrad_malloc() fails the eventual memcpy will dereference a null
    //      * pointer so we need to bail out here not to segfault. */
    //    if (data_ptr -> in_arg == NULL) {
    //         goto err_free;  // We might have allocated out_data earlier, need check whether we need to free it.
    //     }
    //     memcpy(data_ptr -> in_arg, in, inl); 
    // } 
    //data_ptr -> inl = inl;
    data_ptr -> out_arg = (out != NULL) ? data_ptr->out : NULL;
    // Caps for macros.
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_EncryptUpdate(ctx,
                                   data_ptr -> out_arg, &(data_ptr -> outl),
                                   in, inl);
    sdrad_exit();
    *outl = data_ptr->outl;  // Copy out outl
    if (out != NULL) {  // Let's use K&R brace placement to save a few newlines in the listing
        memcpy(out, data_ptr -> out,(size_t)data_ptr ->outl);    
    }

    /* Need to make sure we free in_data and in_data (below) if we
     * made allocations in the data domain earlier. Otherwise we leak memory
     * in the data domain as out_data and in_data go out of scope at the end
     * of the function. */
    /*if (in != NULL) {
        sdrad_free(OPENSSL_DATA_UDI, data_ptr -> in_arg);
    }*/
err_free:
    sdrad_free(OPENSSL_DATA_UDI, data_ptr);
err_out:
    return ret;
}



EVP_PKEY_CTX * __real_EVP_PKEY_CTX_new(EVP_PKEY * pkey, ENGINE * e);
EVP_PKEY_CTX * __wrap_EVP_PKEY_CTX_new(EVP_PKEY * pkey, ENGINE * e)
{
    register EVP_PKEY_CTX *ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_CTX_new(pkey, e) ; 
    sdrad_exit(); 
    return ret;
}

int __real_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx); 

int __wrap_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx)
{
    register int ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_encrypt_init(ctx) ; 
    sdrad_exit(); 
    return ret;
}

int __real_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);

int __wrap_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    register int ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_encrypt(ctx, out, outlen, in,  inlen) ; 
    sdrad_exit(); 
    return ret;
}

int __real_BIO_dump_fp(FILE *fp, const char *s, int len); 

int __wrap_BIO_dump_fp(FILE *fp, const char *s, int len)
{
    register int ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_BIO_dump_fp(fp, s, len); 
    sdrad_exit(); 
    return ret;
}

EVP_PKEY *__real_EVP_PKEY_new(void);
EVP_PKEY *__wrap_EVP_PKEY_new(void)
{
    register int ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_new(); 
    sdrad_exit(); 
    return ret;
}


int __real_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);

int __wrap_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx)
{
    register int ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_decrypt_init(ctx) ; 
    sdrad_exit(); 
    return ret;
}


int __real_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen);
int __wrap_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen, const unsigned char *in, size_t inlen)
{
    register int ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
    sdrad_exit(); 
    return ret;
}

void __real_EVP_PKEY_CTX_free(EVP_PKEY_CTX * ctx); 

void __wrap_EVP_PKEY_CTX_free(EVP_PKEY_CTX * ctx)
{
    SDRAD_CALL(sub_active_domain, __real_EVP_PKEY_CTX_free, ctx); 
}


#if OPENSSL_VERSION_NUMBER >= 0x10101000L  /* not available in OpenSSL 1.1.0 */
int __real_RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2); 
int __wrap_RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    register int ret asm ("r12");
 /*   register int ctx_child asm ("r13") = ctx;
    register int optype_child asm ("r13") = optype;
    register int cmd_child asm ("r14") = cmd;
    register void *p2_child asm ("r15") = p2; */
    sdrad_enter(OPENSSL_UDI);
    ret = __real_RSA_pkey_ctx_ctrl(ctx, optype, cmd , p1, p2) ; 
    sdrad_exit(); 
    return ret;
}
#endif

EVP_CIPHER_CTX *__real_EVP_CIPHER_CTX_new(void);
EVP_CIPHER_CTX *__wrap_EVP_CIPHER_CTX_new(void)
{
    register EVP_CIPHER_CTX *ret asm ("r12");
    sdrad_enter(OPENSSL_UDI);
    ret = __real_EVP_CIPHER_CTX_new();
    sdrad_exit(); 
    return ret;
}