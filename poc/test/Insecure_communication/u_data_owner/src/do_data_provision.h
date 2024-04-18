#ifndef DO_DATA_PROVISION
#define DO_DATA_PROVISION
#include <openssl/evp.h>                                                                         
#include <openssl/ssl.h>

#define NONCE_SZ    64/* This value should be same as the enclave side value */

int do_data_provision_stage(char* server_name, char* server_port);
int do_decrypt_data(EVP_PKEY* pkey, const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len);
int do_pri_decrypt(const char* pri_pem_path, const char* in_buf, int in_len, char* out_buf, int* p_out_len);
int do_send_private_data_and_exp_tim(SSL* ssl);

#endif
