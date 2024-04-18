/**********************************************************************
 * This file contains the main code for data-owner
 * *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include "sr_info.h"
#include "do_debug.h"
#include "do_common.h"
#include "do_data_provision.h"
#include "do_tls_client_common.h"

SSL_CTX* g_ctx = nullptr;
SSL* g_ssl = nullptr;
int g_ssl_enc_sock = -1;
char g_recovered_nonce[NONCE_SZ] = {0};

void test_loopback_file_transfer()
{
    if(do_ssl_send_file(g_ssl, DO_SIGNED_ENC_PATH)){
        print_log(DEBUG_LEVEL_ERROR, "Error during sending the file: %s to the enclave through the established SSL connection\n", DO_SIGNED_ENC_PATH);

        return;
    }
    
    if(do_ssl_recv_file(g_ssl, "./materials/tmp.loopback")){
        print_log(DEBUG_LEVEL_ERROR, "Error during receiving the file: %s from the enclave through the established SSL connection\n" "./materials/tmp.loopback");

    }
        
    print_log(DEBUG_LEVEL_INFO, "Loopback test returned no error, please verify checksum of ./materials/tmp.loopback  and %s\n", DO_SIGNED_ENC_PATH);

    return;
}


int do_data_provision_stage(char* server_name, char* server_port)
{
    int ret = -1;
    int recv_data_sz;
    int nonce_sz;

    /* Establish TLS-communication with the enclave */
    if (do_start_tls_client(server_name, server_port, g_ssl_enc_sock, &g_ctx, &g_ssl) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during establishing TLS connection with enclave..!!\n");
        goto exit;
    }
        
    print_log(DEBUG_LEVEL_INFO, "Successfully established TLS connection with the enclave..!!\n");

#if 0 /* No need to send-receive nonce */
    /* Receive the encrypted nonce */
    recv_data_sz = do_ssl_recv_data(g_ssl, g_buffer);

    if(recv_data_sz <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during receiving the encrypted nonce");
        goto exit;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Successfully received the encrypted nonce from the enclave\n");
       
    /* Recover the plain-text nonce by applying the private key */ 
    if (do_pri_decrypt(g_do_pri_key_file, g_buffer, recv_data_sz, g_recovered_nonce, &nonce_sz) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during recover the plain-text nonce from the encrypted one..!!\n");
        goto exit;
    }

    print_log(DEBUG_LEVEL_INFO, "Successfully recovered the palintext nonce by using public key\n");

    /* Send the plain-text nonce */
    if (do_ssl_send_data(g_ssl, g_recovered_nonce, nonce_sz) <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during sending the plaintext-nonce..!!\n");
        goto exit;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Successfully sent the recovered nonce\n");

    /* Problem during reception of the acknowledgement  */
    if(do_ssl_recv_data(g_ssl, g_buffer) <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during receiving the acknowledgement from the enclave\n");
        goto exit;
    }
    else
    {
        if(strncmp("OK", g_buffer, 3) != 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during verification of the nonce\n");
            goto exit;
        }
    }
    
    print_log(DEBUG_LEVEL_INFO, "Enclave successfully verified the identity from recovered nonce\n");

    if (do_ssl_send_file(g_ssl, DO_RCV_DU_CERT_FILE) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during sending the data-users certificate\n");
        goto exit;
    }
    print_log(DEBUG_LEVEL_INFO, "Sent the data-user's certificate\n");
#endif
    
    /* Send the expiry time and the private data to the enclave */
    if (do_send_private_data_and_exp_tim(g_ssl) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error during sending the private data and expiry time..!!\n");
        goto exit;
    }

    ret = 0;
    
    print_log(DEBUG_LEVEL_INFO, "Successfully sent the certified private data and corresponding expiry timestamp to the enclave\n");
       
exit: 
    do_stop_tls_client(g_ssl_enc_sock, g_ctx, g_ssl);

    return ret;
}

int do_pri_decrypt(const char* pri_pem_path, const char* in_buf, int in_len, char* out_buf, int* p_out_len)
{
    int ret = -1;
    int ciphertext_len;
    FILE* fp = NULL;
    EVP_PKEY* pkey = NULL;
    int cert_sz;
        
    fp = fopen(g_do_pri_key_file,"rb");
    
    if(fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the private-key file\n");
        goto exit;
    }

    pkey = PEM_read_PrivateKey(fp, &pkey, NULL, NULL);
    
    if (pkey == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Failed to extract the pkey from the private-key pem file\n");
        goto exit;
    }
    
    if (do_decrypt_data(pkey, in_buf, in_len, out_buf, p_out_len) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Failed to decrypt\n");
        goto exit;
    }
    
    ret = 0;

exit:
    if (pkey != NULL)
    {
        EVP_PKEY_free(pkey);
    }

    if(fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

int do_decrypt_data(EVP_PKEY* pkey, const char* ctxt, int ctxt_len, char* ptxt, int* p_ptxt_len)
{
    int ret = -1;

    EVP_PKEY_CTX*ctx = EVP_PKEY_CTX_new(pkey,NULL);

    EVP_PKEY_decrypt_init(ctx);
    
    ret = EVP_PKEY_decrypt(ctx, (unsigned char*)ptxt, (size_t *)p_ptxt_len, (const unsigned char*)ctxt, ctxt_len);

    /* On FAILURE, it returns 0 */
    if(ret == 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Failed to decrypt\n");
        ret = -1;
    }
    else
    {
        if (LOG_LEVEL >= DEBUG_LEVEL_DUMP)
        {
            print_log(DEBUG_LEVEL_DUMP, "Decrypted plaintext length: %d, plaintext is:\n", *(p_ptxt_len));
            BIO_dump_fp(stdout,ptxt,(int)*(p_ptxt_len));
        }
            
        print_log(DEBUG_LEVEL_INFO, "Successfully decrypted\n");
        
        ret = 0;
    } 
    
    EVP_PKEY_CTX_free(ctx);
    
    return ret;
}

int do_send_private_data_and_exp_tim(SSL* ssl)
{
    int ret = -1;

    if (do_ssl_send_data(ssl, g_do_exp_tim, (strlen(g_do_exp_tim) + 1)) <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Failed to send the expiry time to the enclave\n");
        goto exit;
    }
        
    if (do_ssl_send_file(ssl, g_do_priv_data_file) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR,  "Failed to send the file containing certified private data to the enclave\n");
        goto exit;
    }
    
    ret = 0;

exit:
    return ret;
}
