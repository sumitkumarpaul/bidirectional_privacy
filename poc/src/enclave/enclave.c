/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL server demonstration program (with RA-TLS)
 * This program is originally based on an mbedTLS example ssl_server.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#define _GNU_SOURCE
#include "mbedtls/build_info.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <libxml/parser.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "mbedtls/base64.h"
#include <libxml/parser.h>
#include <libxml/tree.h>

#include <sgx_report.h>
#include "ra_tls.h"

#define ENCLAVE_LOG_LVL_ERROR 0
#define ENCLAVE_LOG_LVL_PERF_RSLT 1
#define ENCLAVE_LOG_LVL_MIN 2
#define ENCLAVE_LOG_LVL_INFO 3
#define ENCLAVE_LOG_LVL_ALL 4

unsigned int SAVED_LOG_LVL;
unsigned int ENCLAVE_LOG_LVL = ENC_DEF_LOG_LVL;

#define DEBUG_LEVEL 0

#define CA_CRT_PATH "ssl/ca.crt"
#define SRV_CRT_PATH "ssl/enclave.crt"
#define SRV_KEY_PATH "ssl/enclave.key"

#define BUF1_SZ 20480
#define BUF2_SZ 10240
#define FILE_BUF_SZ 102400
#define PRINT_BUF_SZ 1024
#define RSA_KEY_SZ 2048          /* Number of bits in the modulus */
#define RSA_KEY_EXP 65537        /* Keeping it same with the openssl's default value */
#define AES_BLK_SZ 16  
#define AD_KEY_FNAME "xmlrss/testdata/ad_public_key.pem"
#define TIMING_MEASUREMENT_ENDED 0
#define TIMING_MEASUREMENT_STARTED 1

static unsigned char buf1[BUF1_SZ];
static unsigned char buf2[BUF2_SZ];
static unsigned char file_buf[FILE_BUF_SZ];
static unsigned char print_buf[PRINT_BUF_SZ];
static unsigned int lcl_du_listening_port = 0;
static unsigned int ssl_server_listening_port = 0;
static unsigned int did = 0;
static mbedtls_net_context lcl_listen_fd;
static mbedtls_net_context lcl_client_fd;
static mbedtls_net_context ssl_server_listen_fd;
static mbedtls_net_context ssl_server_client_fd;
static mbedtls_net_context ssl_client_server_fd;
static unsigned int ENC_STATE = 0;
static unsigned int num_rcvd_code = 0;
static unsigned int next_did = 0;
static uint8_t *der_key = NULL;
static uint8_t *der_crt = NULL;
static bool g_verify_mrenclave = false;
static bool g_verify_mrsigner = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn = false;
static bool g_in_sgx = false;
static char attestation_type_str[32] = {0};
static char received_D_file[50];
static char received_D_enc_file[50];
static char received_PC_file[50];
static char DU_PC_file[50];
static char op_str[100];
static char saved_location_name[100];
static mbedtls_entropy_context ssl_server_entropy;
static mbedtls_ctr_drbg_context ssl_server_ctr_drbg;
static mbedtls_ssl_context ssl_server_ssl;
static mbedtls_ssl_config ssl_server_conf;
static mbedtls_x509_crt ssl_server_srvcert;
static mbedtls_pk_context ssl_server_pkey;
static mbedtls_entropy_context ssl_client_entropy;
static mbedtls_ctr_drbg_context ssl_client_ctr_drbg;
static mbedtls_ssl_context ssl_client_ssl;
static mbedtls_ssl_config ssl_client_conf;
static mbedtls_x509_crt ssl_client_cacert;
static unsigned int eid;//enclave id
struct timeval start_tv;
struct timeval end_tv;
unsigned int total_tim;
FILE *perf_log_fp = NULL;
static unsigned char DUMMY_KEY[32] = "12345678901234567890123456789012"; // 32 bytes for AES-256
static unsigned char DUMMY_IV[16] = "1234567890123456"; // 16 bytes for AES block size
static unsigned char aes_input_blk[AES_BLK_SZ];
static unsigned char aes_output_blk[AES_BLK_SZ];

unsigned int timing_measurement_state = TIMING_MEASUREMENT_ENDED;
static void *ra_tls_attest_lib;
static void *ra_tls_verify_lib;
static int (*ra_tls_create_key_and_crt_der_f)(uint8_t **der_key, size_t *der_key_size, uint8_t **der_crt, size_t *der_crt_size);
static int (*ra_tls_verify_callback_extended_der_f)(uint8_t *der_crt, size_t der_crt_size, struct ra_tls_verify_callback_results *results);
static void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn));

static void print_hex(const char *title, const unsigned char buf[], size_t len);
static int sha256_file(const char *file_path, mbedtls_sha256_context *ctx, unsigned char *sha256_buf, unsigned int real_file_sz);
static int ssl_recv_padded_file(mbedtls_ssl_context *p_ssl, const char *file_path, unsigned int *p_real_file_sz);
static xmlNode *xml_get_element_by_path(xmlNode *root, xmlChar *path);
static void bin_to_hex(const unsigned char buf[], size_t len, unsigned char *op_buf);
static int file_copy(const char *source_file, const char *target_file);
static int S_VfH(char *hash_buf, const unsigned char *pub_key_buf, size_t keylen, char *sign_buf, size_t sign_sz);
static int S_VfB(const char *data_buf, size_t data_sz, const unsigned char *pub_key_buf, size_t keylen, char *sign_buf, size_t sign_sz);
static int S_VfF(const char *data_fname, const unsigned char *pub_key_buf, size_t keylen, char *sign_buf, size_t sign_sz);
static int S_SigF(const char *data_fname, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen);
static int S_SigB(const char *data_buf, size_t data_sz, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen);
static int S_SigH(char *hash_buf, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen);
static int AE_Kgen(char *pk_buf, size_t pk_buf_sz, size_t *o_pk_sz, char *sk_buf, size_t sk_buf_sz, size_t *o_sk_sz);
static int AE_Enc_buf(const char *pk_buf, size_t pk_sz, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t max_olen);
static int AE_Dec_buf(const char *sk_buf, size_t sk_sz, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen, size_t max_olen);
static int read_all_children(xmlNode *node, char *buf, size_t max_buf_siz);
static void parse_pdsrem(char *str, unsigned int *p_list_sz, unsigned int *list);
static int prepare_FPC_file(char *FPC_fname, unsigned int rem_list[], unsigned int rem_list_sz, char *D_fname);
static int com_ch_init(const char *local_port);
static void com_ch_fin();
static void execute_commands();
static int lcl_du_if_init(const char *port);
static void lcl_du_if_fin();
static int ssl_server_init();
static void ssl_server_fin();
static int lcl_du_con_accept();
static void lcl_du_con_close();
static int ssl_server_con_accept();
static void ssl_server_con_close();
static int execute_Process(unsigned int did, unsigned int S_ID, unsigned int *result);
static int execute_SaveData(unsigned int *pdid);
static int execute_PrepFrd(const char *DU_IP, const char *enc_port, int did, unsigned int rem_list[], unsigned int rem_list_sz);
static int execute_TEESetup(const char *pds_file_name, const char *CP_IP, const char *CP_PORT);
static int execute_SetKey();
static void enclave_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...);
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
static int ssl_client_connect(const char* IP, const char* port);
static void ssl_client_close();
static int my_verify_measurements(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn);
static int my_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
static int ssl_write_data(mbedtls_ssl_context *p_ssl, char *write_buf, int write_len);
static int ssl_read_data(mbedtls_ssl_context *p_ssl, char *read_buf, int max_read_len);
static ssize_t read_dev_file(const char *path, char *buf, size_t count);
static ssize_t write_dev_file(const char *path, char *buf, size_t count);
static int ssl_recv_file(mbedtls_ssl_context *p_ssl, const char *file_path);
static int ssl_send_file(mbedtls_ssl_context *p_ssl, const char *file_path);
static int VerifyAndSave();
static void end_timing();
static void start_timing();
static void aes_encrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, unsigned char *iv);
static void aes_decrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, unsigned char *iv);



int main(int argc, char **argv)
{
    int ret;
    size_t sign_len;
    size_t pk_sz;
    size_t sk_sz;
    size_t clen;
    size_t plen;

    /* Use the pid to identify the enclave */
    eid = getpid();

    if (argc < 2)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Running instruction: [gramine-sgx] ./enclave <sgx/non-sgx> <local listening port>\n");
    } else {
        if (!strcmp(argv[2], "sgx"))
        {
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Running the enclave in sgx mode\n");
            g_in_sgx = true;
        } else {
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Running the enclave in non-sgx mode\n");
            
        }
    }

    ret = com_ch_init(argv[1]);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to initialize the communication channel between the enclave and the outer world..!!\n");
        goto exit;
    }

    execute_commands();

exit:
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Destroying the enclave..!!\n");

    com_ch_fin();
    fflush(stdout);

    return ret;
}

/// @brief Initialize the TCP server for receiving commands from the hosting DU
/// @param local_port Listening port in string format
/// @return 0: In case of success
///         non-zero: Otherwise
static int com_ch_init(const char *local_port)
{
    int ret;

    ret = lcl_du_if_init(local_port);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed setting up the local TCP communication interface with the hosting DU..!!\n");
        goto exit;
    }

    ret = lcl_du_con_accept();

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to listen on the local TCP interface with DU..!!\n");
        goto exit;
    }

exit:
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Destroying the local TCP interface with DU..!!\n");
        com_ch_fin();
    }

    return ret;
}

/// @brief Finalizes the already created TCP server for receiving commands from the hosting DU
static void com_ch_fin()
{
    lcl_du_con_close();
    lcl_du_if_fin();

    return;
}

/// @brief After receiving commands from DU, this function channelizes them to proper dedicated functions
static void execute_commands()
{
    int ret;
    unsigned int result;
    unsigned int did;
    char *tok;

    if (g_in_sgx == true)
    {
        ret = read_dev_file("/dev/attestation/attestation_type", attestation_type_str,
                            sizeof(attestation_type_str) - 1);
        if (ret < 0 && ret != -ENOENT)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "User requested RA-TLS attestation but cannot read SGX-specific file "
                                                      "/dev/attestation/attestation_type\n");
            g_in_sgx == false;
            return;
        }
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Listening for commands from local DU..\n");

    while (1)
    {
        ret = mbedtls_net_recv(&lcl_client_fd, buf1, BUF1_SZ);

        if (ret <= 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during command reception from DU. Error is: %d\n", ret);
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Stopping command processing..\n");
            break;
        }

        /* Init is the combination of SetKey() and TEESetup() */
        if (strncmp(buf1, "Init", strlen("Init")) == 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Started executing Init\n");

            start_timing();

            ret = execute_SetKey();

            if (ret == 0)
            {
                /* Command: TEESetup, <pds file-path>, <IP-address of CP>, <Port of CP> */
                char setup_filename[] = "./pds.xml";
                char CP_IP[] = "127.0.0.1";
                char CP_PORT[] = "4321";
                ret = execute_TEESetup(setup_filename, CP_IP, CP_PORT);
            
                if (ret == 0)
                {
                    sprintf(op_str, "OK\n");
                }
                else
                {
                    sprintf(op_str, "Not-OK, during TEESetup error is: %d\n", ret);
                }
            }
            else
            {
                sprintf(op_str, "Not-OK, during SetKey error is: %d\n", ret);
            }

            end_timing();
            
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended executing Init\n");
        }
        else if (strncmp(buf1, "SetKey", strlen("SetKey")) == 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Started executing SetKey\n");
            
            start_timing();
            
            ret = execute_SetKey();

            if (ret == 0)
            {
                sprintf(op_str, "OK\n");
            }
            else
            {
                sprintf(op_str, "Not-OK, error is: %d\n", ret);
            }

            end_timing();

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended executing SetKey\n");
        }
        else if (strncmp(buf1, "TEESetup", strlen("TEESetup")) == 0)
        {
            /* Command: TEESetup, <pds file-path>, <IP-address of CP>, <Port of CP> */
            char setup_filename[] = "./pds.xml";
            char CP_IP[] = "127.0.0.1";
            char CP_PORT[] = "4321";

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Started executing TEESetup\n");
            start_timing();
            ret = execute_TEESetup(setup_filename, CP_IP, CP_PORT);
            
            if (ret == 0)
            {
                sprintf(op_str, "OK\n");
            }
            else
            {
                sprintf(op_str, "Not-OK, error is: %d\n", ret);
            }
            
            end_timing();
            
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended executing TEESetup\n");
        }
        else if (strncmp(buf1, "PrepFrd", strlen("PrepFrd")) == 0)
        {
            unsigned int did;
            unsigned int rem_list_sz;
            unsigned int rem_list[100]; // No more than 100 statements within PDS[] is allowed in this implementation
            char remote_DU_IP[16];
            char remote_enc_port[6];

            /* The command sould be something like "PrepFrd, <IP of remote DU>, <Listening port of remote enclave>, <did>, [list of IDs]" */
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Started executing PrepFrd\n");

            start_timing();

            /* First token is always "PrepFrd" */
            tok = strtok(buf1, ",");

            if (tok == NULL)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the \"PrepFrd\" command\n");
                ret = -1;
            }
            else
            {
                tok = strtok(NULL, ",");
            }

            if ((tok == NULL) || (ret == -1))
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the IP of the remote DU\n");
                ret = -1;
            }
            else
            {
                strncpy(remote_DU_IP, tok, 16);
                tok = strtok(NULL, ",");
            }

            if ((tok == NULL) || (ret == -1))
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the port of the remote enclave\n");
                ret = -1;
            }
            else
            {
                strncpy(remote_enc_port, tok, 6);
                tok = strtok(NULL, ",");
            }

            if ((tok == NULL) || (ret == -1))
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the did\n");
                ret = -1;
            }
            else
            {
                did = atoi(tok);
                tok = strtok(NULL, "[");
            }

            if ((tok == NULL) || (ret == -1))
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the start of PDS_{rem}[]\n");
                ret = -1;
            }
            else
            {
                /* Received token till now is: [ */
                /* Next token could be , or ] */
                parse_pdsrem(tok, rem_list, &rem_list_sz);
            }

            if (ret != -1)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_MIN, 1, "Forwarding data (did: %d) after removing: %d data processing statements\n", did, rem_list_sz);
                ret = execute_PrepFrd(remote_DU_IP, remote_enc_port, did, rem_list, rem_list_sz);
            }

            if (ret == 0)
            {
                sprintf(op_str, "OK\n");
            }
            else
            {
                sprintf(op_str, "Not-OK, error is: %d\n", ret);
            }

            end_timing();

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended executing PrepFrd\n");
        }
        else if (strncmp(buf1, "SaveData", strlen("SaveData")) == 0)
        {
            start_timing();

            ret = execute_SaveData(&did);

            if (ret == 0)
            {
                sprintf(op_str, "did: %d\n", did);
            }
            else
            {
                sprintf(op_str, "Not-OK, error is: %d\n", ret);
            }

            if (g_in_sgx == true)
            {
                end_timing();
            }
        }
        else if (strncmp(buf1, "Process", strlen("Process")) == 0)
        {
            unsigned int did, S_ID;
            unsigned int result;

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Started executing Process\n");
            start_timing();
            
            /* First token is always "Process" */
            tok = strtok(buf1, ",");

            if (tok == NULL)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the \"Process\" command\n");
                ret = -1;
            }
            else
            {
                tok = strtok(NULL, ",");
            }

            if ((tok == NULL) || (ret == -1))
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the did\n");
                ret = -1;
            }
            else
            {
                did = atoi(tok);
                tok = strtok(NULL, ",");
            }

            if ((tok == NULL) || (ret == -1))
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while parsing the S_ID\n");
                ret = -1;
            }
            else
            {
                S_ID = atoi(tok);
            }

            if (ret != -1)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Starting execution: did = %d, S_ID = %d\n", did, S_ID);
                
                /* For testing, use these parameters. Depending on the situation the content and number of data elements in xml file will change */
                ret = execute_Process(did, S_ID, &result);

                enclave_print_log(ENCLAVE_LOG_LVL_MIN, 1, "Processed data (did: %d) according to processing statement ID: %d, the result is: %u\n", did, S_ID, result);
            }

            if (ret == 0)
            {
                sprintf(op_str, "result: %u\n", result);
            }
            else
            {
                sprintf(op_str, "Not-OK, error is: %d\n", ret);
            }

            end_timing();

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended executing Process\n");
        }
        else if (strncmp(buf1, "Finalize", strlen("Finalize")) == 0)
        {
            char pathname[100];
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Received command for finalization of the enclave\n");

            {
                /* Delete already received code */
                for (int i = 0; i < num_rcvd_code; i++)
                {
                    sprintf(pathname, "./enc/%d/code_%d.so", ssl_server_listening_port, i);
                    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing the dynamic library file: %s\n", pathname);
                    (void)remove(pathname);
                }
            }

            {
                /* Delete already received data and consents */
                for (int i = 0; i < next_did; i++)
                {
                    /* Removing the D-files from enclave's storage*/
                    sprintf(pathname, "./enc/%d/D_%d.xml", ssl_server_listening_port, i);
                    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing the D file: %s\n", pathname);
                    (void)remove(pathname);

                    /* Remove the performance measurement related file as well */
                    if (g_in_sgx == false) {
                        /* Removing the D-files from enclave's storage*/
                        sprintf(pathname, "./enc/%d/D_%d.xml.enc", ssl_server_listening_port, i);
                        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing the D file: %s\n", pathname);
                        (void)remove(pathname);
                    }

                    /* Removing the PC-files from enclave's storage */
                    sprintf(pathname, "./enc/%d/PC_%d.xml", ssl_server_listening_port, i);
                    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing thePC file: %s\n", pathname);
                    (void)remove(pathname);

                    /* Removing the PC-files from DU's storage */
                    sprintf(pathname, "./DU_storage/%d/PC_%d.xml", ssl_server_listening_port, i);
                    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing the PC file: %s\n", pathname);
                    (void)remove(pathname);                  
                }
            }

            {
                /* Remove performance log file */
                sprintf(pathname, "./DU_storage/%d/enc_perf.log", ssl_server_listening_port);
                enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing the performance log file: %s\n", pathname);
                (void)remove(pathname);                  
            }

            /* Remove the empty folder at the end */
            sprintf(pathname, "./enc/%d/", ssl_server_listening_port);
            (void)remove(pathname);

            /* Removing the FPC-files from DU's storage */
            sprintf(pathname, "./DU_storage/%d/FPC.xml", ssl_server_listening_port);
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Removing the FPC file: %s\n", pathname);
            (void)remove(pathname);  

            sprintf(pathname, "./DU_storage/%d/", ssl_server_listening_port);
            (void)remove(pathname);
                        
            break;
        }
        else
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Received unknown command: %s\n", buf1); // Sumit may happen buffer overflow
            ret = -1;
        }

        mbedtls_net_send(&lcl_client_fd, op_str, strlen(op_str));
    }

    return;
}

/// @brief Inits and binds the port for com_ch_init()
/// @param port Listening port in string format
/// @return 0: In case of success
///         non-zero: Otherwise
static int lcl_du_if_init(const char *port)
{
    int ret;

    mbedtls_net_init(&lcl_listen_fd);

    ret = mbedtls_net_bind(&lcl_listen_fd, "localhost", port, MBEDTLS_NET_PROTO_TCP);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Successfully bounded the local interface with TCP port: %s\n", port);

    lcl_du_listening_port = atoi(port);
exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Last error was: %d - %s\n\n", ret, error_buf);
#endif
        lcl_du_if_fin();
    }

    return ret;
}

/// @brief Frees the socket used for communicating with local DU
static void lcl_du_if_fin()
{
    mbedtls_net_free(&lcl_listen_fd);

    return;
}

/// @brief Initializes an SSL server on the port: (lcl_du_listening_port + 1)
/// @return 0: In the case of success
///error code: Otherwise
static int ssl_server_init()
{
    int ret;
    const char *pers = "ssl_server";
    char port[6] = {0};

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&ssl_server_listen_fd);
    mbedtls_ssl_init(&ssl_server_ssl);
    mbedtls_ssl_config_init(&ssl_server_conf);
    mbedtls_x509_crt_init(&ssl_server_srvcert);
    mbedtls_pk_init(&ssl_server_pkey);
    mbedtls_entropy_init(&ssl_server_entropy);
    mbedtls_ctr_drbg_init(&ssl_server_ctr_drbg);

    // SSL's port must be one more than the local DU's port
    ssl_server_listening_port = lcl_du_listening_port + 1;
    sprintf(port, "%d", ssl_server_listening_port);

    /* Create a directory for storing all the required objects for this enclave */
    sprintf(saved_location_name, "./DU_storage/%d/", ssl_server_listening_port);
    ret = mkdir(saved_location_name, 0777);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not create the director: %s\n", saved_location_name);
        ret = -1;
        goto exit;
    }

    if ((g_in_sgx == false) || (!strcmp(attestation_type_str, "none")))
    {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    }
    else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap"))
    {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }

        char *error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "%s\n", error);
            return 1;
        }
    }
    else
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Seeding the random number generator...\n");

    ret = mbedtls_ctr_drbg_seed(&ssl_server_ctr_drbg, mbedtls_entropy_func, &ssl_server_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    if (ra_tls_attest_lib)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Creating the RA-TLS enclave cert and key (using \"%s\" as "
                                                  "attestation type)...",
                          attestation_type_str);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&ssl_server_srvcert, (unsigned char *)der_crt, der_crt_size);
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&ssl_server_pkey, (unsigned char *)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ssl_server_ctr_drbg);
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }
    }
    else
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Creating normal enclave cert and key...");

        ret = mbedtls_x509_crt_parse_file(&ssl_server_srvcert, SRV_CRT_PATH);
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse_file(&ssl_server_srvcert, CA_CRT_PATH);
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_keyfile(&ssl_server_pkey, SRV_KEY_PATH, /*password=*/NULL,
                                       mbedtls_ctr_drbg_random, &ssl_server_ctr_drbg);
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
            goto exit;
        }

        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Bind on https://localhost:%s/ ...", port);

    ret = mbedtls_net_bind(&ssl_server_listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Setting up the SSL data....");

    ret = mbedtls_ssl_config_defaults(&ssl_server_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&ssl_server_conf, mbedtls_ctr_drbg_random, &ssl_server_ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_server_conf, ssl_debug, stdout);

    if (!ra_tls_attest_lib)
    {
        /* no RA-TLS attest library present, use embedded CA chain */
        mbedtls_ssl_conf_ca_chain(&ssl_server_conf, ssl_server_srvcert.next, NULL);
    }

    ret = mbedtls_ssl_conf_own_cert(&ssl_server_conf, &ssl_server_srvcert, &ssl_server_pkey);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl_server_ssl, &ssl_server_conf);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Last error was: %d - %s\n\n", ret, error_buf);
#endif
        ssl_server_fin();
    }

    return ret;
}

/// @brief Finalizes the already initialized ssl server
static void ssl_server_fin()
{
    if (ra_tls_attest_lib)
    {
        dlclose(ra_tls_attest_lib);
    }

    mbedtls_net_free(&ssl_server_client_fd);
    mbedtls_net_free(&ssl_server_listen_fd);

    mbedtls_x509_crt_free(&ssl_server_srvcert);
    mbedtls_pk_free(&ssl_server_pkey);
    mbedtls_ssl_free(&ssl_server_ssl);
    mbedtls_ssl_config_free(&ssl_server_conf);
    mbedtls_ctr_drbg_free(&ssl_server_ctr_drbg);
    mbedtls_entropy_free(&ssl_server_entropy);

    free(der_key);
    der_key = NULL;

    free(der_crt);
    der_crt = NULL;

    return;
}

/// @brief Accept TCP connection from local DU
/// @return 0: In the case of success
///Error code: Otherwise
static int lcl_du_con_accept()
{
    int ret;
    size_t len;

    mbedtls_net_init(&lcl_client_fd);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Waiting for a connection with local DU...\n");

    ret = mbedtls_net_accept(&lcl_listen_fd, &lcl_client_fd, NULL, 0, NULL);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " Established TCP connection with local DU\n");

exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Last error was: %d - %s\n\n", ret, error_buf);
#endif
        lcl_du_con_close();
    }

    return ret;
}

/// @brief Closes the TCP connection with local DU
static void lcl_du_con_close()
{
    mbedtls_net_free(&lcl_client_fd);

    return;
}

/// @brief Accepts a SSL connection from remote enclave or DO
/// @return 0: In the case of success
///Error code: Otherwise
static int ssl_server_con_accept()
{
    int ret;
    size_t len;

    mbedtls_net_init(&ssl_server_client_fd);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Waiting for a remote connection from a ssl client...");

    ret = mbedtls_net_accept(&ssl_server_listen_fd, &ssl_server_client_fd, NULL, 0, NULL);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_server_ssl, &ssl_server_client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_server_ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto exit;
        }
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " Established SSL connection with remote ssl client\n");

    ret = 0;

exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Last error was: %d - %s\n\n", ret, error_buf);
#endif
        ssl_server_con_close();
    }

    return ret;
}

/// @brief Closes the SSL server
static void ssl_server_con_close()
{
    int ret;
    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Closing the ssl connection...\n");

    (void)mbedtls_ssl_close_notify(&ssl_server_ssl);

    mbedtls_ssl_session_reset(&ssl_server_ssl);
    mbedtls_net_free(&ssl_server_client_fd);

    return;
}

/// @brief Code corresponds to SetKey() entry point of the algorithm
/// @return 0: In the case of success
///        -1: Otherwise
static int execute_SetKey()
{
    int ret = -1;

    if (ENC_STATE != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot execute: %s, current state of enclave is: %d\n", __func__, ENC_STATE);
        goto exit;
    }

    ret = ssl_server_init();

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed setting up the ssl communication interface with the remote parties..!!\n");
        ssl_server_fin();
    }

    ret = 0;
    ENC_STATE = 1;

exit:
    return ret;
}

/// @brief Code corresponds to TEESetup() entry point of the algorithm
/// @param pds_file_name Filename corresponding to the input pds[]
/// @param CP_IP During setup, enclave has to communicate with the code-provider. Listning IP of the code provider
/// @param CP_PORT Listning port of the code provider
/// @return 0: In the case of success
///        -1: Otherwise
static int execute_TEESetup(const char *pds_file_name, const char *CP_IP, const char *CP_PORT)
{
    int ret = -1;
    unsigned char sha256_buf[32];
    mbedtls_sha256_context sha256_ctx;
    unsigned int real_file_sz;
    int num_pd;
    int req_sz;
    xmlDocPtr doc = NULL;
    xmlNode *root_element = NULL;
    size_t S_len;
    size_t olen;
    xmlNode *node = NULL;
    xmlNode *pd_node = NULL;
    xmlNode *S_node = NULL;
    xmlNode *CH_node = NULL;
    xmlNode *AS_node = NULL;
    xmlChar xmlPath[100];
    unsigned char ad_pub_key_buf[1024];
    int ad_keylen = 0;
    unsigned int i;
    static mbedtls_net_context cp_client_fd;
    FILE *ad_key_fp = NULL;
    int is_connected = 0;
    char port[6] = {0};

    if (ENC_STATE != 1)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot execute: %s, current state of enclave is: %d\n", __func__, ENC_STATE);
        goto exit;
    }

    ad_key_fp = fopen(AD_KEY_FNAME, "rb");

    if (ad_key_fp == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot open: %s\n", AD_KEY_FNAME);
        goto exit;
    }

    ad_keylen = fread(ad_pub_key_buf, 1, sizeof(ad_pub_key_buf), ad_key_fp);
    /* For including the terminating NULL byte, as per the requirement of mbedtls_pk_parse_public_key() */
    ad_pub_key_buf[ad_keylen] = '\0';
    ad_keylen++;    
    /* Create a directory for storing all the required objects for this enclave */
    sprintf(saved_location_name, "./enc/%d/", ssl_server_listening_port);
    ret = mkdir(saved_location_name, 0777);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not create the director: %s\n", saved_location_name);
        ret = -1;
        goto exit;
    }

    /* Connect with CP, over TCP interface */
    mbedtls_net_init(&cp_client_fd);

    /* In real situation, there might be different CP for different codes */
    ret = mbedtls_net_connect(&cp_client_fd, CP_IP, CP_PORT, MBEDTLS_NET_PROTO_TCP);

    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed to connect with CP\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, " Connected with CP\n");

    /*parse the file and get the DOM */
    doc = xmlReadFile(pds_file_name, NULL, 0);

    if (doc == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "error: could not parse file %s\n", pds_file_name);
        ret = -1;
        goto exit;
    }
    strcpy((char *)xmlPath, "PC/PDS/");

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);
    node = xml_get_element_by_path(root_element, xmlPath);

    sprintf(port, "%d", ssl_server_listening_port);

    if (node != NULL)
    {
        num_pd = xmlChildElementCount(node);
        pd_node = xmlFirstElementChild(node);

        enclave_print_log(ENCLAVE_LOG_LVL_MIN, 1, "Started executing setup with: %d proposed data-processing statements\n", num_pd);

        for (i = 0; i < num_pd; i++)
        {
            S_node = xmlFirstElementChild(pd_node);   // Points to pd_i.S
            CH_node = xmlNextElementSibling(S_node);  // Points to pd_i.CH
            AS_node = xmlNextElementSibling(CH_node); // Points to pd_i.AS

            /* Prepare the command for obtaining a particular code */
            /* Note: Do not put any <space> in the command */
            req_sz = sprintf(buf1, "GetCode,%d,%s,%s", i, CP_IP, port);

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Warning: For experimental purpose, always request for code 0\n");

            /* Send request for a particular code over the TCP connection */
            ret = mbedtls_net_send(&cp_client_fd, buf1, req_sz);

            if (ret != req_sz)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed to send request to CP during obtaing the code having id: %d\n  ! mbedtls_net_connect returned %d\n\n", i, ret);
                goto exit;
            }

            if (is_connected == 0)
            {
                /* Open a new SSL server for receiving the code */
                ret = ssl_server_con_accept();

                if (ret < 0)
                {
                    enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed to accept connection returned %d\n\n", ret);
                    goto exit;
                }

                is_connected = 1;

                enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, " Connected via SSL connection\n");
            }

            /* Receive so-many files from CP */
            sprintf(saved_location_name, "./enc/%d/code_%d.so", ssl_server_listening_port, i);

            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, " Started receiving file %s\n", saved_location_name);
           
            /* Receive the dynamic libary corresponding to S_ID */
            ret = ssl_recv_padded_file(&ssl_server_ssl, saved_location_name, &real_file_sz);

            if (ret < 0)
            {
                goto exit;
            }
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, " Receive complete\n");

            /* TODO: Chance of performance improvement, receiving the chunk obin_to_hexf a file and simultaneously update of sha256 can be */
            mbedtls_sha256_starts(&sha256_ctx, 0); /* SHA-256, not 224 */
            ret = sha256_file(saved_location_name, &sha256_ctx, sha256_buf, real_file_sz);

            if (ret < 0)
            {
                goto exit;
            }

            mbedtls_sha256_finish(&sha256_ctx, sha256_buf);
            bin_to_hex(sha256_buf, 32, file_buf);
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, " Hash calculation complete\n");

            /* First 64-bytes contains the hash of the code in hexa decimal format. The size of each statement is fixed and it is 500 butes */
            S_len = xmlStrlen(xmlNodeGetContent(S_node));
            memcpy(&file_buf[64], (const char *)xmlNodeGetContent(S_node), S_len);

            if (mbedtls_base64_decode(buf1, BUF1_SZ, &olen, (const char *)xmlNodeGetContent(AS_node), xmlStrlen(xmlNodeGetContent(AS_node))) != 0)
            {
                goto exit;
            }

            /* During the generation of the signature using linux-command, line-feed(decimal value 10) is inserted at
             the end of the buffer. So, here also adding that at the end */
            file_buf[S_len + 64] = 10;
            ret = S_VfB(file_buf, (S_len + 64 + 1), ad_pub_key_buf, ad_keylen, buf1, olen);

            enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "AS-signature verification complete, return: %d\n", ret);

            if (ret != 0)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "For code: %s, return after verification of auditor's signature is: %d\n", i, ret);
                goto exit;
            }
            else
            {
                num_rcvd_code++;
            }

            pd_node = xmlNextElementSibling(pd_node);
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, " Ended processing file %s\n", saved_location_name);
        }

        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, " Received %d code components from the CP\n", num_rcvd_code);
    }
    else
    {
        goto exit;
    }

    ret = 0;
    ENC_STATE = 2;
    is_connected = 0;

exit:
    req_sz = sprintf(buf1, "CloseCP");

    /* Send request to CP for closing the connection */
    (void)mbedtls_net_send(&cp_client_fd, buf1, req_sz);

    ssl_server_con_close();
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);
    mbedtls_sha256_free(&sha256_ctx);
    /* Delete created TCP connection with CP */
    mbedtls_net_free(&cp_client_fd);
    /*free the document */
    xmlFreeDoc(doc);
    fclose(ad_key_fp);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return ret;
}

/// @brief Remove specific consents and forward to another DU
/// @param DU_IP IP address of the remote DU
/// @param enc_port Port number for the listning enclave in string format
/// @param did did to be forwarded
/// @param rem_list The elements, which are to be removed fro PDS[]
/// @param rem_list_sz Number of elements present within the previous list
/// @return 0: In the case of success
///        -1: In the case of failure
static int execute_PrepFrd(const char *DU_IP, const char *enc_port, int did, unsigned int rem_list[], unsigned int rem_list_sz)
{
    int ret = -1;
    char src_PC_fname[100];
    char src_D_fname[100];
    char FPC_fname[100];

    if (ENC_STATE != 2)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot execute: %s, current state of enclave is: %d\n", __func__, ENC_STATE);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Started SSL connection establishment with child enclave\n");
    ret = ssl_client_connect(DU_IP, enc_port);
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Competed SSL connection establishment with child enclave\n");

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 0, "Error while connecting with the enclave. Ret = %d\n", ret);
        goto exit;
    }

    sprintf(src_PC_fname, "./enc/%d/PC_%d.xml", ssl_server_listening_port, did);
    sprintf(src_D_fname, "./enc/%d/D_%d.xml", ssl_server_listening_port, did);
    sprintf(FPC_fname, "./DU_storage/%d/FPC.xml", ssl_server_listening_port);    

    ret = file_copy(src_PC_fname, FPC_fname);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "File copy problem, to: %s from: %s\n", src_PC_fname, FPC_fname);
        ret = -1;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "RSS-like redaction operation start\n");
    /* Remove the specified elements from the FPC and update FPC.SC */
    ret = prepare_FPC_file(FPC_fname, rem_list, rem_list_sz, src_D_fname);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem during consent preparation\n");
        ret = -1;
    }
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "RSS-like redaction operation end\n");

    ret = ssl_send_file(&ssl_client_ssl, src_D_fname);
    
    if (ret < 0) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while sending D to the remote enclave\n");        
        goto exit;
    }

    ret = ssl_send_file(&ssl_client_ssl, FPC_fname);
    
    if (ret < 0) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while sending PC to the remote enclave\n");        
        goto exit;
    }

    /* Try read the OK message from the receiving enclave */
    do
    {
        ret = ssl_read_data(&ssl_client_ssl, buf1, BUF1_SZ);

        if (ret < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while receiving the OK message from the enclave\n");
            goto exit;
        }
    } while (ret == 0);

    if (strcmp(buf1, "OK\n") != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Received a message from the enclave, but that is not an OK message\n"); 
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1,"Completed forwarding data\n");

    ret = 0;

exit:
    ssl_client_close();
    return ret;
}

/// @brief Code corresponds to SaveData() entry point of the algorithm
/// @param pdid Output did of the newly saved data
/// @return 0: In the case of success
///        -1: Otherwise
static int execute_SaveData(unsigned int *pdid)
{
    int ret = -1;

    if (ENC_STATE != 2)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot execute: %s, current state of enclave is: %d\n", __func__, ENC_STATE);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_MIN, 1, "Waiting for receiving the data and consent\n");

    ret = ssl_server_con_accept();

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while accepting the connection\n");
        ret = -1;
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Receiving data-file\n");

    sprintf(received_D_file, "./enc/%d/D_%d.xml", ssl_server_listening_port, next_did);
    sprintf(received_PC_file, "./enc/%d/PC_%d.xml", ssl_server_listening_port, next_did);

    sprintf(received_D_enc_file, "./enc/%d/D_%d.xml.enc", ssl_server_listening_port, next_did);// This file is only for the performance measurement in non-priv mode


    ret = ssl_recv_file(&ssl_server_ssl, received_D_file);

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while receiving the data file\n");
        ret = -1;
        goto exit;
    }

    /* For performance measurement purpose in non-priv mode */
    if (g_in_sgx == false)
    {
        /* In non-priv mode do not need to measure the time for sending PC file, but requires the D-file to be saved in encrypted format */
        aes_encrypt_file(received_D_file, received_D_enc_file, DUMMY_KEY, DUMMY_IV);
        end_timing();
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Receiving pc-file\n");

    ret = ssl_recv_file(&ssl_server_ssl, received_PC_file);

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while receiving the consent file\n");
        ret = -1;
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "RSS-like verification operation start\n");

    ret = VerifyAndSave();

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "RSS-like verification operation end\n");

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during verification of the received content\n");
        ret = -1;
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Successfully verified both the files\n");

    sprintf(DU_PC_file, "./DU_storage/%d/PC_%d.xml", ssl_server_listening_port, next_did);

    /* Return unencrypted PC-file to DU */
    ret = file_copy(received_PC_file, DU_PC_file);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "File copy problem, to: %s from: %s\n", received_PC_file, DU_PC_file);
        ret = -1;
        goto exit;
    }

    ret = ssl_write_data(&ssl_server_ssl, "OK\n", sizeof("OK\n"));

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during returning OK message to the sender\n");
        ret = -1;
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Successfully written OK message to the sender of these message\n");

    *pdid = next_did;
    next_did++;

    ret = 0;

exit:
    ssl_server_con_close();

    if (ret != 0)
    {
        (void)remove(received_D_file);
        (void)remove(received_PC_file);
        (void)remove(DU_PC_file);
    }

    return ret;
}

/// @brief Code corresponds to Process() entry point of the algorithm
/// @param did did of the data to be process
/// @param S_ID Difference from the exact algorithm. The id of S, which is required to be executed on the data
/// @param result Output of the computation
/// @return 0: If enclave can successfully executed
///        -1: Otherwise
static int execute_Process(unsigned int did, unsigned int S_ID, unsigned int *result)
{
    unsigned int (*fn_f)(const char *file_path);
    char *error;
    int ret = -1;
    void *libp = NULL;
    char fname[100];

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Within the function: %s\n", __func__);

    if (ENC_STATE != 2)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot execute: %s, current state of enclave is: %d\n", __func__, ENC_STATE);
        ret = -1;
        goto exit;
    }

    sprintf(fname, "./enc/%d/code_%d.so", ssl_server_listening_port, S_ID);

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Starting the dynamic library loading\n");

    libp = dlopen(fname, RTLD_NOW|RTLD_NODELETE);
    
    if (libp == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot open the dynamic library: %s\n", fname);
        ret = -1;
        goto exit;
    }

    fn_f = dlsym(libp, "fn");
    
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended the dynamic library loading\n");

    if (fn_f == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "The function fn is not found within the loaded library\n");
        ret = -1;
        goto exit;
    }

    if ((error = dlerror()) != NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "%s\n", error);
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot load the symbol from the dynamic library\n");
        ret = -1;
        goto exit;
    }

    sprintf(fname, "./enc/%d/D_%d.xml", ssl_server_listening_port, did);

    /* For performance measurement purpose in non-priv mode */
    if (g_in_sgx == false)
    {
        sprintf(received_D_enc_file, "./enc/%d/D_%d.xml", ssl_server_listening_port, did);
        /* Decrypt the file and then delete that */
        aes_decrypt_file(received_D_enc_file, "dummy.dec", DUMMY_KEY, DUMMY_IV);
        (void)remove("dummy.dec");
    }    

    *result = fn_f(fname);
    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Return from the function: %u\n", *result);

    ret = 0;

exit:
    if (libp != NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Starting the dynamic library un-loading\n");
        dlclose(libp);
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Ended the dynamic library un-loading\n");
    }

    return ret;
}

/// @brief Logging function for debugging
/// @param enclave_dbg_lvl The level of the print statement
/// @param do_flush Whether to flush the print buffer immediately to the sceen(will make the execution slower)
/// @param fmt The format specifier like printf()
/// @param  The paramerts to be printed, just like printf()
static void enclave_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...)
{
    int printed_size = 0;
    struct timezone tz;
    struct timeval tv;
    struct tm *now;
    va_list ap;

    if (ENCLAVE_LOG_LVL >= enclave_dbg_lvl)
    {
        gettimeofday(&tv, &tz);
        now = localtime(&tv.tv_sec);

        if (now != NULL)
        {
            printed_size = snprintf(print_buf, PRINT_BUF_SZ, "[ENC: %07d]\t[%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", eid, now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
        }

        va_start(ap, fmt);
        vsnprintf(&print_buf[printed_size], (PRINT_BUF_SZ - printed_size - 1), fmt, ap);
        va_end(ap);
        printf("%s", print_buf);

        if (do_flush != 0)
        {
            fflush(stdout);
        }
    }

    return;
}

/// @brief This is a callback function which is called by the ssl processor in the case of any error
/// @param ctx ssl context
/// @param level level of error
/// @param file The file where the log will be printed
/// @param line Location of the code where the problem occurred
/// @param str The string to be printed
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    fprintf((FILE *)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE *)ctx);
}

/// @brief When acting as the parent DU, it acts as client. This function connects with a children DU's enclave
/// @param IP IP address of the children DU
/// @param port Listening port of the children DU's enclave
/// @return 0: In the case of success
/// Otherwise: In the case of error
static int ssl_client_connect(const char* IP, const char* port)
{
    int ret;
    size_t len;
    int exit_code = EXIT_FAILURE;
    uint32_t flags;
    const char *pers = "ssl_client1";
    bool usr_verification = true;

    char *error;
    ra_tls_verify_lib = NULL;
    ra_tls_verify_callback_extended_der_f = NULL;
    ra_tls_set_measurement_callback_f = NULL;
    struct ra_tls_verify_callback_results my_verify_callback_results = {0};

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&ssl_client_server_fd);
    mbedtls_ssl_init(&ssl_client_ssl);
    mbedtls_ssl_config_init(&ssl_client_conf);
    mbedtls_ctr_drbg_init(&ssl_client_ctr_drbg);
    mbedtls_x509_crt_init(&ssl_client_cacert);
    mbedtls_entropy_init(&ssl_client_entropy);

    if (g_in_sgx)
    {
        /*
         * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
         * functions from libsgx_urts.so, thus we don't need to load this helper library.
         */
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!ra_tls_verify_lib)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "%s\n", dlerror());
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Please make sure that you are using client_dcap.manifest\n");
            return 1;
        }
    }

    if ((ra_tls_verify_lib != NULL) && (usr_verification == true))
    {
        ra_tls_verify_callback_extended_der_f = dlsym(ra_tls_verify_lib,
                                                      "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "%s\n", error);
            return 1;
        }

        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "[ using our own SGX-measurement verification callback"
                                                  " (via command line options) ]\n");

        g_verify_mrenclave = true;
        g_verify_mrsigner = true;
        g_verify_isv_prod_id = false;
        g_verify_isv_svn = false;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);
    }
    else if (ra_tls_verify_lib)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "[ using default SGX-measurement verification callback"
                                                  " (via RA_TLS_* environment variables) ]\n");
        (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */
    }
    else
    {
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "[ Non-sgx mode, instead of RA-TLS, using normal TLS flows ]\n");
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Seeding the random number generator...");

    ret = mbedtls_ctr_drbg_seed(&ssl_client_ctr_drbg, mbedtls_entropy_func, &ssl_client_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Connecting to tcp/%s/%s...", IP, port);

    ret = mbedtls_net_connect(&ssl_client_server_fd, IP, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Setting up the SSL/TLS structure...");

    ret = mbedtls_ssl_config_defaults(&ssl_client_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse_file(&ssl_client_cacert, CA_CRT_PATH);
    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ssl_client_conf, &ssl_client_cacert, NULL);
    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    if (ra_tls_verify_lib)
    {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&ssl_client_conf, &my_verify_callback, &my_verify_callback_results);
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");
    }

    mbedtls_ssl_conf_rng(&ssl_client_conf, mbedtls_ctr_drbg_random, &ssl_client_ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_client_conf, ssl_debug, stdout); // Sumit: Difference

    ret = mbedtls_ssl_setup(&ssl_client_ssl, &ssl_client_conf);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_client_ssl, IP);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_client_ssl, &ssl_client_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_client_ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "  ! ra_tls_verify_callback_results:\n"
                                                        "    attestation_scheme=%d, err_loc=%d, \n",
                              my_verify_callback_results.attestation_scheme,
                              my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme)
            {
            case RA_TLS_ATTESTATION_SCHEME_EPID:
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "    epid.ias_enclave_quote_status=%s\n\n",
                                  my_verify_callback_results.epid.ias_enclave_quote_status);
                break;
            case RA_TLS_ATTESTATION_SCHEME_DCAP:
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "    dcap.func_verify_quote_result=0x%x, "
                                                            "dcap.quote_verification_result=0x%x\n\n",
                                  my_verify_callback_results.dcap.func_verify_quote_result,
                                  my_verify_callback_results.dcap.quote_verification_result);
                    if (my_verify_callback_results.err_loc == 3) {
                        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1,"!!!!! Probably the environment variables are not set on the terminal\n");
                    }
                    else if (my_verify_callback_results.err_loc == 5) {
                        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1,"!!!!! Probably the code is not compiled with correct details of the enclave\n");
                    }
                    else {
                        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1,"Unknown reason\n");
                    }                    

                break;
            default:
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "  ! unknown attestation scheme!\n\n");
                break;
            }

            goto exit;
        }
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl_client_ssl);
    if (flags != 0)
    {
        char vrfy_buf[512];
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    }
    else
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " ok\n");
    }

    exit_code = EXIT_SUCCESS;
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Last error was: %d - %s\n\n", ret, error_buf);
        ssl_client_close();
    }
#endif

    return exit_code;
}

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char *mrenclave, const char *mrsigner,
                                  const char *isv_prod_id, const char *isv_svn)
{
    ssize_t bytes;

    /* 1. read `my_target_info` file */
    sgx_target_info_t target_info;
    bytes = read_dev_file("/dev/attestation/my_target_info", (char *)&target_info,
                          sizeof(target_info));
    if (bytes != sizeof(target_info))
    {
        /* error is already printed by read_dev_file() */
        return -1;
    }

    /* 2. write data from `my_target_info` to `target_info` file */
    bytes = write_dev_file("/dev/attestation/target_info", (char *)&target_info, sizeof(target_info));
    if (bytes != sizeof(target_info))
    {
        /* error is already printed by write_dev_file_f() */
        return -1;
    }

    /* 3. `user_report_data` file not required */
    sgx_report_data_t user_report_data = {0};

    bytes = write_dev_file("/dev/attestation/user_report_data", (char *)&user_report_data,
                           sizeof(user_report_data));
    if (bytes != sizeof(user_report_data))
    {
        /* error is already printed by write_dev_file_f() */
        return -1;
    }

    /* 4. read `report` file */
    sgx_report_t report;
    bytes = read_dev_file("/dev/attestation/report", (char *)&report, sizeof(report));
    if (bytes != sizeof(report))
    {
        return -1;
    }

    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (g_verify_mrenclave &&
        memcmp(mrenclave, &report.body.mr_enclave, sizeof(report.body.mr_enclave)))
        return -1;

    if (g_verify_mrsigner &&
        memcmp(mrsigner, &report.body.mr_signer, sizeof(report.body.mr_signer)))
        return -1;

    if (g_verify_isv_prod_id &&
        memcmp(isv_prod_id, &report.body.isv_prod_id, sizeof(report.body.isv_prod_id)))
        return -1;

    if (g_verify_isv_svn &&
        memcmp(isv_svn, &report.body.isv_svn, sizeof(report.body.isv_svn)))
        return -1;

    return 0;
}

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    if (depth != 0)
    {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags)
    {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_extended_der_f(crt->raw.p, crt->raw.len,
                                                 (struct ra_tls_verify_callback_results *)data);
}

/// @brief When acting as the parent DU, it acts as client. Finalizes that client.
static void ssl_client_close()
{
    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  . Closing the connection...\n");

    (void)mbedtls_ssl_close_notify(&ssl_server_ssl);

    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);

    mbedtls_entropy_free(&ssl_client_entropy);
    mbedtls_x509_crt_free(&ssl_client_cacert);
    mbedtls_ctr_drbg_free(&ssl_client_ctr_drbg);
    mbedtls_ssl_config_free(&ssl_client_conf);
    mbedtls_ssl_free(&ssl_client_ssl);
    mbedtls_net_free(&ssl_client_server_fd);

    return;
}

/// @brief Read data over an established ssl connection
/// @param p_ssl Pointer to the ssl contex
/// @param read_buf The buffer to hold the received data
/// @param max_read_len Maximum number of bytes the buffer must hold
/// @return >= 0: In case of success, it returns the read size
///   Error code: In case of error
static int ssl_read_data(mbedtls_ssl_context *p_ssl, char *read_buf, int max_read_len)
{
    int ret = -1;
    int len = max_read_len - 1;

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  < Reading data from established ssl connection:");
    memset(read_buf, 0, max_read_len);

    do
    {
        /* Send a zero byte ack immediately */
        if (mbedtls_ssl_get_bytes_avail(p_ssl) == 0)
        {
            mbedtls_ssl_write(p_ssl, read_buf, 0);
        }

        ret = mbedtls_ssl_read(p_ssl, read_buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Wants read-write more\n");
            continue;
        }

        if (ret < 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " connection was closed gracefully\n");
                break;

            case MBEDTLS_ERR_NET_CONN_RESET:
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " connection was reset by peer\n");
                break;

            default:
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " mbedtls_ssl_read returned -0x%x\n", -ret);
                break;
            }

            break;
        } else if (ret == 0){
            /* 0 size may be obtained for ack from other end */
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, " mbedtls_ssl_read received 0 bytes message\n");
            break;
        }

        len = ret;

        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, " %lu bytes read\n", len);

        if (ret > 0)
            break;
    } while (1);

    /* Returns read-size or error */
    return ret;
}

/// @brief Send data over an established ssl connection
/// @param p_ssl Pointer to the ssl contex
/// @param write_buf The buffer to hold the data to be sent
/// @param write_len The size of the data to be sent
/// @return >= 0: In case of success, it returns the actual number of bytes sent. Maybe less than write_len
///   Error code: In case of error
static int ssl_write_data(mbedtls_ssl_context *p_ssl, char *write_buf, int write_len)
{
    int ret;
    int written_len;

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "  > Write data to established ssl connection:");

    while ((ret = mbedtls_ssl_write(p_ssl, write_buf, write_len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! peer closed the connection\n\n");
            break;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            break;
        }
    }

    write_len = ret;
    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, " %lu bytes written\n", write_len);

    /* Returns written length or the error code */
    return ret;
}

/// @brief Read few bytes from a device file
/// @param path The device file name(its location)
/// @param buf The buffer to hold the read data
/// @param count Number of bytes to be read
/// @return >= 0: In the case of success. Number of bytes actually able to read
///           <0: In the case of error. Error code.
static ssize_t read_dev_file(const char *path, char *buf, size_t count)
{
    FILE *f = fopen(path, "r");

    if (!f)
    {
        return -errno;
    }

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0)
    {
        int errsv = errno;
        fclose(f);
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during file read: %d\n", -errsv);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during file close: %d\n", -errno);
        return -errno;
    }

    return bytes;
}

/// @brief Write few bytes to a device file
/// @param path The device file name(its location)
/// @param buf The buffer to hold the data to be written
/// @param count Number of bytes to be written
/// @return >= 0: In the case of success. Number of bytes actually able to write
///           <0: In the case of error. Error code.
static ssize_t write_dev_file(const char *path, char *buf, size_t count)
{
    FILE *f = fopen(path, "a");
    if (!f)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during file open: %d\n", -errno);
        return -errno;
    }

    fseek(f, 0L, SEEK_END);

    ssize_t bytes = fwrite(buf, 1, count, f);
    if (bytes <= 0)
    {
        int errsv = errno;
        fclose(f);
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during file write: %d\n", -errsv);
        return -errsv;
    }

    fseek(f, 0L, SEEK_END);

    int close_ret = fclose(f);
    if (close_ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during file close: %d\n", -errno);
        return -errno;
    }

    return bytes;
}

/// @brief Send a file over an established ssl connection
/// @param p_ssl Pointer to an already established ssl connection
/// @param file_path Location of the file to be sent
/// @return 0: In case of success
///        -1: Otherwise
static int ssl_send_file(mbedtls_ssl_context *p_ssl, const char *file_path)
{
    int ret = -1;
    int read_sz;
    int str_sz;
    int send_sz;
    int cur_send_sz;
    int file_sz = 0;
    FILE *fp;

    fp = fopen(file_path, "rb");

    if (fp == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "During SSL send, while opening the file: %s\n", file_path);
        goto exit;
    }

    /* Get the file size */
    fseek(fp, 0, SEEK_END); // seek to end of file
    file_sz = ftell(fp);    // get current file pointer
    fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    /* Convert the file-size to string */
    str_sz = snprintf(buf1, BUF1_SZ, "%d", file_sz);

    if (ssl_write_data(p_ssl, buf1, (str_sz + 1)) != (str_sz + 1))
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot send the file-size properly\n");
        goto exit;
    }

    /* Wait for the SYNC message from receiver.
       As the SYNC message will be generated after sending the previous data
       so need to send 0-byte dat, so using ssl_read_data() instead of mbedtls_ssl_read() */
    do
    {
        ret = ssl_read_data(p_ssl, buf1, BUF1_SZ);

        if (ret < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while receiving the SYNC message from the enclave\n");
            goto exit;
        }
    } while (ret == 0);

    send_sz = 0;

    while (send_sz != file_sz)
    {
        read_sz = fread(file_buf, 1, FILE_BUF_SZ, fp);

        cur_send_sz = 0;

        while (read_sz != cur_send_sz)
        {
            ret = ssl_write_data(p_ssl, &file_buf[cur_send_sz], (read_sz - cur_send_sz));

            if (ret < 0)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "While sending the file: %s\n", file_path);
                goto exit;
            }

            cur_send_sz += ret;
        }

        send_sz += cur_send_sz;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);

    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/// @brief Receive a file over an established ssl connection
/// @param p_ssl Pointer to an already established ssl connection
/// @param file_path Location of the file to be saved
/// @return 0: In case of success
///        -1: Otherwise
static int ssl_recv_file(mbedtls_ssl_context *p_ssl, const char *file_path)
{
    int ret = -1;
    int write_sz;
    int cur_recv_sz;
    int cur_write_sz;
    int file_sz;
    int recv_sz;
    FILE *fp;
    mbedtls_sha256_context ctx2;

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Started receiving the file: %s\n", file_path);

    fp = fopen(file_path, "wb");

    if (fp == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "While creating the file: %s\n", file_path);
        goto exit;
    }

    /* First read the file size */
    do
    {
        /* Send a zero byte ack immediately */
        if (mbedtls_ssl_get_bytes_avail(p_ssl) == 0)
        {
            mbedtls_ssl_write(p_ssl, file_buf, 0);
        }

        ret = mbedtls_ssl_read(p_ssl, buf1, BUF1_SZ);

        if (ret < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error(= %d) while receiving the SYNC message from the receiver\n", ret);
            goto exit;
        }
        else if (ret == 0){
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Read data size = %d\n", ret);
        }
    } while (ret == 0);

    file_sz = atoi(buf1);
    if (file_sz < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Receiving file size is < 0\n");
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Read the file size, which is: %d\n", file_sz);
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if (mbedtls_ssl_write(p_ssl, buf1, 1) < 1)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while sending the SYNC message, during file-transfer\n");
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Written sync message successfully\n");

    recv_sz = 0;

    /* Data will be sent after receiving the SYNC */
    /* That data may get delayed to receive here */
    /* So, sending a 0 byte message here */
    mbedtls_ssl_write(p_ssl, buf1, 0);

    while (recv_sz != file_sz)
    {
        cur_recv_sz = mbedtls_ssl_read(p_ssl, file_buf, FILE_BUF_SZ);

        if (cur_recv_sz < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while receiving data for the file: %d\n", cur_recv_sz);
            goto exit;
        }

        cur_write_sz = 0;

        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Received file data size: %d\n", cur_recv_sz);

        while (cur_recv_sz != cur_write_sz)
        {
            ret = fwrite(&file_buf[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

            if (ret < 0)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while writing to the file: %d\n", ret);
                goto exit;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Successfully received file having size: %d bytes\n", recv_sz);

    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/// @brief Print the input binary in hexadecimal format. It can be used only for debugging
/// @param title Some title string to be printed
/// @param buf Input buffer holding the binary value
/// @param len Data size in buf, in terms of bytes
static void print_hex(const char *title, const unsigned char buf[], size_t len)
{
    if (title != NULL)
    {
        printf("%s: ", title);
    }

    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);

    printf("\r\n");
}

/// @brief Make a copy of an input file
/// @param source_file The input filename
/// @param target_file The destination filename
/// @return 0: In the case of success
///        -1: In the case of error
static int file_copy(const char *source_file, const char *target_file)
{
    int ret = -1;
    char ch;
    unsigned int src_file_sz;
    unsigned int copied_sz = 0;
    int read_sz = 0;
    int write_sz = 0;

    FILE *source = NULL;
    FILE *target = NULL;

    source = fopen(source_file, "rb");

    if (source == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot open: %s\n", source_file);
        goto exit;
    }

    fseek(source, 0, SEEK_END);  // seek to end of file
    src_file_sz = ftell(source); // get current file pointer
    fseek(source, 0, SEEK_SET);  // seek back to beginning of file

    target = fopen(target_file, "wb");

    if (target == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot open: %s\n", target_file);
        goto exit;
    }

    while (copied_sz < src_file_sz)
    {
        read_sz = fread(file_buf, 1, FILE_BUF_SZ, source);
        write_sz = fwrite(file_buf, 1, read_sz, target);

        if (read_sz != write_sz)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Read and write size are different\n");
            goto exit;
        }

        copied_sz += write_sz;
    }

    ret = 0;
exit:
    fclose(source);
    fclose(target);

    return ret;
}

/// @brief Generates the sha256 of a file
/// @param file_path Input file path
/// @param ctx Existing SHA-256 context to get updated, if this file's SHA-256 is to be combinded with some existing SHA-256 calculation
///            It can be NULL. In that case only the SHA-256 of the current file will be calculated
/// @param sha256_buf Output buffer holding the SHA-256. Holds actual value if ctx is not NULL
/// @param real_file_sz 
/// @return 0: In case of success
///        -1: Otherwise
static int sha256_file(const char *file_path, mbedtls_sha256_context *ctx, unsigned char *sha256_buf, unsigned int real_file_sz)
{
    int ret = -1;
    FILE *fp;
    int read_sz = 0;
    int cur_read_sz;
    mbedtls_sha256_context local_sha256_ctx;

    fp = fopen(file_path, "rb");

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Real file size: %d\n", real_file_sz);

    if (fp == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "During SHA256 calculation, cannot open the file: %s\n", file_path);
        goto exit;
    }

    /* If real_file_sz is set as 0, then determine the real-file size */
    if (real_file_sz == 0)
    {
        fseek(fp, 0, SEEK_END);   // seek to end of file
        real_file_sz = ftell(fp); // get current file pointer
        fseek(fp, 0, SEEK_SET);   // seek back to beginning of file
    }

    /* If input context is NULL then use local one and finalize it at the end */
    if (ctx == NULL)
    {
        mbedtls_sha256_starts(&local_sha256_ctx, 0);
    }

    while (read_sz < real_file_sz)
    {
        cur_read_sz = fread(file_buf, 1, FILE_BUF_SZ, fp);

        if (cur_read_sz <= 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot read the file: %s\n", file_path);
            goto exit;
        }

        read_sz += cur_read_sz;

        /* As the file has not ended here, it may read the dummy data as well */
        if (read_sz > real_file_sz)
        {
            cur_read_sz -= (read_sz - real_file_sz);
        }

        /* If input context is NULL then use local one and finalize it at the end */
        if (ctx == NULL)
        {
            mbedtls_sha256_update(&local_sha256_ctx, file_buf, cur_read_sz);
        }
        else
        {
            mbedtls_sha256_update(ctx, file_buf, cur_read_sz);
        }
    }

    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }
    if ((ctx == NULL) && (sha256_buf != NULL))
    {
        mbedtls_sha256_finish(&local_sha256_ctx, sha256_buf);
    }

    return ret;
}

/// @brief Receive a file padded to a certain fix length. Save the unpadded version in specific location
/// @param p_ssl Listening ssl context
/// @param file_path Location, where to save the received file
/// @param p_real_file_sz Outputs the actual size of the file
/// @return  0: In the case of success
///         -1: Otherwise
static int ssl_recv_padded_file(mbedtls_ssl_context *p_ssl, const char *file_path, unsigned int *p_real_file_sz)
{
    int ret = -1;
    int write_sz;
    int cur_recv_sz;
    int cur_write_sz;
    int file_sz;
    int recv_sz;
    FILE *fp;
    mbedtls_sha256_context ctx2;

    fp = fopen(file_path, "w+b");

    if (fp == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "While creating the file: %s\n", file_path);
        goto exit;
    }

    /* First read the file size */
    do
    {
        /* Send a zero byte ack immediately */
        if (mbedtls_ssl_get_bytes_avail(p_ssl) == 0)
        {
            mbedtls_ssl_write(p_ssl, file_buf, 0);
        }

        ret = mbedtls_ssl_read(p_ssl, buf1, BUF1_SZ);
        if (ret < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error(= %d) while receiving the SYNC message from the receiver\n", ret);
            goto exit;
        }
        else if (ret == 0){
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Read data size = %d\n", ret);
        }
    } while (ret == 0);

    file_sz = atoi(buf1);
    if (file_sz < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Receiving file size is < 0\n");
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Read the file size, which is: %d\n", file_sz);

    /* Send-back a single byte sync message to the server after receiving the file size */
    if (mbedtls_ssl_write(p_ssl, buf1, 1) < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while sending the SYNC message, during file-transfer\n");
        goto exit;
    }

    recv_sz = 0;
    /* Data will be sent after receiving the SYNC */
    /* That data may get delayed to receive here */
    /* So, sending a 0 byte message here */
    mbedtls_ssl_write(p_ssl, buf1, 0);

    while (recv_sz != file_sz)
    {
        cur_recv_sz = mbedtls_ssl_read(p_ssl, file_buf, FILE_BUF_SZ);

        if (cur_recv_sz < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Problem while receiving data for the file: %d\n", cur_recv_sz);
            goto exit;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            ret = fwrite(&file_buf[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

            if (ret < 0)
            {
                enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while writing to the file: %d\n", ret);
                goto exit;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Successfully received file having size: %d bytes\n", recv_sz);

    ret = fseek(fp, (file_sz - 8), SEEK_SET);

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while trying to feek(), to read file's real size, ret: %d\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Before reading last 8-bytes of the file\n");

    /* Read last 8 bytes */
    ret = fread(buf1, 1, 8, fp);

    if (ret <= 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while trying to fread(), to read file's real size, ret: %d\n", ret);
        goto exit;
    }

    *p_real_file_sz = atoi(buf1);
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "File's real size is: %d\n", *p_real_file_sz);

    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/// @brief Obtain the xmlNode* pointer corresponding to specified path within the xml
/// @param root The root node of the xml file
/// @param path Input path. Next subnode is represented by "/" and i-th children by [i]
/// @return Not NULL: If the path is found
///             NULL: Otherwise
static xmlNode *xml_get_element_by_path(xmlNode *root, xmlChar *path)
{
    xmlNode *cur_node = root;
    char *token;
    int children_num;
    int max_children_num;
    int i;
    xmlNode *node = NULL;

    token = strtok((char *)path, "/:");
    while (cur_node != NULL)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (xmlStrcmp((xmlChar *)token, cur_node->name) != 0)
            {
                cur_node = xmlNextElementSibling(cur_node);
                continue;
            }
            else
            {
                /* If match, then find whether there is any numerics mentioned  */
                token = strtok(NULL, "/:");

                /* User specified path has completed */
                if (token == NULL)
                {
                    node = cur_node;
                    break;
                }
                else
                {
                    children_num = atoi(token);

                    /* Check whether it is a numeric one */
                    if (children_num != 0)
                    {
                        max_children_num = xmlChildElementCount(cur_node->parent);

                        if (children_num > max_children_num)
                        {
                            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Not enough number of children nodes. Expected :%d, has: %d\n", children_num, max_children_num);
                            break;
                        }

                        /* Go to the i-th children. For first children no need to move to next */
                        for (i = 2; ((cur_node != NULL) && (i <= children_num)); i++)
                        {
                            cur_node = xmlNextElementSibling(cur_node);
                        }

                        token = strtok(NULL, "/:");

                        if (token == NULL)
                        {
                            node = cur_node;
                            break;
                        }
                    }

                    cur_node = cur_node->children;
                }
            }
        }
        else
        {
            cur_node = cur_node->next;
        }
    }

    return node;
}

/// @brief Verify and save the received PC and D
/// @return  0: In the case of success
///         -1: Otherwise
static int VerifyAndSave()
{
    int ret;
    unsigned char sha256_buf[32];
    unsigned char sha256_buf_hex[64 + 1];
    unsigned char signature_buf[256]; // Size of the signature is 256 bytes
    mbedtls_sha256_context sha256_ctx;
    unsigned int file_sz;
    int num_pd;
    xmlDocPtr PC_file_doc = NULL;
    xmlDocPtr D_file_doc = NULL;
    xmlNode *PC_file_root_element = NULL;
    xmlNode *D_file_root_element = NULL;
    xmlNode *PC_file_node = NULL;
    xmlNode *D_file_node = NULL;
    xmlChar xmlPath[100];
    unsigned int i;
    FILE *fp;
    size_t fresh_sk_len, fresh_pk_len, DO_pk_len, sig_len, buf_sz;

    ret = sha256_file(received_D_file, NULL, sha256_buf, 0);

    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot calculate the hash of the received data-file\n");
        goto exit;
    }

    bin_to_hex(sha256_buf, 32, sha256_buf_hex);
    sha256_buf_hex[64] = '\0'; // For printing purpose only
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "SHA-256 of received D-file: %s\n", sha256_buf_hex);

    /* Parse the file and get the DOM */
    PC_file_doc = xmlReadFile(received_PC_file, NULL, 0);

    if (PC_file_doc == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not parse file %s\n", received_PC_file);
        ret = -1;
        goto exit;
    }

    /* Get the root element node */
    PC_file_root_element = xmlDocGetRootElement(PC_file_doc);
    if (PC_file_root_element == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not find the root of the file %s\n", received_PC_file);
        ret = -1;
        goto exit;
    }

    /*parse the file and get the DOM */
    D_file_doc = xmlReadFile(received_D_file, NULL, 0);

    if (D_file_doc == NULL)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not parse file %s\n", received_D_file);
        ret = -1;
        goto exit;
    }

    D_file_root_element = xmlDocGetRootElement(D_file_doc);

    /* Check whether PC.DH = H(D) */
    {
        strcpy(xmlPath, "PC/DH");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);
        if (strncmp(sha256_buf_hex, xmlNodeGetContent(PC_file_node), 64) != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: PC.DH != H(D)\n");
            ret = -1;
            goto exit;
        }
    }

    /* Verifies PC.VK and D.CSK are linked together */
    {
        char known_pattern[] = "known_pattern";
        char ctxt_buf[256] = {0};
        char ptxt_buf[256] = {0};
        size_t clen, plen;

        /* Encrypt with PC.VK */
        strcpy(xmlPath, "PC/VK");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);
        fresh_pk_len = strlen(xmlNodeGetContent(PC_file_node));
        /* buf1 now contains: PC.VK */
        memcpy(buf1, xmlNodeGetContent(PC_file_node), fresh_pk_len + 1);
        ret = AE_Enc_buf(buf1, fresh_pk_len + 1, known_pattern, sizeof(known_pattern), ctxt_buf, &clen, sizeof(ctxt_buf));
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Encryption error, using PC.VK\n");
            ret = -1;
            goto exit;
        }
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Encryption successfully using PC.VK, clen = %d\n", clen);

        /* Decrypt with D.CSK */
        strcpy(xmlPath, "D/CSK");
        D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);
        fresh_sk_len = strlen(xmlNodeGetContent(D_file_node));
        /* buf2 now contains: D.CSK */
        memcpy(buf2, xmlNodeGetContent(D_file_node), fresh_sk_len + 1);
        ret = AE_Dec_buf(buf2, fresh_sk_len + 1, ctxt_buf, clen, ptxt_buf, &plen, sizeof(ptxt_buf));
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Decryption error, using D.CSK\n");
            ret = -1;
            goto exit;
        }
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Decrypted successfully using D.CSK\n");

        /* Comare whether the original data can be retrieved */
        if (strncmp(ptxt_buf, known_pattern, sizeof(known_pattern)) != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: PC.VK and D.CSK are not linked together\n");
            ret = -1;
            goto exit;
        }
    }

    /* Verify D.DOS with D.DOC */
    {
        /* Prepare: D.DS|PC.VK */
        strcpy(xmlPath, "D/DS");
        D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);

        buf_sz = read_all_children(D_file_node, file_buf, FILE_BUF_SZ);
        if (buf_sz < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during reading D.DS[]\n");
            ret = -1;
            goto exit;
        }

        memcpy(&file_buf[buf_sz], buf1, fresh_pk_len);
        buf_sz += fresh_pk_len;

        /* For printing purpose only, the NULL charecter is added */
        file_buf[buf_sz] = '\0';
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "D.DS[]|PC.VK: %s\n", file_buf);

        /* Retrieve: D.DOC */
        strcpy(xmlPath, "D/DOC");
        D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);
        DO_pk_len = strlen(xmlNodeGetContent(D_file_node));
        /* buf2 now contains: D.DOC */
        memcpy(buf2, xmlNodeGetContent(D_file_node), DO_pk_len + 1);

        /* Retrieve: D.DOS */
        strcpy(xmlPath, "D/DOS");
        D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);
        ret = mbedtls_base64_decode(signature_buf, 256, &sig_len, xmlNodeGetContent(D_file_node), strlen(xmlNodeGetContent(D_file_node)));
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot decode the signature D.DOS as base64 format\n");
            ret = -1;
            goto exit;
        }

        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Recovered signature D.DOS and its size is: %d\n", sig_len);

        /* Verify D.DOS with D.DOC */
        ret = S_VfB(file_buf, buf_sz, buf2, DO_pk_len + 1, signature_buf, sig_len);

        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Return after calling S_VfB: %d\n", ret);

        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while verifying D.DOS with D.DOC: %d\n", ret);
            goto exit;
        }
    }

    /* Verify PC.SC with PC.VK */
    {
        /* Prepare: PC.PDS[]|PC.DH */
        strcpy(xmlPath, "PC/PDS");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);

        buf_sz = read_all_children(PC_file_node, file_buf, FILE_BUF_SZ);
        if (buf_sz < 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during reading D.DS[]\n");
            ret = -1;
            goto exit;
        }

        /* Retrieve: PC.DH */
        strcpy(xmlPath, "PC/DH");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);
        memcpy(&file_buf[buf_sz], xmlNodeGetContent(PC_file_node), 64); /* Always the length is 64 */
        buf_sz += 64;

        /* For printing purpose only, the NULL charecter is added */
        file_buf[buf_sz] = '\0';
        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "PC.PDS[]|PC.DH: %s\n", file_buf);

        /* Retrieve: PC.SC */
        strcpy(xmlPath, "PC/SC");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);
        ret = mbedtls_base64_decode(signature_buf, 256, &sig_len, xmlNodeGetContent(PC_file_node), strlen(xmlNodeGetContent(PC_file_node)));
        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot decode the signature PS.SC as base64 format\n");
            ret = -1;
            goto exit;
        }

        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Recovered signature PS.SC and its size is: %d\n", sig_len);

        /* Verify PC.SC with PC.VK */
        ret = S_VfB(file_buf, buf_sz, buf1, fresh_pk_len + 1, signature_buf, sig_len);

        enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Return after calling S_VfB: %d\n", ret);

        if (ret != 0)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while verifying PC.SC with PC.VK: %d\n", ret);
            goto exit;
        }
    }

    ret = 0;
exit:
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);
    mbedtls_sha256_free(&sha256_ctx);
    /*free the document */
    xmlFreeDoc(D_file_doc);
    xmlFreeDoc(PC_file_doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return ret;
}

/// @brief Generates the hexadecimal representation of the input binary data
/// @param buf Buffer containing binary data
/// @param len Number of bytes data present in buf
/// @param op_buf The buffer holding the hexadecimal string
///        Note: The output is always twice in lenght of len
static void bin_to_hex(const unsigned char buf[], size_t len, unsigned char *op_buf)
{
    for (size_t i = 0; i < len; i++)
    {
        sprintf(op_buf, "%02x", buf[i]);
        op_buf += 2;
    }
}

/// @brief Corresponds to AE.KGen() in the algorithm: Genrates RSA-keypair according to RSA_KEY_SZ and RSA_KEY_EXP
/// @param pk_buf Buffer to hold the output public-key in PEM format string
/// @param pk_buf_sz Maximum size pk_buf can hold
/// @param o_pk_sz Actual size of the generated public-key in PEM format string
/// @param sk_buf Buffer to hold the output secret-key in PEM format string
/// @param sk_buf_sz Maximum size sk_buf can hold
/// @param o_sk_sz Actual size of the generated Secret-key in PEM format string
/// @return 0 In the case of success
static int AE_Kgen(char *pk_buf, size_t pk_buf_sz, size_t *o_pk_sz, char *sk_buf, size_t sk_buf_sz, size_t *o_sk_sz)
{
    int ret;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_genkey";
    *o_pk_sz = *o_sk_sz = 0;

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Seeding the random number generator for the key-generation...\n");

    mbedtls_pk_init(&key);

    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                          (unsigned int)-ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Generating the RSA key [ %d-bit, exponent: %d ]...\n", RSA_KEY_SZ, RSA_KEY_EXP);

    if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)MBEDTLS_PK_RSA))) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int)-ret);
        goto exit;
    }

    if ((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, RSA_KEY_SZ, RSA_KEY_EXP)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Exporting the public key in the pem buffer\n");

    if ((ret = mbedtls_pk_write_pubkey_pem(&key, pk_buf, pk_buf_sz)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_write_pubkey_pem returned %d\n\n", ret);
        goto exit;
    }

    /* Add 1 for the trailing null charecter */
    *o_pk_sz = (strlen(pk_buf) + 1);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Exporting the secret key in the pem buffer\n");

    if ((ret = mbedtls_pk_write_key_pem(&key, sk_buf, sk_buf_sz)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_write_key_pem returned %d\n\n", ret);
        goto exit;
    }

    /* Add 1 for the trailing null charecter */
    *o_sk_sz = (strlen(sk_buf) + 1);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&key);

    return ret;
}

/// @brief Corresponds to the buffer flavour of AE.Enc(). Encrypts a given buffer with input public-key
/// @param pk_buf Public-key in PEM format
/// @param pk_sz Size of pk_buf
/// @param input Input buffer to be encrypted
/// @param ilen Lenght of the input buffer
/// @param output Buffer for holding the encrypted output
/// @param olen Length of the output ciphertext
/// @param max_olen Maximum size the output buffer can hold
/// @return
static int AE_Enc_buf(const char *pk_buf,
               size_t pk_sz,
               const unsigned char *input,
               size_t ilen, unsigned char *output,
               size_t *olen, size_t max_olen)
{
    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_encrypt";
    *olen = 0;

    ret = -1;

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Seeding the random number generator for encryption\n");

    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        goto exit;
    }

    mbedtls_pk_init(&pk);

    if ((ret = mbedtls_pk_parse_public_key(&pk, pk_buf, pk_sz)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_parse_public_key returned -0x%x\n", -ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Starting encryption\n");

    if ((ret = mbedtls_pk_encrypt(&pk, input, ilen, output, olen, max_olen, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_encrypt returned -0x%x\n", -ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Encryption successful...ciphertext size = %d\n", *olen);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);

#if defined(MBEDTLS_ERROR_C)
    if (ret != 0)
    {
        mbedtls_strerror(ret, (char *)buf1, BUF1_SZ);
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "  !  Last error was: %s\n", buf1);
    }
#endif

    return ret;
}

/// @brief Corresponds to the buffer flavour of AE.Dec(). Decrypts a given ciphertext with input secret-key
/// @param sk_buf Secret-key in PEM format
/// @param sk_sz Size of sk_buf
/// @param input Input buffer to be decrypted
/// @param ilen Lenght of the input buffer
/// @param output Buffer for holding the decrypted output
/// @param olen Length of the output plaintext
/// @param max_olen Maximum size the output buffer can hold
/// @return
static int AE_Dec_buf(const char *sk_buf,
               size_t sk_sz,
               const unsigned char *input,
               size_t ilen, unsigned char *output,
               size_t *olen, size_t max_olen)
{
    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_decrypt";
    *olen = 0;

    ret = -1;

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Seeding the random number generator for decryption purpose\n");

    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
        goto exit;
    }

    mbedtls_pk_init(&pk);

    if ((ret = mbedtls_pk_parse_key(&pk, sk_buf, sk_sz, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_parse_key returned -0x%x\n", -ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Starting decryption\n");

    if ((ret = mbedtls_pk_decrypt(&pk, input, ilen, output, olen, max_olen, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_decrypt returned -0x%x\n", -ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "Decryption successful...plaintext size = %d, plaintext: %s\n", *olen, output);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);

#if defined(MBEDTLS_ERROR_C)
    if (ret != 0)
    {
        mbedtls_strerror(ret, (char *)buf2, BUF2_SZ);
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "  !  Last error was: %s\n", buf2);
    }
#endif

    return ret;
}

/// @brief Generates a signature on already computed hash value
/// @param hash_buf Buffer containing previously calculated hash value. This should always be of size 32 bytes
/// @param pri_key_buf Buffer containing the private key in PEM format
/// @param keylen Key-length
/// @param sign_buf Buffer which will hold the signature
/// @param p_olen Holds the size of the output signature
/// @return 0 in the case of success, 1 otherwise
static int S_SigH(char *hash_buf, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen)
{
    int ret = 1;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_sign_pss";
    *p_olen = 0;

    mbedtls_entropy_init(&entropy);   // TODO: One single entropy init can be done for the enclave
    mbedtls_pk_init(&pk);             // TODO: One single pk init can be done for enclave's key-pair
    mbedtls_ctr_drbg_init(&ctr_drbg); // TODO: One single drbg init can be done for the enclave

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Seeding the random number generator for signing the buffer...");

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Reading private key from the buffer\n");

    if ((ret = mbedtls_pk_parse_key(&pk, (unsigned char *)pri_key_buf, keylen, /*pwd=*/NULL, 0, mbedtls_ctr_drbg_random, NULL)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Could not read key\n");
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "  ! mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
    {
        ret = 1;
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Key is not an RSA key\n");
        goto exit;
    }

    /* Use PKCS_V15 format to make it compatible with linux command */
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Generating the RSA/SHA-256 signature");

    if ((ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash_buf, 32, sign_buf, MBEDTLS_PK_SIGNATURE_MAX_SIZE, p_olen,
                               mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_sign returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "\n  . Signature successful\n");

exit:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret);
}

/// @brief Creates a hash of a data-buffer first and then signs that
/// @param data_buf Data buffer to be signed
/// @param data_sz Size of the data within data_buf
/// @param pri_key_buf Buffer containing the private key in PEM format
/// @param keylen Key-length
/// @param sign_buf Buffer which will hold the signature
/// @param p_olen Holds the size of the output signature
/// @return 0 in the case of success, 1 otherwise
static int S_SigB(const char *data_buf, size_t data_sz, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen)
{
    int ret = 1;
    unsigned char hash[32];

    /* 0 here means use the full SHA-256, not the SHA-224 variant */
    mbedtls_sha256(data_buf, data_sz, hash, 0);

    ret = S_SigH(hash, pri_key_buf, keylen, sign_buf, p_olen);

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Return from signature generation call: %d\n", ret);

    return ret;
}

/// @brief Creates a hash of file and then signs that
/// @param data_fname Name of the file, which is to be signed
/// @param pri_key_buf Buffer containing the private key in PEM format
/// @param keylen Key-length
/// @param sign_buf Buffer which will hold the signature
/// @param p_olen Holds the size of the output signature
/// @return 0 in the case of success, 1 otherwise
static int S_SigF(const char *data_fname, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen)
{
    int ret = 1;
    unsigned char hash[32];

    if ((ret = mbedtls_md_file(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data_fname, hash)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Could not calculate the hash of the file: %s\n\n", data_fname);
    }
    else
    {
        ret = S_SigH(hash, pri_key_buf, keylen, sign_buf, p_olen);
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Return from signature generation call: %d\n", ret);
    }

    return ret;
}

/// @brief Verifies the signature, corresponding to a hash value
/// @param hash_buf Buffer containing pre-computed hash value. It should always be 32 bytes long.
/// @param pub_key_buf Buffer containing the public key in PEM format
/// @param keylen Size of the key buffer
/// @param sign_buf Buffer containing the signature
/// @param sign_sz Size of the valid data in sign_buf
/// @return 0 if the signature is valid, 1 otherwise
static int S_VfH(char *hash_buf, const unsigned char *pub_key_buf, size_t keylen, char *sign_buf, size_t sign_sz)
{
    int ret = 1;
    int exit_code = -1;
    int olen;
    mbedtls_pk_context pk;
    unsigned char hash[32];

    mbedtls_pk_init(&pk);

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Reading public key\n");

    if ((ret = mbedtls_pk_parse_public_key(&pk, pub_key_buf, keylen)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Could not read key\n");
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "  ! mbedtls_pk_parse_public_keyfile returned %d\n\n", ret);
        goto exit;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Key is not an RSA key\n");
        goto exit;
    }

    /* Use PKCS_V15 padding format as the linux command uses that */
    if ((ret = mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk),
                                       MBEDTLS_RSA_PKCS_V15,
                                       MBEDTLS_MD_SHA256)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Invalid padding\n");
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file and
     * verify the signature
     */
    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . Verifying the RSA/SHA-256 signature");
    if ((ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash_buf, 32,
                                 sign_buf, sign_sz)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_verify returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(ENCLAVE_LOG_LVL_ALL, 1, "\n  . OK (the signature is valid)\n\n");

    exit_code = 0;

exit:
    mbedtls_pk_free(&pk);

    return exit_code;
}

/// @brief Caculates the hash of a data buffer and then verifies the corresponding signature
/// @param data_buf Buffer containing the data, which is to be signed
/// @param data_sz Size of the data residing in data_buf
/// @param pub_key_buf Buffer containing the public key in PEM format
/// @param keylen Size of the key buffer
/// @param sign_buf Buffer containing the signature
/// @param sign_sz Size of the valid data in sign_buf
/// @return 0 if the signature is valid, 1 otherwise
static int S_VfB(const char *data_buf, size_t data_sz, const unsigned char *pub_key_buf, size_t keylen, char *sign_buf, size_t sign_sz)
{
    int ret = 1;
    unsigned char hash[32];

    /* 0 here means use the full SHA-256, not the SHA-224 variant */
    mbedtls_sha256(data_buf, data_sz, hash, 0);

    ret = S_VfH(hash, pub_key_buf, keylen, sign_buf, sign_sz);

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Return from signature (of size = %d) verification call: %d\n", sign_sz, ret);

    return ret;
}

/// @brief Caculates the hash of a data file and then verifies the corresponding signature
/// @param data_fname Name of the file containing the data, which is already signed
/// @param pub_key_buf Buffer containing the public key in PEM format
/// @param keylen Size of the key buffer
/// @param sign_buf Buffer containing the signature
/// @param sign_sz Size of the valid data in sign_buf
/// @return 0 if the signature is valid, 1 otherwise
static int S_VfF(const char *data_fname, const unsigned char *pub_key_buf, size_t keylen, char *sign_buf, size_t sign_sz)
{
    int ret = 1;
    unsigned char hash[32];

    if ((ret = mbedtls_md_file(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data_fname, hash)) != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, " failed\n  ! Could not calculate the hash of the file: %s\n\n", data_fname);
    }
    else
    {
        ret = S_VfH(hash, pub_key_buf, keylen, sign_buf, sign_sz);
        enclave_print_log(ENCLAVE_LOG_LVL_INFO, 0, "Return from signature verification call: %d\n", ret);
    }

    return ret;
}

/// @brief Read the content of all the children into a buffer
/// @param node The parent node
/// @param buf The buffer, which will hold the content
/// @param max_buf_siz Maximum size of the buffer
/// @return In the case of error: -1
///         In the case of success: The size of the read buffer excluding the trailing NULL charecter
static int read_all_children(xmlNode *node, char *buf, size_t max_buf_siz)
{
    int num_children;
    xmlNode *cur_node;
    int ret = -1;
    int i;
    int cur_node_len;
    int written_sz = 0;

    num_children = xmlChildElementCount(node);
    cur_node = xmlNextElementSibling(node->children);

    for (i = 0; ((cur_node != NULL) && (i < num_children)); i++)
    {
        cur_node_len = strlen(xmlNodeGetContent(cur_node));

        if ((written_sz + cur_node_len + 1) > max_buf_siz)
        {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "No more space in the buffer\n");
            goto exit;
        }

        memcpy(&buf[written_sz], xmlNodeGetContent(cur_node), cur_node_len);

        written_sz += cur_node_len;

        cur_node = xmlNextElementSibling(cur_node);
    }

    ret = written_sz;
exit:

    return ret;
}

static void parse_pdsrem(char *str, unsigned int *list, unsigned int *p_list_sz)
{
    char *token;
    unsigned int list_strt_val, list_end_val;
    char *str1, *str2, *subtoken;
    char *saveptr1, *saveptr2;
    int i, j, k;
    *p_list_sz = 0;

    /* get the first token */
    token = str;

    /* walk through other tokens */
    if (token != NULL)
    {
        for (j = 1, str1 = token;; j++, str1 = NULL)
        {
            token = strtok_r(str1, ",", &saveptr1);
            if (token == NULL)
            {
                break;
            }

            i = 0;
            for (str2 = token;; str2 = NULL)
            {
                subtoken = strtok_r(str2, ":", &saveptr2);
                if (subtoken == NULL)
                {
                    break;
                }
                else
                {
                    i++;
                }

                if (i == 2)
                {
                    list_end_val = atoi(subtoken);

                    for (k = (list_strt_val + 1); k <= list_end_val; k++)
                    {
                        list[(*p_list_sz)] = k;
                        (*p_list_sz)++;
                    }
                }
                else
                {
                    list[(*p_list_sz)] = atoi(token);
                    list_strt_val = list[(*p_list_sz)];
                    (*p_list_sz)++;
                }
            }
        }
    }

    return;
}

/// @brief Remove specified elements from the prefilled consent and update the SC part
/// @param FPC_fname Path of the prefilled PC file for the forwarding process
/// @param rem_list List of elements to be removed
/// @param rem_list_sz Size of the previous list
/// @param D_fname Name of the corresponding D-file, where secret signing key can be found
/// @return  0: In case of success
///         -1: Otherwise
static int prepare_FPC_file(char *FPC_fname, unsigned int rem_list[], unsigned int rem_list_sz, char *D_fname)
{
    unsigned int i, j, num_children;
    int ret = 0;
    xmlDocPtr FPC_file_doc = NULL;
    xmlNode *FPC_file_root_element = NULL;
    xmlNode *FPC_file_node = NULL;
    xmlNode *D_file_root_element = NULL;
    xmlNode *D_file_node = NULL;
    xmlDocPtr D_file_doc = NULL;
    xmlNode *cur_node = NULL;
    xmlNode *del_node = NULL;    
    xmlChar  xmlPath[100];
    FILE* fp = NULL;
    int buf_sz;
    unsigned char signature_buf[256];//Size of the signature
    size_t sig_len;
    size_t b64_sig_len;

    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Removing %d elements from: %s\n", rem_list_sz, FPC_fname);

    /* Parse the file and get the DOM */
    FPC_file_doc = xmlReadFile(FPC_fname, NULL, 0);
   
    if (FPC_file_doc == NULL) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not parse file %s\n", FPC_fname);
        ret = -1;
	    goto exit;        
    }
    
    /* Get the root element node */
    FPC_file_root_element = xmlDocGetRootElement(FPC_file_doc);
    if (FPC_file_root_element == NULL) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not find the root of the file %s\n", FPC_fname);
        ret = -1;
	    goto exit;        
    }

    strcpy(xmlPath,"PC/PDS");
    FPC_file_node = xml_get_element_by_path(FPC_file_root_element, xmlPath);    

    num_children = xmlChildElementCount(FPC_file_node);
    cur_node = xmlNextElementSibling(FPC_file_node->children);

    /* Delete all the nodes from PDS[] which are present in rem_list[] */
    
    /* i iterates over FPC and j iterates over rem_list */
    for (i = 0, j = 0; ((j < rem_list_sz) && (i < num_children) && (cur_node != NULL)); i++)
    {
        /* Make 1-indexed values to 0-indexed values */
        if ((rem_list[j] - 1) == i){
            enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Removing element: %d\n", rem_list[j]);
            del_node = cur_node;
            cur_node = xmlNextElementSibling(cur_node);
            xmlUnlinkNode(del_node);
            xmlFreeNode(del_node);
            j++;
        } else if ((rem_list[j] - 1) > i) {
            cur_node = xmlNextElementSibling(cur_node);
        } else {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Code should not come here..!!\n");
            j++;
            cur_node = xmlNextElementSibling(cur_node);            
        }
    }

    /*parse the file and get the DOM */
    D_file_doc = xmlReadFile(D_fname, NULL, 0);
   
    if (D_file_doc == NULL) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "error: could not parse file %s\n", D_fname);
        ret = -1;
	    goto exit;        
    }
    
    D_file_root_element = xmlDocGetRootElement(D_file_doc);

    buf_sz = read_all_children(FPC_file_node, file_buf, FILE_BUF_SZ);
    if (buf_sz < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error during reading: %s\n", FPC_fname);
        ret = -1;
        goto exit;
    }

    strcpy(xmlPath, "PC/DH");
    FPC_file_node = xml_get_element_by_path(FPC_file_root_element, xmlPath);
    
    /* Append FPC.DH with FPC.PDS[] before calculating signature */
    memcpy(&file_buf[buf_sz], xmlNodeGetContent(FPC_file_node), 64);
    buf_sz += 64;

    strcpy(xmlPath,"D/CSK");
    D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);

    ret = S_SigB(file_buf, buf_sz, xmlNodeGetContent(D_file_node), strlen(xmlNodeGetContent(D_file_node)) + 1, signature_buf, &sig_len);
    if (ret < 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Error while creating signature with freshly generated private-key\n");
        ret = -1;
        goto exit;
    }

    ret = mbedtls_base64_encode(buf1, BUF1_SZ, &b64_sig_len, signature_buf, sig_len);
    if (ret != 0)
    {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot convert the generated signature with freshly generated private-key to base64 format\n");
        ret = -1;
        goto exit;
    }

    strcpy(xmlPath, "PC/SC");
    FPC_file_node = xml_get_element_by_path(FPC_file_root_element, xmlPath);
    xmlNodeSetContent(FPC_file_node, buf1);

    xmlSaveFileEnc(FPC_fname, FPC_file_doc, "UTF-8");

    ret = 0;

exit:
    /*free the document */
    xmlFreeDoc(FPC_file_doc);
    xmlFreeDoc(D_file_doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return ret;
}

/// @brief Starts time measurement
static void start_timing()
{
    struct timezone tz;

    if (timing_measurement_state == TIMING_MEASUREMENT_ENDED) {
        gettimeofday(&start_tv, &tz);
        timing_measurement_state = TIMING_MEASUREMENT_STARTED;
    } else {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Previous timing measurement has not finished yet\n");
    }

    return;
}

/// @brief Ends time measurement
static void end_timing()
{
    struct timezone tz;
    struct tm *now;
    char perf_log_file[100];

    if (timing_measurement_state == TIMING_MEASUREMENT_STARTED) {
        gettimeofday(&end_tv, &tz);
        total_tim = ((end_tv.tv_sec - start_tv.tv_sec)*1000000) + (end_tv.tv_usec - start_tv.tv_usec);
        timing_measurement_state = TIMING_MEASUREMENT_ENDED;

        /* Use default file for logging performance measurements */
        sprintf(perf_log_file, "./DU_storage/%d/enc_perf.log", ssl_server_listening_port);
        perf_log_fp = fopen(perf_log_file, "w");
        
        if (perf_log_fp != NULL) {
            fprintf(perf_log_fp, " %d\n", total_tim);
            fflush(perf_log_fp);

            fclose(perf_log_fp);
        } else {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Log file pointer is NULL\n");
        }
    } else {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Timing measurement has not started yet\n");
    }
    return;
}

static void aes_encrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, unsigned char *iv) {
    FILE *f, *fout;
    mbedtls_aes_context aes;
    size_t read;

    // Initialize AES context
    mbedtls_aes_init(&aes);
    
    // Set the AES encryption key
    if(mbedtls_aes_setkey_enc(&aes, key, 256) != 0) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to set AES key.\n");
        return;
    }

    // Open the input file
    f = fopen(input_filename, "rb");
    if (!f) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to open input file.\n");
        return;
    }

    // Open the output file
    fout = fopen(output_filename, "wb");
    if (!fout) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to open output file.\n");
        fclose(f);
        return;
    }

    // First perform interms of blocks
    while ((read = fread(aes_input_blk, 1, AES_BLK_SZ, f)) > 0) {
        // Padding if necessary (simple PKCS#7 padding)
        if (read < AES_BLK_SZ) {
            memset(aes_input_blk + read, AES_BLK_SZ - read, AES_BLK_SZ - read);
        }

        if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, AES_BLK_SZ, iv, aes_input_blk, aes_output_blk) != 0) {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to encrypt.\n");
            fclose(f);
            fclose(fout);
            return;
        }
        
        fwrite(aes_output_blk, 1, AES_BLK_SZ, fout);
    }

    // Clean up
    fclose(f);
    fclose(fout);
    mbedtls_aes_free(&aes);
}

static void aes_decrypt_file(const char *input_filename, const char *output_filename, const unsigned char *key, unsigned char *iv) {
    /* There is a minor problem towards the begining of the file after dcryption.
       However, this is good enough for measuring the performance. */
    FILE *f, *fout;
    mbedtls_aes_context aes;
    size_t read;
    int file_sz;

    // Initialize AES context
    mbedtls_aes_init(&aes);

    // Set the AES decryption key
    if(mbedtls_aes_setkey_dec(&aes, key, 256) != 0) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to set AES key.\n");
        return;
    }
    
    // Open the input file
    f = fopen(input_filename, "rb");
    if (!f) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to open input file.\n");
        return;
    }

    // Open the output file
    fout = fopen(output_filename, "wb");
    if (!fout) {
        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to open output file.\n");
        fclose(f);
        return;
    }
  
    while ((read = fread(aes_input_blk, 1, AES_BLK_SZ, f)) > 0) {
        if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, AES_BLK_SZ, iv, aes_input_blk, aes_output_blk) != 0) {
            enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Failed to decrypt.\n");
            fclose(f);
            fclose(fout);
            return;
        }

        // Write the decrypted block to the output file
        // Note: Proper PKCS#7 padding handling should be implemented here for the last block
        fwrite(aes_output_blk, 1, AES_BLK_SZ, fout);
    }

    //Todo, padding removal is required
    /* Get the file size */
    fseek(f, 0, SEEK_END); // seek to end of file
    file_sz = ftell(f);    // get current file pointer
    fseek(f, 0, SEEK_SET); // seek back to beginning of file    
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Encrypted file(%s) size: %d\n", input_filename, file_sz);
    fseek(fout, 0, SEEK_END); // seek to end of file
    file_sz = ftell(fout);    // get current file pointer
    fseek(fout, 0, SEEK_SET); // seek back to beginning of file
    enclave_print_log(ENCLAVE_LOG_LVL_INFO, 1, "Decrypted file(%s) size: %d\n", output_filename, file_sz);


    // Clean up
    fclose(f);
    fclose(fout);

    mbedtls_aes_free(&aes);
}
