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

#include <fcntl.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/base64.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include <enclave_details.h>

#include <sgx_report.h>
#include "ra_tls.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define DO_LOG_LVL_ERROR 0
#define DO_LOG_LVL_PERF_RSLT 1
#define DO_LOG_LVL_MIN 2
#define DO_LOG_LVL_INFO 3
#define DO_LOG_LVL_ALL 4

unsigned int SAVED_LOG_LVL;
unsigned int DO_LOG_LVL = DO_DEF_LOG_LVL;

#define DEBUG_LEVEL 0

#define CA_CRT_PATH "ssl/ca.crt"
#define SRV_CRT_PATH "ssl/enclave.crt"
#define BUF1_SZ 16384
#define BUF2_SZ 10240
#define BUF3_SZ 10240
#define BUF4_SZ 10240
#define FILE_BUF_SZ 102400
#define PRINT_BUF_SZ 1024
#define PADDED_CODE_SZ 20480
#define TIMING_MEASUREMENT_ENDED 0
#define TIMING_MEASUREMENT_STARTED 1
#define DFLT_PERF_LOG_FILE "./do_perf.log"

static char pds_file[100];
static char ds_file[100];
static char DO_pri_key_file[100];
static char DO_pub_key_file[100];
static char du_port[6] = {0};
static char du_ip[16] = {0};
static char PC_file[] = "PC.xml";
static char D_file[] = "D.xml";
static bool non_sgx_du = false;
static unsigned char buf1[BUF1_SZ];
static unsigned char buf2[BUF2_SZ];
static unsigned char buf3[BUF3_SZ];
static unsigned char buf4[BUF4_SZ];
static unsigned char file_buf[FILE_BUF_SZ];
static unsigned char print_buf[PRINT_BUF_SZ];
/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];
static char du_enc_port[6] = {0};
static mbedtls_net_context lcl_listen_fd;
static mbedtls_net_context lcl_client_fd;
static mbedtls_net_context ssl_server_listen_fd;
static mbedtls_net_context ssl_server_client_fd;
static mbedtls_net_context ssl_client_server_fd;
static void *ra_tls_verify_lib;
static bool g_verify_mrenclave = false;
static bool g_verify_mrsigner = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn = false;
static mbedtls_entropy_context ssl_client_entropy;
static mbedtls_ctr_drbg_context ssl_client_ctr_drbg;
static mbedtls_ssl_context ssl_client_ssl;
static mbedtls_ssl_config ssl_client_conf;
static mbedtls_x509_crt ssl_client_cacert;
struct timeval start_tv;
struct timeval end_tv;
unsigned int total_tim;
FILE *perf_log_fp;
unsigned int timing_measurement_state = TIMING_MEASUREMENT_ENDED;
int (*ra_tls_verify_callback_extended_der_f)(uint8_t *der_crt, size_t der_crt_size, struct ra_tls_verify_callback_results *results);
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn));

static int parse_hex(const char *hex, void *buffer, size_t buffer_size);
static xmlNode *xml_get_element_by_path(xmlNode *root, xmlChar *path);
static void bin_to_hex(const unsigned char buf[], size_t len, unsigned char *op_buf);
static int file_copy(const char *source_file, const char *target_file);
static int S_SigB(const char *data_buf, size_t data_sz, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen);
static int S_SigH(char *hash_buf, const unsigned char *pri_key_buf, size_t keylen, char *sign_buf, size_t *p_olen);
static int S_KGen(char *pub_key_buf, size_t *pub_key_len, char *pri_key_buf, size_t *pri_key_len);
static int read_file_to_buf(const char *fname, char *buffer, size_t max_buf_sz);
static int read_all_children(xmlNode *node, char *buf, size_t max_buf_siz);
static int sha256_file(const char *file_path, mbedtls_sha256_context *ctx, unsigned char *sha256_buf, unsigned int real_file_sz);
static void do_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...);
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
static int ssl_client_connect();
static void ssl_client_close();
static int my_verify_measurements(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn);
static int my_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
static int ssl_write_data(mbedtls_ssl_context *p_ssl, char *write_buf, int write_len);
static int ssl_read_data(mbedtls_ssl_context *p_ssl, char *read_buf, int max_read_len);
static int ssl_recv_file(mbedtls_ssl_context *p_ssl, const char *file_path);
static int ssl_send_file(mbedtls_ssl_context *p_ssl, const char *file_path);
static int prepare_D_and_PC_file();
static void end_timing();
static void start_timing();

int main(int argc, char **argv)
{
    int ret = -1;

    if (argc < 7)
    {
        /* TODO: Instead of using public-key certificate, we are using only public-key here */
        do_print_log(DO_LOG_LVL_ERROR, 0, "Usage error..!!\nRun: ./data_owner <Path to DS file> <Path to PDS file> <Path to DO' secret-key> <Path to DO' public-key> <DU's IP> <DU's enclave's listning port>\n");
        goto exit;
    }
    
    if (argc >= 8)
    {
        if (!strcmp(argv[7], "non-sgx"))
        {
            non_sgx_du = true;
        }
    }

    do_print_log(DO_LOG_LVL_INFO, 1, "Started executing SendOrgData: %s, %s, %s, %s, %s, %s\n", ds_file, pds_file, DO_pri_key_file, DO_pub_key_file, du_ip, du_enc_port);

    if (non_sgx_du == false)
    {
        /* Start performance measurement from here for the real operation
           because we need to calculate the time requirement for the prepocessing
         */
        start_timing();
    }

    strncpy(ds_file, argv[1], 100);
    strncpy(pds_file, argv[2], 100);
    strncpy(DO_pri_key_file, argv[3], 100);
    strncpy(DO_pub_key_file, argv[4], 100);
    strncpy(du_ip, argv[5], 16);
    strncpy(du_enc_port, argv[6], 6);

    do_print_log(DO_LOG_LVL_INFO, 0, "Started SSL connection establishment with enclave\n");

    do_print_log(DO_LOG_LVL_MIN, 1, "Sending the data (%s) with approved processing statements (%s) to the DU[1,1]'s enclave\n", ds_file, pds_file);

    /* Use default file for performance measurement */
    perf_log_fp = fopen(DFLT_PERF_LOG_FILE, "w");

    ret = prepare_D_and_PC_file();

    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Error while preparing D and PC\n");
        goto exit;
    }

    do_print_log(DO_LOG_LVL_INFO, 1, "Ended RSS-like sign. operation\n");

    if (non_sgx_du == true)
    {
        /* In non-priv mode, start performance measurement after preparing the file */
        start_timing();
    }

    /* Successful connection means the remote attestation and verification of epk is done */
    ret = ssl_client_connect();
    do_print_log(DO_LOG_LVL_INFO, 1, "Competed SSL connection establishment with enclave\n");

    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Error while connecting with remote enclave\n");
        goto exit;
    }

    do_print_log(DO_LOG_LVL_INFO, 0, "Connected with the remote enclave\n");

    ret = ssl_send_file(&ssl_client_ssl, D_file);

    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Error while sending D to the remote enclave\n");
        goto exit;
    }
    
    if (non_sgx_du == true)
    {
        /* In non-priv mode (without sgx), we do not need to send consent, so stop performance measurement here */
        end_timing();
    }

    ret = ssl_send_file(&ssl_client_ssl, PC_file);

    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Error while sending PC to the remote enclave\n");
        goto exit;
    }

    /* Try read the OK message from the receiving enclave */
    do
    {
        ret = ssl_read_data(&ssl_client_ssl, buf1, BUF1_SZ);

        if (ret < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Error while receiving the OK message from the enclave\n");
            goto exit;
        }
    } while (ret == 0);

    if (strcmp(buf1, "OK\n") != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Received a message from the enclave, but that is not an OK message\n");
        goto exit;
    }

    if (non_sgx_du == false)
    {
        /* In real mode, measure time after performing all the activities */
        end_timing();
    }

    do_print_log(DO_LOG_LVL_INFO, 1, "Completed sending original data\n");
    ret = 0;

exit:
    do_print_log(DO_LOG_LVL_INFO, 0, "Closing the DO's program..!!\n");
    ssl_client_close();
    fflush(stdout);
    fclose(perf_log_fp);

    return ret;
}

static void do_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...)
{
    int printed_size = 0;
    struct timezone tz;
    struct timeval tv;
    struct tm *now;
    va_list ap;

    if (DO_LOG_LVL >= enclave_dbg_lvl)
    {
        gettimeofday(&tv, &tz);
        now = localtime(&tv.tv_sec);

        if (now != NULL)
        {
            printed_size = snprintf(print_buf, PRINT_BUF_SZ, "[DO]\t\t[%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
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

static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    fprintf((FILE *)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE *)ctx);
}

static int ssl_client_connect()
{
    int ret;
    size_t len;
    int exit_code = EXIT_FAILURE;
    uint32_t flags;
    const char *pers = "cp_ssl_client";

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

    /*
     * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
     * functions from libsgx_urts.so, thus we don't need to load this helper library.
     */
    ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
    if (!ra_tls_verify_lib)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "%s\n", dlerror());
        do_print_log(DO_LOG_LVL_ERROR, 1, "User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
        do_print_log(DO_LOG_LVL_ERROR, 1, "Please make sure that you are using client_dcap.manifest\n");
        return 1;
    }

    if (non_sgx_du == true)
    {
        do_print_log(DO_LOG_LVL_INFO, 1, "!!!!!!!!!!!!!!!!!!!!!!!!! [ using normal TLS flows ]!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
    else
    {
        ra_tls_verify_callback_extended_der_f = dlsym(ra_tls_verify_lib,
                                                      "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "%s\n", error);
            return 1;
        }

        do_print_log(DO_LOG_LVL_ALL, 1, "[ using our own SGX-measurement verification callback"
                                             " (via command line options) ]\n");

        g_verify_mrenclave = true;
        g_verify_mrsigner = true;
        g_verify_isv_prod_id = false;
        g_verify_isv_svn = false;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);

        if (parse_hex(MRENCLAVE_STR, g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot parse the mrenclave\n");
            return 1;
        }

        if (parse_hex(MRSIGNER_STR, g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot parse the mrsigner\n");
            return 1;
        }

        if (parse_hex(ISV_PROD_ID_STR, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)) < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot parse the isv_prod_id\n");
            return 1;
        }

        if (parse_hex(ISV_SVN_STR, g_expected_isv_svn, sizeof(g_expected_isv_svn)) < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot parse the isv_svn\n");
            return 1;
        }
    }

    do_print_log(DO_LOG_LVL_ALL, 1, "\n  . Seeding the random number generator...");

    ret = mbedtls_ctr_drbg_seed(&ssl_client_ctr_drbg, mbedtls_entropy_func, &ssl_client_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");

    do_print_log(DO_LOG_LVL_ALL, 1, "  . Connecting to tcp/%s/%s...", du_ip, du_enc_port);

    ret = mbedtls_net_connect(&ssl_client_server_fd, du_ip, du_enc_port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");

    do_print_log(DO_LOG_LVL_ALL, 1, "  . Setting up the SSL/TLS structure...");

    ret = mbedtls_ssl_config_defaults(&ssl_client_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");

    do_print_log(DO_LOG_LVL_ALL, 1, "  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse_file(&ssl_client_cacert, CA_CRT_PATH);
    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ssl_client_conf, &ssl_client_cacert, NULL);
    do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");

    if ((ra_tls_verify_lib != NULL) && (non_sgx_du == false))
    {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        do_print_log(DO_LOG_LVL_ALL, 1, "  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&ssl_client_conf, &my_verify_callback, &my_verify_callback_results);
        do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");
    }

    mbedtls_ssl_conf_rng(&ssl_client_conf, mbedtls_ctr_drbg_random, &ssl_client_ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_client_conf, ssl_debug, stdout); // Sumit: Difference

    ret = mbedtls_ssl_setup(&ssl_client_ssl, &ssl_client_conf);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_client_ssl, du_ip);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_client_ssl, &ssl_client_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    do_print_log(DO_LOG_LVL_ALL, 1, "  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_client_ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            do_print_log(DO_LOG_LVL_ERROR, 1, "  ! ra_tls_verify_callback_results:\n"
                                                   "    attestation_scheme=%d, err_loc=%d, \n",
                              my_verify_callback_results.attestation_scheme,
                              my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme)
            {
            case RA_TLS_ATTESTATION_SCHEME_EPID:
                do_print_log(DO_LOG_LVL_ERROR, 1, "    epid.ias_enclave_quote_status=%s\n\n",
                                  my_verify_callback_results.epid.ias_enclave_quote_status);
                break;
            case RA_TLS_ATTESTATION_SCHEME_DCAP:
                do_print_log(DO_LOG_LVL_ERROR, 1, "    dcap.func_verify_quote_result=0x%x, "
                                                       "dcap.quote_verification_result=0x%x\n\n",
                                  my_verify_callback_results.dcap.func_verify_quote_result,
                                  my_verify_callback_results.dcap.quote_verification_result);
                if (my_verify_callback_results.err_loc == 3)
                {
                    do_print_log(DO_LOG_LVL_ERROR, 1, "!!!!! Probably the environment variables are not set on the terminal\n");
                }
                else if (my_verify_callback_results.err_loc == 5)
                {
                    do_print_log(DO_LOG_LVL_ERROR, 1, "!!!!! Probably the code is not compiled with correct details of the enclave\n");
                }
                else
                {
                    do_print_log(DO_LOG_LVL_ERROR, 1, "Unknown reason\n");
                }
                break;
            default:
                do_print_log(DO_LOG_LVL_ERROR, 1, "  ! unknown attestation scheme!\n\n");
                break;
            }

            goto exit;
        }
    }

    do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");

    do_print_log(DO_LOG_LVL_ALL, 1, "  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl_client_ssl);
    if (flags != 0)
    {
        char vrfy_buf[512];
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        do_print_log(DO_LOG_LVL_ERROR, 1, "%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    }
    else
    {
        do_print_log(DO_LOG_LVL_ALL, 1, " ok\n");
    }

    exit_code = EXIT_SUCCESS;
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        do_print_log(DO_LOG_LVL_ERROR, 1, "Last error was: %d - %s\n\n", ret, error_buf);
        ssl_client_close();
    }
#endif

    return exit_code;
}

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char *mrenclave, const char *mrsigner,
                                  const char *isv_prod_id, const char *isv_svn)
{
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (g_verify_mrenclave &&
        memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Mismatch in MRENCLAVE value\n");
        return -1;
    }

    if (g_verify_mrsigner &&
        memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Mismatch in MRSIGNER value\n");
        return -1;
    }

    if (g_verify_isv_prod_id &&
        memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Mismatch in ISV_PROD_ID value\n");
        return -1;
    }

    if (g_verify_isv_svn &&
        memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Mismatch in ISV_SVN value\n");
        return -1;
    }

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

static void ssl_client_close()
{
    do_print_log(DO_LOG_LVL_ALL, 1, "  . Closing the connection...\n");

    (void)mbedtls_ssl_close_notify(&ssl_client_ssl);

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

static int ssl_read_data(mbedtls_ssl_context *p_ssl, char *read_buf, int max_read_len)
{
    int ret = -1;
    int len = max_read_len - 1;

    do_print_log(DO_LOG_LVL_ALL, 1, "  < Reading data from established ssl connection:");
    memset(read_buf, 0, max_read_len);

    do
    {
        if (ret != 0){
            mbedtls_ssl_write(p_ssl, read_buf, 0);
        }

        ret = mbedtls_ssl_read(p_ssl, read_buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, " Continueing loop, ret %d\n", ret);
            continue;
        }

        if (ret < 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                do_print_log(DO_LOG_LVL_ERROR, 1, " connection was closed gracefully\n");
                break;

            case MBEDTLS_ERR_NET_CONN_RESET:
                do_print_log(DO_LOG_LVL_ERROR, 1, " connection was reset by peer\n");
                break;

            default:
                do_print_log(DO_LOG_LVL_ERROR, 1, " mbedtls_ssl_read returned -0x%x\n", -ret);
                break;
            }

            break;
        } else if (ret == 0){
            /* 0 size may be obtained for ack from other end */
            do_print_log(DO_LOG_LVL_INFO, 1, " mbedtls_ssl_read received 0 bytes message\n");
            break;
        }

        len = ret;
        do_print_log(DO_LOG_LVL_INFO, 1, " %lu bytes read\n", len);

        if (ret > 0)
        {
            do_print_log(DO_LOG_LVL_INFO, 1, " Breaking loop, ret %d\n", ret);
            break;
        }
    } while (1);

    do_print_log(DO_LOG_LVL_INFO, 1, " Returning with, ret %d\n", ret);

    /* Returns read-size or error */
    return ret;
}

static int ssl_write_data(mbedtls_ssl_context *p_ssl, char *write_buf, int write_len)
{
    int ret;
    int written_len;

    do_print_log(DO_LOG_LVL_ALL, 1, "  > Write data to established ssl connection:");

    while ((ret = mbedtls_ssl_write(p_ssl, write_buf, write_len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! peer closed the connection\n\n");
            break;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            break;
        }
    }

    write_len = ret;
    do_print_log(DO_LOG_LVL_ALL, 1, " %lu bytes written\n", write_len);

    /* Returns written length or the error code */
    return ret;
}

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
        do_print_log(DO_LOG_LVL_ERROR, 1, "During SSL send, while opening the file: %s\n", file_path);
        goto exit;
    }

    /* Get the file size */
    fseek(fp, 0, SEEK_END); // seek to end of file
    file_sz = ftell(fp);    // get current file pointer
    fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    do_print_log(DO_LOG_LVL_INFO, 1, "Started sending the file: %s, having size: %d\n", file_path, file_sz);

    /* Convert the file-size to string */
    str_sz = snprintf(buf1, BUF1_SZ, "%d", file_sz);

    if (ssl_write_data(p_ssl, buf1, (str_sz + 1)) != (str_sz + 1))
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot send the file-size properly\n");
        goto exit;
    }

    do_print_log(DO_LOG_LVL_INFO, 1, "Sent file size properly\n");

    /* Wait for the SYNC message from receiver.
       As the SYNC message will be generated after sending the previous data
       so need to send 0-byte dat, so using ssl_read_data() instead of mbedtls_ssl_read() */
    do
    {
        ret = ssl_read_data(p_ssl, buf1, BUF1_SZ);
        
        if (ret < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Error(= %d) while receiving the SYNC message from the receiver\n", ret);
            goto exit;
        }
    } while (ret == 0);

    do_print_log(DO_LOG_LVL_INFO, 1, "Received sync message (size= %d)\n", ret);

    send_sz = 0;

    while (send_sz < file_sz)
    {
        read_sz = fread(file_buf, 1, FILE_BUF_SZ, fp);

        cur_send_sz = 0;

        while (read_sz != cur_send_sz)
        {
            ret = ssl_write_data(p_ssl, &file_buf[cur_send_sz], (read_sz - cur_send_sz));

            if (ret < 0)
            {
                do_print_log(DO_LOG_LVL_ERROR, 1, "While sending the file: %s\n", file_path);
                goto exit;
            }

            do_print_log(DO_LOG_LVL_INFO, 1, "Successfully sent: %d bytes of file data\n", ret);

            cur_send_sz += ret;

            if (cur_send_sz < read_sz){
                do_print_log(DO_LOG_LVL_INFO, 1, "Sending file in more than one iteration. Sent size: %d\n", ret);
            }
        }

        send_sz += cur_send_sz;
    }

    do_print_log(DO_LOG_LVL_INFO, 1, "Successfully sent file: %d bytes of file data to the receiver\n", send_sz);

    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

static int parse_hex(const char *hex, void *buffer, size_t buffer_size)
{
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++)
    {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t *)buffer)[i]);
    }
    return 0;
}

/// @brief Prepare the D and PC structures. Required parameters are already available via global variables.
/// @return 0: In the case of success
///        -1: Otherwise
static int prepare_D_and_PC_file()
{
    int ret = 0;
    xmlDocPtr PC_file_doc = NULL;
    xmlDocPtr D_file_doc = NULL;
    xmlNode *PC_file_root_element = NULL;
    xmlNode *D_file_root_element = NULL;
    xmlNode *PC_file_node = NULL;
    xmlNode *D_file_node = NULL;
    xmlChar xmlPath[100];
    unsigned char signature_buf[256]; // Size of the signature
    int file_sz = 0;
    int buf_sz;
    FILE *fp;
    size_t fresh_pk_len = BUF1_SZ;
    size_t fresh_sk_len = BUF2_SZ;
    size_t sig_len;
    size_t b64_sig_len;
    unsigned char sha256_buf[32];
    /* Take one byte extra for trailing NULL charecter */
    unsigned char sha256_buf_hex[64 + 1];

    /** The implementation of this function is little bit out-of order from its specification in the algorithm **/
    /** The orders are changed to make the performance measurement of RSS-like situation better **/
    /** At first, the operation with D.xml is completed and then started with PC.xml **/
    /** KeyGenerataion is not taken into account, just like the other methods **/

    /* D.DS[] = DS_{DO}[] */
    ret = file_copy(ds_file, D_file);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "File copy problem, to: %s from: %s\n", D_file, ds_file);
        ret = -1;
        goto exit;
    }

    /* Open D.xml file and complete its operation first */

    /*parse the file and get the DOM */
    D_file_doc = xmlReadFile(D_file, NULL, 0);

    if (D_file_doc == NULL)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "error: could not parse file %s\n", D_file);
        ret = -1;
        goto exit;
    }

    D_file_root_element = xmlDocGetRootElement(D_file_doc);

    /* Generate fresh key-pair */
    ret = S_KGen(buf1, &fresh_pk_len, buf2, &fresh_sk_len);
    
    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Key generation error. Ret: %d\n", ret);
        ret = -1;
        goto exit;
    }

    /* Store the freshly generated private-key in D.CSK */
    strcpy(xmlPath, "D/CSK");
    D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);
    xmlNodeSetContent(D_file_node, buf2); // buf2 is already NULL terminated

    /* Store DO's long term public-key in D.DOC */
    ret = read_file_to_buf(DO_pub_key_file, file_buf, FILE_BUF_SZ);
    if (ret < 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot read the DO's public-key file: %s\n", DO_pub_key_file);
        ret = -1;
        goto exit;
    }
    /* Make sure the buffer is NULL terminated */
    file_buf[ret] = '\0';

    strcpy(xmlPath, "D/DOC");
    D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);
    xmlNodeSetContent(D_file_node, file_buf);

    /* Set D.DOS with the signature on D.DS[]|PC.VK */
    {
        strcpy(xmlPath, "D/DS");
        D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);

        buf_sz = read_all_children(D_file_node, file_buf, FILE_BUF_SZ);
        if (buf_sz < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Error during reading: %s\n", D_file);
            ret = -1;
            goto exit;
        }

        memcpy(&file_buf[buf_sz], buf1, fresh_pk_len);
        buf_sz += fresh_pk_len;

        /* For printing purpose only, the NULL charecter is added */
        file_buf[buf_sz] = '\0';
        do_print_log(DO_LOG_LVL_ALL, 1, "D.DS[]|VK: %s\n", file_buf);

        /* Store the long term private-key to buf3 */
        ret = read_file_to_buf(DO_pri_key_file, buf3, BUF3_SZ);
        if (ret < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot read the DO's private-key file: %s\n", DO_pri_key_file);
            ret = -1;
            goto exit;
        }

        /* Append NULL charecter at the end, for the requirement of mbedtls API */
        buf3[ret] = '\0';
        ret += 1;
        ret = S_SigB(file_buf, buf_sz, buf3, ret, signature_buf, &sig_len);
        if (ret < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Error while creating signature with DO's private-key\n");
            ret = -1;
            goto exit;
        }

        ret = mbedtls_base64_encode(buf4, BUF4_SZ, &b64_sig_len, signature_buf, sig_len);
        if (ret != 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot convert the generated signature with DO's private-key to base64 format\n");
            ret = -1;
            goto exit;
        }

        strcpy(xmlPath, "D/DOS");
        D_file_node = xml_get_element_by_path(D_file_root_element, xmlPath);
        xmlNodeSetContent(D_file_node, buf4); // buf4 is already NULL terminated
    }

    /* D file is complete and now can be saved */
    xmlSaveFileEnc(D_file, D_file_doc, "UTF-8");

    do_print_log(DO_LOG_LVL_INFO, 0, "Started RSS-like sign. operation\n");

    /* PC.PDS[] = PDS_{DO}[] */
    ret = file_copy(pds_file, PC_file);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "File copy problem, to: %s from: %s\n", PC_file, pds_file);
        ret = -1;
        goto exit;
    }

    /* Parse the file and get the DOM */
    PC_file_doc = xmlReadFile(PC_file, NULL, 0);

    if (PC_file_doc == NULL)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "error: could not parse file %s\n", PC_file);
        ret = -1;
        goto exit;
    }

    /* Get the root element node */
    PC_file_root_element = xmlDocGetRootElement(PC_file_doc);
    if (PC_file_root_element == NULL)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "error: could not find the root of the file %s\n", PC_file);
        ret = -1;
        goto exit;
    }

    /* Store the fresh public-key in PC.VK */
    strcpy(xmlPath, "PC/VK");
    PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);
    xmlNodeSetContent(PC_file_node, buf1); // buf1 is already NULL terminated

    /* Update PC.DH with the hash of D */
    {
        /* Calculate SHA-256 of D */
        ret = sha256_file(D_file, NULL, sha256_buf, 0);

        if (ret < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot calculate the hash of D-file\n");
            ret = -1;
            goto exit;
        }

        bin_to_hex(sha256_buf, 32, sha256_buf_hex);

        strcpy(xmlPath, "PC/DH");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);

        /* Add the NULL charecter, otherwise it cannot be written using xmlNodeSetContent */
        sha256_buf_hex[64] = '\0';
        xmlNodeSetContent(PC_file_node, sha256_buf_hex);
    }

    /* Update PC.SC with the signature on PC.PDS[]|PC.DH */
    {
        strcpy(xmlPath, "PC/PDS");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);

        buf_sz = read_all_children(PC_file_node, file_buf, FILE_BUF_SZ);
        if (buf_sz < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Error during reading: %s\n", PC_file);
            ret = -1;
            goto exit;
        }

        /* Append PC.DH with PC.PDS[] before calculating signature */
        memcpy(&file_buf[buf_sz], sha256_buf_hex, 64);
        buf_sz += 64;

        ret = S_SigB(file_buf, buf_sz, buf2, (fresh_sk_len + 1), signature_buf, &sig_len);
        if (ret < 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Error while creating signature with freshly generated private-key\n");
            ret = -1;
            goto exit;
        }

        ret = mbedtls_base64_encode(buf4, BUF4_SZ, &b64_sig_len, signature_buf, sig_len);
        if (ret != 0)
        {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot convert the generated signature with freshly generated private-key to base64 format\n");
            ret = -1;
            goto exit;
        }

        strcpy(xmlPath, "PC/SC");
        PC_file_node = xml_get_element_by_path(PC_file_root_element, xmlPath);
        xmlNodeSetContent(PC_file_node, buf4);
    }

    xmlSaveFileEnc(PC_file, PC_file_doc, "UTF-8");

exit:
    /*free the documents */
    xmlFreeDoc(D_file_doc);
    xmlFreeDoc(PC_file_doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return ret;
}

static xmlNode *xml_get_element_by_path(xmlNode *root, xmlChar *path)
{
    xmlNode *cur_node = root;
    char *token;
    int children_num;
    int max_children_num;
    int i;
    xmlNode *node = NULL;

    token = strtok(path, "/:");
    while (cur_node != NULL)
    {
        if (cur_node->type == XML_ELEMENT_NODE)
        {
            if (xmlStrcmp(token, cur_node->name) != 0)
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
                            printf("Not enough number of children nodes. Expected :%d, has: %d\n", children_num, max_children_num);
                            break;
                        }

                        /* Go to the i-th children. For first children no need to move to next */
                        for (i = 2; ((cur_node != NULL) && (i <= children_num)); i++)
                        {
                            cur_node = xmlNextElementSibling(cur_node);
                        }

                        token = strtok(NULL, "/:");
                        printf("Current path is: %s\n", xmlGetNodePath(cur_node));

                        if (token == NULL)
                        {
                            node = cur_node;
                            printf("Travarsal completed, the value of the path: %s, is: %s\n", xmlGetNodePath(cur_node), xmlNodeGetContent(cur_node));
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

static void bin_to_hex(const unsigned char buf[], size_t len, unsigned char *op_buf)
{
    for (size_t i = 0; i < len; i++)
    {
        sprintf(op_buf, "%02x", buf[i]);
        op_buf += 2;
    }
}

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
        printf("Cannot open: %s\n", source_file);
        goto exit;
    }

    fseek(source, 0, SEEK_END);  // seek to end of file
    src_file_sz = ftell(source); // get current file pointer
    fseek(source, 0, SEEK_SET);  // seek back to beginning of file

    target = fopen(target_file, "wb");

    if (target == NULL)
    {
        printf("Cannot open: %s\n", target_file);
        goto exit;
    }

    while (copied_sz < src_file_sz)
    {
        read_sz = fread(file_buf, 1, FILE_BUF_SZ, source);
        write_sz = fwrite(file_buf, 1, read_sz, target);

        if (read_sz != write_sz)
        {
            printf("Read and write size are different\n");
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

/// @brief Generates a new RSA-2048 keypair
/// @param pub_key_buf Buffer for storing the newly generated public-key as a PEM string
/// @param pub_key_len When calling, this must hold the maximum length of the input buffer.
///                    During output, it returns the strlen of the generated PEM string
/// @param pri_key_buf Buffer for storing the newly generated private-key as a PEM string
/// @param pub_key_len When calling, this must hold the maximum length of the input buffer.
///                    During output, it returns the strlen of the generated PEM string
/// @return 0: During success
///        -1: During failure
static int S_KGen(char *pub_key_buf, size_t *pub_key_len, char *pri_key_buf, size_t *pri_key_len)
{
    int ret = 1;
    int exit_code = -1;
    mbedtls_pk_context key;
    int i;
    char *p, *q;

    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    /*
     * Set to sane values
     */
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    do_print_log(DO_LOG_LVL_ALL, 1, "\n  . Seeding the random number generator...\n");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n",
                          (unsigned int)-ret);
        goto exit;
    }

    /*
     * 1.1. Generate the key
     */
    do_print_log(DO_LOG_LVL_ALL, 1, "\n  . Generating the private key ...\n");
    fflush(stdout);

    if ((ret = mbedtls_pk_setup(&key,
                                mbedtls_pk_info_from_type((mbedtls_pk_type_t)MBEDTLS_PK_RSA))) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_pk_setup returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                              2048, 65537);
    if (ret != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_rsa_gen_key returned -0x%04x\n",
                          (unsigned int)-ret);
        goto exit;
    }

    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

    if ((ret = mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP)) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! could not export RSA parameters\n\n");
        goto exit;
    }

    do_print_log(DO_LOG_LVL_ALL, 1, "  . Copying keys to buffer...\n");

    if ((ret = mbedtls_pk_write_key_pem(&key, pri_key_buf, *pri_key_len)) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed to write generated private key\n");
        goto exit;
    }

    *pri_key_len = strlen(pri_key_buf);

    if ((ret = mbedtls_pk_write_pubkey_pem(&key, pub_key_buf, *pub_key_len)) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed to write generated private key\n");
        goto exit;
    }

    *pub_key_len = strlen(pub_key_buf);

    do_print_log(DO_LOG_LVL_INFO, 1, "Key generation successful..!!\n");

    ret = 0;

exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        memset(buf1, 0, sizeof(buf1));
        mbedtls_strerror(ret, buf1, sizeof(buf1));
        do_print_log(DO_LOG_LVL_ERROR, 1, " - %s\n", buf1);
#else
        mbedtls_printf("\n");
#endif
    }

    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);

    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

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

    do_print_log(DO_LOG_LVL_ALL, 1, "\n  . Seeding the random number generator for signing the buffer...");

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    do_print_log(DO_LOG_LVL_ALL, 1, "\n  . Reading private key from the buffer\n");

    if ((ret = mbedtls_pk_parse_key(&pk, (unsigned char *)pri_key_buf, keylen, /*pwd=*/NULL, 0, mbedtls_ctr_drbg_random, NULL)) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! Could not read key\n");
        do_print_log(DO_LOG_LVL_ERROR, 1, "  ! mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    if (!mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA))
    {
        ret = 1;
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! Key is not an RSA key\n");
        goto exit;
    }

    /* Use PKCS_V15 format to make it compatible with linux command */
    mbedtls_rsa_set_padding(mbedtls_pk_rsa(pk), MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

    do_print_log(DO_LOG_LVL_ALL, 1, "\n  . Generating the RSA/SHA-256 signature");

    if ((ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash_buf, 32, sign_buf, MBEDTLS_PK_SIGNATURE_MAX_SIZE, p_olen,
                               mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_pk_sign returned %d\n\n", ret);
        goto exit;
    }

    do_print_log(DO_LOG_LVL_INFO, 1, "\n  . Signature successful\n");

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

    do_print_log(DO_LOG_LVL_INFO, 0, "Return from signature generation call: %d\n", ret);

    return ret;
}

/// @brief Read the content of a file into a buffer
/// @param fname The name of the file
/// @param buffer Input buffer
/// @param max_buf_sz Maximum size of the input buffer
/// @return In case of success, returns the size of the file
///         In the case of failure, returns -1
static int read_file_to_buf(const char *fname, char *buffer, size_t max_buf_sz)
{
    /* declare a file pointer */
    FILE *infile = NULL;
    long numbytes;
    int ret = -1;

    /* open an existing file for reading */
    infile = fopen(fname, "r");

    /* quit if the file does not exist */
    if (infile == NULL)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot open the file: %s for reading\n", fname);
        goto exit;
    }

    /* Get the number of bytes */
    fseek(infile, 0L, SEEK_END);
    numbytes = ftell(infile);

    if (numbytes > max_buf_sz)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "The buffer cannot hold the file content\n");
        goto exit;
    }

    /* reset the file position indicator to
    the beginning of the file */
    fseek(infile, 0L, SEEK_SET);

    /* copy all the text into the buffer */
    ret = fread(buffer, sizeof(char), numbytes, infile);
    if (numbytes != ret)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot read all the file content. Read only: %d bytes out of %d bytes\n", ret, numbytes);
        ret = -1;
        goto exit;
    }

exit:
    fclose(infile);

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
            do_print_log(DO_LOG_LVL_ERROR, 1, "No more space in the buffer\n");
            goto exit;
        }

        // do_print_log(DO_LOG_LVL_ERROR, 1, "Value of child: %d is: %s\n", i, xmlNodeGetContent(cur_node));

        memcpy(&buf[written_sz], xmlNodeGetContent(cur_node), cur_node_len);

        written_sz += cur_node_len;

        cur_node = xmlNextElementSibling(cur_node);
    }

    ret = written_sz;
exit:

    return ret;
}

/// @brief Generate a SHA-256 hash of an input file
/// @param file_path Location of the input file
/// @param ctx Already opened SHA256 context, maybe used for updating an existing hash. Can be NULL.
/// @param sha256_buf Output buffer for holding the SHA-256 hash. The output size will always be 32.
/// @param real_file_sz Size of the input file. If specified as 0, then the function will calculate it.
/// @return 0: In the case of success
///        -1: Otherwise
static int sha256_file(const char *file_path, mbedtls_sha256_context *ctx, unsigned char *sha256_buf, unsigned int real_file_sz)
{
    int ret = -1;
    FILE *fp;
    int read_sz = 0;
    int cur_read_sz;
    mbedtls_sha256_context local_sha256_ctx;

    fp = fopen(file_path, "rb");

    do_print_log(DO_LOG_LVL_ALL, 1, "Real file size: %d\n", real_file_sz);

    if (fp == NULL)
    {
        do_print_log(DO_LOG_LVL_ERROR, 1, "During SHA256 calculation, cannot open the file: %s\n", file_path);
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
            do_print_log(DO_LOG_LVL_ERROR, 1, "Cannot read the file: %s\n", file_path);
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


/// @brief Starts time measurement
static void start_timing()
{
    struct timezone tz;

    if (timing_measurement_state == TIMING_MEASUREMENT_ENDED) {
        gettimeofday(&start_tv, &tz);
        timing_measurement_state = TIMING_MEASUREMENT_STARTED;
    } else {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Previous timing measurement has not finished yet\n");
    }

    return;
}

/// @brief Ends time measurement
static void end_timing()
{
    struct timezone tz;
    struct tm *now;

    if (timing_measurement_state == TIMING_MEASUREMENT_STARTED) {
        gettimeofday(&end_tv, &tz);
        total_tim = ((end_tv.tv_sec - start_tv.tv_sec)*1000000) + (end_tv.tv_usec - start_tv.tv_usec);
        timing_measurement_state = TIMING_MEASUREMENT_ENDED;
        if (perf_log_fp != NULL) {
            fprintf(perf_log_fp, " %d\n", total_tim);
            fflush(perf_log_fp);
        } else {
            do_print_log(DO_LOG_LVL_ERROR, 1, "Log file pointer is NULL\n");
        }
    } else {
        do_print_log(DO_LOG_LVL_ERROR, 1, "Timing measurement has not started yet\n");
    }
    return;
}
