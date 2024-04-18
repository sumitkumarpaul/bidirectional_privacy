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
#include <ctype.h>
#include <sys/time.h>
#include <libxml/parser.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
#include "../enclave_details.h"

#include <sgx_report.h>
#include "ra_tls.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define CP_LOG_LVL_ERROR 0
#define CP_LOG_LVL_PERF_RSLT 1
#define CP_LOG_LVL_MIN 2
#define CP_LOG_LVL_INFO 3
#define CP_LOG_LVL_ALL 4

unsigned int SAVED_LOG_LVL;
unsigned int CP_LOG_LVL = CP_LOG_LVL_PERF_RSLT;

#define DEBUG_LEVEL 0

#define CA_CRT_PATH "ssl/ca.crt"
#define BUF1_SZ 1024
#define FILE_BUF_SZ 16384
#define PRINT_BUF_SZ 1024
#define PADDED_CODE_SZ 16384

static bool non_sgx_du = false;

static unsigned char buf1[BUF1_SZ];
static unsigned char file_buf[FILE_BUF_SZ];
static unsigned char print_buf[PRINT_BUF_SZ];
/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];
static unsigned int lcl_du_listening_port = 0;
static unsigned int ssl_server_listening_port = 0;
static char req_s[64];
static char du_ip[16];
static char du_enc_port[6];
static mbedtls_net_context lcl_listen_fd;
static mbedtls_net_context lcl_client_fd;
static mbedtls_net_context ssl_client_server_fd;
static void *ra_tls_attest_lib;
static void *ra_tls_verify_lib;
static int (*ra_tls_create_key_and_crt_der_f)(uint8_t **der_key, size_t *der_key_size, uint8_t **der_crt, size_t *der_crt_size);
int (*ra_tls_verify_callback_extended_der_f)(uint8_t *der_crt, size_t der_crt_size, struct ra_tls_verify_callback_results *results);
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn));
static int parse_hex(const char *hex, void *buffer, size_t buffer_size);
extern int mbedtls_ssl_flush_output(mbedtls_ssl_context *ssl);

static bool g_verify_mrenclave = false;
static bool g_verify_mrsigner = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn = false;
static char attestation_type_str[32] = {0};

static mbedtls_entropy_context ssl_client_entropy;
static mbedtls_ctr_drbg_context ssl_client_ctr_drbg;
static mbedtls_ssl_context ssl_client_ssl;
static mbedtls_ssl_config ssl_client_conf;
static mbedtls_x509_crt ssl_client_cacert;

static int com_ch_init(const char *local_port);
static void com_ch_fin();
static void execute_commands();
static int lcl_du_if_init(const char *port);
static void lcl_du_if_fin();
static int lcl_du_con_accept();
static void lcl_du_con_close();
static int execute_GetCode();
static void enclave_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...);
static void ssl_debug(void *ctx, int level, const char *file, int line, const char *str);
static int ssl_client_connect();
static void ssl_client_close();
static int my_verify_measurements(const char *mrenclave, const char *mrsigner, const char *isv_prod_id, const char *isv_svn);
static int my_verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
static int ssl_write_data(mbedtls_ssl_context *p_ssl, char *write_buf, int write_len);
static int ssl_read_data(mbedtls_ssl_context *p_ssl, char *read_buf, int max_read_len);
static int ssl_send_padded_file(mbedtls_ssl_context *p_ssl, const char *file_path, unsigned int padded_size);

int main(int argc, char **argv)
{
    int ret;

    if (argc <= 2)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 0, "Usage error..!!\nRun: ./code_provider <listening TCP port> <use_sgx:sgx/non-sgx>\n");
        goto exit;
    }

    if (!strcmp(argv[2], "non-sgx"))
    {
        non_sgx_du = true;
        enclave_print_log(CP_LOG_LVL_INFO, 1, "Running CP in non-sgx mode\n");
    }

    ret = com_ch_init(argv[1]);

    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 0, "Failed to initialize the listening port..!!\n");
        goto exit;
    }

    while(1)
    {
        execute_commands();
    }

exit:
    enclave_print_log(CP_LOG_LVL_INFO, 0, "Destroying the enclave..!!\n");
    com_ch_fin();
    fflush(stdout);

    return ret;
}

static int com_ch_init(const char *local_port)
{
    int ret;

    ret = lcl_du_if_init(local_port);

    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 0, "Failed setting up the local TCP communication interface with the hosting DU..!!\n");
        goto exit;
    }

exit:
    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 0, "Destroying the listning TCP interface with DU..!!\n");
        com_ch_fin();
    }

    return ret;
}

static void com_ch_fin()
{
    lcl_du_con_close();
    lcl_du_if_fin();

    return;
}

static void execute_commands()
{
    int ret;
    char *cmd;
    unsigned char *s;
    unsigned char *ip;
    unsigned char *port;
    int is_connected = 0;

    ret = lcl_du_con_accept();

    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 0, "Failed to listen on the local TCP interface with DU..!!\n");
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, "New connection accepted, now listening for commands from DU..\n");

    while (1) {
        ret = mbedtls_net_recv(&lcl_client_fd, buf1, BUF1_SZ);

        if (ret <= 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 0, "Error during command reception from DU. Error is: %d\n", ret);
            enclave_print_log(CP_LOG_LVL_ERROR, 0, "Stopping command processing..\n");
            goto exit;
        }

        cmd = strtok(buf1, ",");

        if ((cmd != NULL) && (strncmp(buf1, "GetCode", strlen("GetCode")) == 0))
        {
            s = strtok(NULL, ",");

            if (s != NULL)
            {
                ip = strtok(NULL, ",");

                if (ip != NULL)
                {
                    port = strtok(NULL, ",");

                    if (port != NULL)
                    {
                        /* Pointer arithmatic to prepare parameters  */
                        memset(req_s, 0, sizeof(req_s));
                        memset(du_ip, 0, sizeof(du_ip));
                        memset(du_enc_port, 0, sizeof(du_enc_port));
                        memcpy(req_s, s, (ip - s - 1));
                        memcpy(du_ip, ip, (port - ip - 1));
                        memcpy(du_enc_port, port, ret - (port - buf1));

                        if (is_connected == 0){
                            ret = ssl_client_connect();

                            if (ret < 0)
                            {
                                enclave_print_log(CP_LOG_LVL_ERROR, 0, "Error while connecting with the enclave. Ret = %d\n", ret);
                                goto exit;
                            }
                            is_connected = 1;
                        }

                        ret = execute_GetCode();
                    }
                }
            }
        }
        else if ((cmd != NULL) && (strncmp(buf1, "CloseCP", strlen("CloseCP")) == 0)){
            enclave_print_log(CP_LOG_LVL_INFO, 1, "Received close request from the enclave\n");
            break;
        }
        else
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Received unknown command: %s\n", buf1); // Sumit may happen buffer overflow
            break;
        }
    }

    is_connected = 0;
exit:
    ssl_client_close();
    lcl_du_con_close();

    return;
}

static int lcl_du_if_init(const char *port)
{
    int ret;

    mbedtls_net_init(&lcl_listen_fd);

    ret = mbedtls_net_bind(&lcl_listen_fd, "0.0.0.0", port, MBEDTLS_NET_PROTO_TCP);

    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ALL, 1, " failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, "Successfully bounded the local interface with TCP port: %s\n", port);

    lcl_du_listening_port = atoi(port);
exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ALL, 1, "Last error was: %d - %s\n\n", ret, error_buf);
#endif
        lcl_du_if_fin();
    }

    return ret;
}

static void lcl_du_if_fin()
{
    mbedtls_net_free(&lcl_listen_fd);

    return;
}

static int lcl_du_con_accept()
{
    int ret;
    size_t len;

    mbedtls_net_init(&lcl_client_fd);

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Waiting for a connection request from DU...\n");

    ret = mbedtls_net_accept(&lcl_listen_fd, &lcl_client_fd, NULL, 0, NULL);

    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 0, " failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, " Established TCP connection with local DU\n");

exit:
    if (ret != 0)
    {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Last error was: %d - %s\n\n", ret, error_buf);
#endif
        lcl_du_con_close();
    }

    return ret;
}

static void lcl_du_con_close()
{
    mbedtls_net_free(&lcl_client_fd);

    return;
}

static int execute_GetCode()
{
    int ret;
    char filename[100];
    int code_id;
    int i;

    enclave_print_log(CP_LOG_LVL_INFO, 0, "Obtained request is: %s, %s, %s\n", req_s, du_ip, du_enc_port);

    code_id = atoi(req_s);

    sprintf(filename, "./code_library/code_%d/code_%d.so", code_id, code_id);

    enclave_print_log(CP_LOG_LVL_ALL, 1, "Sending the file: %s from CP to the requested DU\n", filename);
  
    ret = ssl_send_padded_file(&ssl_client_ssl, filename, PADDED_CODE_SZ);

    if (ret < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "ssl_send_padded_file returned error: %d\n", ret);
        goto exit;
    }

    ret = 0;
exit:

    return ret;
}

static void enclave_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...)
{
    int printed_size = 0;
    struct timezone tz;
    struct timeval tv;
    struct tm *now;
    va_list ap;

    if (CP_LOG_LVL >= enclave_dbg_lvl)
    {
        gettimeofday(&tv, &tz);
        now = localtime(&tv.tv_sec);

        if (now != NULL)
        {
            printed_size = snprintf(print_buf, PRINT_BUF_SZ, "[CP] [%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
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
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "%s\n", dlerror());
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Please make sure that you are using client_dcap.manifest\n");
        return 1;
    }

    if (non_sgx_du == true)
    {
        enclave_print_log(CP_LOG_LVL_INFO, 1, "!!!!!!!!!!!!!!!!!!!!!!!!! [ using normal TLS flow ]!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    }
    else
    {
        ra_tls_verify_callback_extended_der_f = dlsym(ra_tls_verify_lib,
                                                      "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "%s\n", error);
            return 1;
        }

        enclave_print_log(CP_LOG_LVL_ALL, 1, "[ using our own SGX-measurement verification callback"
                                               " (via command line options) ]\n");

        g_verify_mrenclave = true;
        g_verify_mrsigner = true;
        g_verify_isv_prod_id = false;
        g_verify_isv_svn = false;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);

        if (parse_hex(MRENCLAVE_STR, g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot parse the mrenclave\n");
            return 1;
        }

        if (parse_hex(MRSIGNER_STR, g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot parse the mrsigner\n");
            return 1;
        }

        if (parse_hex(ISV_PROD_ID_STR, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)) < 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot parse the isv_prod_id\n");
            return 1;
        }

        if (parse_hex(ISV_SVN_STR, g_expected_isv_svn, sizeof(g_expected_isv_svn)) < 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot parse the isv_svn\n");
            return 1;
        }
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, "\n  . Seeding the random number generator...");

    ret = mbedtls_ctr_drbg_seed(&ssl_client_ctr_drbg, mbedtls_entropy_func, &ssl_client_entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Connecting to tcp/%s/%s...", du_ip, du_enc_port);

    ret = mbedtls_net_connect(&ssl_client_server_fd, du_ip, du_enc_port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Setting up the SSL/TLS structure...");

    ret = mbedtls_ssl_config_defaults(&ssl_client_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse_file(&ssl_client_cacert, CA_CRT_PATH);
    if (ret < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ssl_client_conf, &ssl_client_cacert, NULL);
    enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");

    if ((ra_tls_verify_lib != NULL) && (non_sgx_du == false))
    {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&ssl_client_conf, &my_verify_callback, &my_verify_callback_results);
        enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");
    }

    mbedtls_ssl_conf_rng(&ssl_client_conf, mbedtls_ctr_drbg_random, &ssl_client_ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_client_conf, ssl_debug, stdout); // Sumit: Difference

    ret = mbedtls_ssl_setup(&ssl_client_ssl, &ssl_client_conf);
    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_client_ssl, du_ip);
    if (ret != 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_client_ssl, &ssl_client_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_client_ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "  ! ra_tls_verify_callback_results:\n"
                                                   "    attestation_scheme=%d, err_loc=%d, \n",
                              my_verify_callback_results.attestation_scheme,
                              my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme)
            {
            case RA_TLS_ATTESTATION_SCHEME_EPID:
                enclave_print_log(CP_LOG_LVL_ERROR, 1, "    epid.ias_enclave_quote_status=%s\n\n",
                                  my_verify_callback_results.epid.ias_enclave_quote_status);
                break;
            case RA_TLS_ATTESTATION_SCHEME_DCAP:
                enclave_print_log(CP_LOG_LVL_ERROR, 1, "    dcap.func_verify_quote_result=0x%x, "
                                                       "dcap.quote_verification_result=0x%x\n\n",
                                  my_verify_callback_results.dcap.func_verify_quote_result,
                                  my_verify_callback_results.dcap.quote_verification_result);
                    if (my_verify_callback_results.err_loc == 3) {
                        enclave_print_log(CP_LOG_LVL_ERROR, 1,"!!!!! Probably the environment variables are not set on the terminal\n");
                    }
                    else if (my_verify_callback_results.err_loc == 5) {
                        enclave_print_log(CP_LOG_LVL_ERROR, 1,"!!!!! Probably the code is not compiled with correct details of the enclave\n");
                    }
                    else {
                        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Unknown reason\n");
                    }
                break;
            default:
                enclave_print_log(CP_LOG_LVL_ERROR, 1, "  ! unknown attestation scheme!\n\n");
                break;
            }

            goto exit;
        }
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl_client_ssl);
    if (flags != 0)
    {
        char vrfy_buf[512];
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    }
    else
    {
        enclave_print_log(CP_LOG_LVL_ALL, 1, " ok\n");
    }

    exit_code = EXIT_SUCCESS;
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Last error was: %d - %s\n\n", ret, error_buf);
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
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Mismatch in MRENCLAVE value\n");
        return -1;
    }

    if (g_verify_mrsigner &&
        memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Mismatch in MRSIGNER value\n");
        return -1;
    }

    if (g_verify_isv_prod_id &&
        memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Mismatch in ISV_PROD_ID value\n");
        return -1;
    }

    if (g_verify_isv_svn &&
        memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Mismatch in ISV_SVN value\n");
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
    enclave_print_log(CP_LOG_LVL_ALL, 1, "  . Closing the connection...\n");

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
    int ret;
    int len = max_read_len - 1;

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  < Reading data from established ssl connection:");
    memset(read_buf, 0, max_read_len);

    do
    {
        /* Send a zero byte ack immediately */
        mbedtls_ssl_write(p_ssl, read_buf, 0);
        
        ret = mbedtls_ssl_read(p_ssl, read_buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                enclave_print_log(CP_LOG_LVL_ERROR, 1, " connection was closed gracefully\n");
                break;

            case MBEDTLS_ERR_NET_CONN_RESET:
                enclave_print_log(CP_LOG_LVL_ERROR, 1, " connection was reset by peer\n");
                break;
            
            /* 0 size may be obtained for ack from other end */
            case 0:
                break;

            default:
                enclave_print_log(CP_LOG_LVL_ERROR, 1, " mbedtls_ssl_read returned -0x%x\n", -ret);
                break;
            }

            break;
        }

        len = ret;
        enclave_print_log(CP_LOG_LVL_ALL, 1, " %lu bytes read\n", len);

        if (ret > 0)
            break;
    } while (1);

    /* Returns read-size or error */
    return ret;
}

static int ssl_write_data(mbedtls_ssl_context *p_ssl, char *write_buf, int write_len)
{
    int ret;
    int written_len;

    enclave_print_log(CP_LOG_LVL_ALL, 1, "  > Write data to established ssl connection:");

    while ((ret = mbedtls_ssl_write(p_ssl, write_buf, write_len)) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! peer closed the connection\n\n");
            break;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            break;
        }
    }

    write_len = ret;
    enclave_print_log(CP_LOG_LVL_ALL, 1, " %lu bytes written\n", write_len);

    /* Returns written length or the error code */
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

static int ssl_send_padded_file(mbedtls_ssl_context *p_ssl, const char *file_path, unsigned int padded_size)
{
    int ret = -1;
    int read_sz;
    int str_padded_sz;
    int dummy_data_end;
    int str_sz;
    int send_sz;
    int cur_send_sz;
    int file_sz = 0;
    FILE *fp;

    fp = fopen(file_path, "rb");

    if (fp == NULL)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "During SSL send, while opening the file: %s\n", file_path);
        goto exit;
    }

    /* Get the file size */
    fseek(fp, 0, SEEK_END); // seek to end of file
    file_sz = ftell(fp);    // get current file pointer
    fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    /* Send the padded size */
    str_padded_sz = snprintf(file_buf, FILE_BUF_SZ, "%d", padded_size);

    if (ssl_write_data(p_ssl, file_buf, (str_padded_sz + 1)) != (str_padded_sz + 1))
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot send the file-size properly\n");
        goto exit;
    }

    /* Wait for the SYNC message from receiver.
       As the SYNC message will be generated after sending the previous data
       so need to send 0-byte dat, so using ssl_read_data() instead of mbedtls_ssl_read() */
    do
    {
        ret = ssl_read_data(p_ssl, file_buf, BUF1_SZ);

        if (ret < 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Error while receiving the SYNC message from the enclave\n");
            goto exit;
        }
    } while (ret == 0);

    send_sz = 0;

    if (padded_size > FILE_BUF_SZ){
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "File cannot be sent in optimized way\n");
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Later you can recompile the code with larger buffer size\n");

        /* Send real data unless the file is completely sent */
        while (send_sz < file_sz)
        {
            read_sz = fread(file_buf, 1, FILE_BUF_SZ, fp);

            cur_send_sz = 0;

            while (read_sz != cur_send_sz)
            {
                ret = ssl_write_data(p_ssl, &file_buf[cur_send_sz], (read_sz - cur_send_sz));

                if (ret < 0)
                {
                    enclave_print_log(CP_LOG_LVL_ERROR, 1, "While sending the file: %s\n", file_path);
                    goto exit;
                }

                cur_send_sz += ret;
            }

            send_sz += cur_send_sz;
        }

        enclave_print_log(CP_LOG_LVL_INFO, 1, "Successfully sent real file: %d bytes of file data to the receiver\n", send_sz);

        /* Send dummy data till last 8 bytes, which will contain the real-size. 7-digit for the value and one charecter for the terminating '\0' */
        dummy_data_end = padded_size - 8;

        while (send_sz < dummy_data_end)
        {
            ret = ssl_write_data(p_ssl, file_buf, MIN((dummy_data_end - send_sz), FILE_BUF_SZ));

            if (ret < 0)
            {
                enclave_print_log(CP_LOG_LVL_ERROR, 1, "While sending the file: %s\n", file_path);
                goto exit;
            }

            send_sz += ret;
        }

        /* Convert the file-size to a 7 digit string */
        str_sz = snprintf(buf1, BUF1_SZ, "%07d", file_sz);

        /* Send the real-size of the file */
        if (ssl_write_data(p_ssl, buf1, (str_sz + 1)) != (str_sz + 1))
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot send the real file-size properly\n");
            goto exit;
        }

        enclave_print_log(CP_LOG_LVL_ALL, 1, "Sent file-size: %s\n", buf1);
    } else {
        /* Send file in optimized way by reducing the number of ssl_write_data() */
        /* Write the file_sz in string format(7 digits and one NULL charecter) at the end */
        sprintf(&file_buf[padded_size-8], "%07d", file_sz);

        /* Send real + padded data together */
        while (send_sz < padded_size)
        {
            read_sz = fread(file_buf, 1, FILE_BUF_SZ, fp);

            if (read_sz < file_sz){
                enclave_print_log(CP_LOG_LVL_ERROR, 1, "It was expected that, entire file should have been read in single call\n");
            } else {
                /* Entire file is read in a single call */
                /* Actual file size will be less than the padded size */
                read_sz = padded_size;
            }

            cur_send_sz = 0;

            while (padded_size != cur_send_sz)
            {
                ret = ssl_write_data(p_ssl, &file_buf[cur_send_sz], (read_sz - cur_send_sz));

                if (ret < 0)
                {
                    enclave_print_log(CP_LOG_LVL_ERROR, 1, "While sending the file: %s\n", file_path);
                    goto exit;
                }

                if (ret != padded_size){
                    enclave_print_log(CP_LOG_LVL_ERROR, 1, "Note entire file cannot be sent in single call, ret = %d, padded_size = %d, mbedtls_ssl_flush_output() returned: %d\n", ret, padded_size, mbedtls_ssl_flush_output(p_ssl));
                }

                cur_send_sz += ret;
            }

            send_sz += cur_send_sz;
        }

        enclave_print_log(CP_LOG_LVL_INFO, 1, "Successfully sent the padded file: %d bytes of file data to the receiver\n", send_sz);
    }

    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}