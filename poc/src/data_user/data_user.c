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
#include <libxml/tree.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

#include <sgx_report.h>
#include "ra_tls.h"
#include <enclave_details.h>

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define CP_LOG_LVL_ERROR 0
#define CP_LOG_LVL_MIN   1
#define CP_LOG_LVL_INFO  2
#define CP_LOG_LVL_ALL   3

#define CP_LOG_LVL CP_LOG_LVL_ALL

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MALICIOUS_STR "MALICIOUS DATA"

#define CA_CRT_PATH "ssl/ca.crt"
#define SRV_CRT_PATH "ssl/enclave.crt"
#define SRV_KEY_PATH "ssl/enclave.key"
#define DE_BUF_SZ    1024
#define ES_BUF_SZ    1024
#define BUF1_SZ	     1024
#define FILE_BUF_SZ  10240
#define PRINT_BUF_SZ 1024
#define PADDED_CODE_SZ 20480
#define SERVER_PORT "4433"

char secret_key_file[] = "xmlrss/testdata/do_secret_key.pem";
char public_key_file[] = "xmlrss/testdata/do_public_key.pem";
char pds_file[] = "pds.xml";
char pc_file[] = "pc.xml";
char red_file[] = "red.xml";
char exported_redkey_file[] = "redkey.obj";
char ds_file[] = "ds.xml";
char du_port[6];
char du_ip[] = "127.0.0.1";
char pc_file_name[100];
char ds_file_name[100];
int num_pd;
int num_di;

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
static char remote_du_enc_ssl_port[6];
static char own_enc_port[6];
static mbedtls_net_context lcl_listen_fd;
static mbedtls_net_context lcl_client_fd;
static mbedtls_net_context ssl_server_listen_fd;
static mbedtls_net_context ssl_server_client_fd;
static mbedtls_net_context ssl_client_server_fd;
static void* ra_tls_attest_lib;
static void* ra_tls_verify_lib;
static int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt, size_t* der_crt_size);
int (*ra_tls_verify_callback_extended_der_f)(uint8_t* der_crt, size_t der_crt_size, struct ra_tls_verify_callback_results* results);
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner, const char* isv_prod_id, const char* isv_svn));
static int parse_hex(const char* hex, void* buffer, size_t buffer_size);
static xmlNode* xml_get_element_by_path(xmlNode * root, xmlChar* path);
static int setHashInPDS();
static int sha256_file(const char* file_path, mbedtls_sha256_context* ctx, unsigned char* sha256_buf);
static void bin_to_hex(const unsigned char buf[], size_t len, unsigned char* op_buf);
static int redact_file(unsigned int num_red_pd);

static uint8_t* der_key = NULL;
static uint8_t* der_crt = NULL;

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;
static bool g_in_sgx		 = false;
static char attestation_type_str[32] = {0};

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
static mbedtls_net_context enclave_con_fd;


static int com_ch_init(const char* local_port);
static void com_ch_fin();
static void execute_commands();
static int lcl_du_if_init(const char* port);
static void lcl_du_if_fin();
static int ssl_server_init();
static void ssl_server_fin();
static int lcl_du_con_accept();
static void lcl_du_con_close();
static int ssl_server_con_accept();
static void ssl_server_con_close();
static void execute_Compute();
static void execute_SaveData();
static void execute_GetCode();
static void execute_LSetup();
static void execute_SetKey();
static void enclave_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...);
static void ssl_debug(void* ctx, int level, const char* file, int line, const char* str);
static int ssl_client_connect();
static void ssl_client_close();
static int my_verify_measurements(const char* mrenclave, const char* mrsigner, const char* isv_prod_id, const char* isv_svn);
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
static int ssl_write_data(mbedtls_ssl_context* p_ssl,char* write_buf, int write_len);
static int ssl_read_data(mbedtls_ssl_context* p_ssl, char* read_buf, int max_read_len);
static ssize_t read_dev_file(const char* path, char* buf, size_t count);
static ssize_t write_dev_file(const char* path, char* buf, size_t count);
static int ssl_recv_file(mbedtls_ssl_context* p_ssl, const char* file_path);
static int ssl_send_file(mbedtls_ssl_context* p_ssl, const char* file_path);
static int ssl_send_padded_file(mbedtls_ssl_context* p_ssl, const char* file_path, unsigned int padded_size);
static int prepare_D_file();
static int prepare_PDS_file();
static int send_message_to_enclave(const char* msg_buf, unsigned int msg_sz);

static int exp_file_write(const char* str) {
    int ret;
   // declaring a file pointer
   FILE *filePointer;

   // opening the file in write mode
   filePointer = fopen("/enc/test.txt", "w");
   
   if (filePointer != NULL) {
       // using fwrite(), writing the above char array into the specified file
       ret = fwrite(str, 1, strlen(str), filePointer);

       enclave_print_log(CP_LOG_LVL_ERROR, 1,"fwrite returned %d\n", ret);

       // closing the file
       fclose(filePointer);
   } else {
       enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot open the file\n");
   }
   
    return ret;
}

static int exp_file_read() {
    int ret;
   // declaring a file pointer
   FILE *filePointer;

   // initializing a char array which we have to write into the file
   char buffer[100];

   // opening the file in write mode
   filePointer = fopen("/enc/test.txt", "r");
   
   if (filePointer != NULL) {
       // using fwrite(), writing the above char array into the specified file
       ret = fread(buffer, 1, sizeof(buffer), filePointer);

       enclave_print_log(CP_LOG_LVL_ERROR, 1,"fread returned %d, its content is: %s\n", ret, buffer);

       // closing the file
       fclose(filePointer);
   } else {
       enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot open the file\n");
   }
   
    return ret;
}

int main(int argc, char** argv) {
    int ret = 0;
    char command[1000];
    char* tok;
    size_t cmd_sz;

    /* Similar to sending original data by data-owner */
    if (argc != 2){
        printf("Please run as: ./data_user <own enclave's listening port>\n");
        return -1;
    }
    strncpy(own_enc_port, argv[1], sizeof(own_enc_port));
    
    mbedtls_net_init(&enclave_con_fd);
    
    ret = mbedtls_net_connect(&enclave_con_fd, du_ip, own_enc_port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! cannot communicate with enclave %d\n\n", ret);
        goto exit;
    }
    
    while (1){
        printf("Please enter you command:");
        tok = fgets(command, sizeof(command), stdin);

        printf("The command is: %s", command);

        if(strncmp(command, "Init", sizeof("Init")) == 0){
            printf("Here\n");
            ret = send_message_to_enclave("SetKey", sizeof("SetKey"));
            
            if (ret <= 0) {
                enclave_print_log(CP_LOG_LVL_ERROR, 1," Enclave returned unexpected value: %d\n\n", ret);
            } else {
                tok = strtok(command, ",");

                if (tok == NULL)
                {
                    enclave_print_log(CP_LOG_LVL_ERROR, 1, "Problem while parsing the \"Init\" command\n");
                    ret = -1;
                }
                else
                {
                    tok = strtok(NULL, ",");
                }

                if ((tok == NULL) || (ret == -1))
                {
                    enclave_print_log(CP_LOG_LVL_ERROR, 1, "Problem while parsing the rest of the command\n");
                    ret = -1;
                }
                else
                {
                    cmd_sz = sprintf(buf1, "TEESetup,%s", tok);
                    /* At first obtain the data */
                    ret = send_message_to_enclave(buf1, cmd_sz);

                    if (ret <= 0)
                    {
                        enclave_print_log(CP_LOG_LVL_ERROR, 1," Enclave returned unexpected value: %d\n\n", ret);
                    }
                }
            }
        }
    }

    
exit:
    send_message_to_enclave("Finalize", sizeof("Finalize"));

    com_ch_fin();
    fflush(stdout);

    return ret;    
}

static int com_ch_init(const char* local_port) {
    int ret;

    ret = lcl_du_if_init(local_port);

    if(ret != 0) {
	enclave_print_log(CP_LOG_LVL_ERROR, 0,"Failed setting up the local TCP communication interface with the hosting DU..!!\n");
	goto exit;
    }
    
    ret = lcl_du_con_accept();
    
    if(ret != 0) {
	enclave_print_log(CP_LOG_LVL_ERROR, 0,"Failed to listen on the local TCP interface with DU..!!\n");
	goto exit;
    }
    
exit:
    if (ret != 0) {
	enclave_print_log(CP_LOG_LVL_ERROR, 0,"Destroying the local TCP interface with DU..!!\n");
	com_ch_fin();
    }

    return ret;
}

static void com_ch_fin(){
    lcl_du_con_close();
    lcl_du_if_fin();

    return;
}

static void execute_commands(){
    int ret;
    char* cmd;
    unsigned char* s;
    unsigned char* ip;
    unsigned char* port;

    enclave_print_log(CP_LOG_LVL_ALL, 1,"Listening for commands from local DU..\n");

    while (1) {
	ret = mbedtls_net_recv(&lcl_client_fd, buf1, BUF1_SZ);

	if (ret <= 0) {
	    enclave_print_log(CP_LOG_LVL_ERROR, 0,"Error during command reception from DU. Error is: %d\n", ret);
	    enclave_print_log(CP_LOG_LVL_ERROR, 0,"Stopping command processing..\n");
	    break;
        }

	cmd = strtok(buf1, ",");

	if ((cmd != NULL) && (strncmp(buf1, "GetCode", strlen("GetCode")) == 0))
	{
	   s = strtok(NULL, ",");

	   if(s != NULL) {
	   	ip = strtok(NULL, ",");
	   	
		if(ip != NULL) {
	   	    port = strtok(NULL, ",");

		    if (port != NULL) {
			/* Pointer arithmatic to prepare parameters  */
		    	memset(req_s, 0, sizeof(req_s));
		    	memset(du_ip, 0, sizeof(du_ip));
		    	memset(remote_du_enc_ssl_port, 0, sizeof(remote_du_enc_ssl_port));
		        memcpy(req_s, s, (ip - s - 1));
		        memcpy(du_ip, ip, (port - ip - 1));
		        memcpy(remote_du_enc_ssl_port, port, ret - (port - buf1) - 1);

	   		execute_GetCode();
		    }
	   	}
	   }
	}
	else
	{
	    enclave_print_log(CP_LOG_LVL_ERROR, 1,"Received unknown command: %s\n", buf1);//Sumit may happen buffer overflow
	}
    }
    
    return;
}

static int lcl_du_if_init(const char* port) {
    int ret;
    
    mbedtls_net_init(&lcl_listen_fd);

    ret = mbedtls_net_bind(&lcl_listen_fd, "localhost", port, MBEDTLS_NET_PROTO_TCP);
    
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ALL, 1," failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }
    
    enclave_print_log(CP_LOG_LVL_ALL, 1,"Successfully bounded the local interface with TCP port: %s\n", port);

   lcl_du_listening_port = atoi(port); 
exit:
    if (ret != 0) {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ALL, 1,"Last error was: %d - %s\n\n", ret, error_buf);
#endif
	lcl_du_if_fin();
    
    }

    return ret;
}

static void lcl_du_if_fin() {
    mbedtls_net_free(&lcl_listen_fd);

    return;
}

static int ssl_server_init() {
    int ret;
    const char* pers = "ssl_server";
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

    //SSL's port must be one more than the local DU's port
    ssl_server_listening_port = lcl_du_listening_port + 1;
    sprintf(port, "%d", ssl_server_listening_port);

    if ((g_in_sgx == false) || (!strcmp(attestation_type_str, "none"))) {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            enclave_print_log(CP_LOG_LVL_ALL, 1,"User requested RA-TLS attestation but cannot find lib\n");
            return 1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            enclave_print_log(CP_LOG_LVL_ALL, 1,"%s\n", error);
            return 1;
        }
    } else {
        enclave_print_log(CP_LOG_LVL_ALL, 1,"Unrecognized remote attestation type: %s\n", attestation_type_str);
        return 1;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Seeding the random number generator...\n");

    ret = mbedtls_ctr_drbg_seed(&ssl_server_ctr_drbg, mbedtls_entropy_func, &ssl_server_entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    if (ra_tls_attest_lib) {
        enclave_print_log(CP_LOG_LVL_ALL, 1,"\n  . Creating the RA-TLS enclave cert and key (using \"%s\" as "
                       "attestation type)...", attestation_type_str);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&ssl_server_srvcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&ssl_server_pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ssl_server_ctr_drbg);
        if (ret != 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }
    } else {
        enclave_print_log(CP_LOG_LVL_ALL, 1,"\n  . Creating normal enclave cert and key...");

        ret = mbedtls_x509_crt_parse_file(&ssl_server_srvcert, SRV_CRT_PATH);
        if (ret != 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse_file(&ssl_server_srvcert, CA_CRT_PATH);
        if (ret != 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_keyfile(&ssl_server_pkey, SRV_KEY_PATH, /*password=*/NULL,
                                       mbedtls_ctr_drbg_random, &ssl_server_ctr_drbg);
        if (ret != 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
            goto exit;
        }

        enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Bind on https://localhost:%s/ ...", port);

    ret = mbedtls_net_bind(&ssl_server_listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Setting up the SSL data....");

    ret = mbedtls_ssl_config_defaults(&ssl_server_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&ssl_server_conf, mbedtls_ctr_drbg_random, &ssl_server_ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_server_conf, ssl_debug, stdout);

    if (!ra_tls_attest_lib) {
        /* no RA-TLS attest library present, use embedded CA chain */
        mbedtls_ssl_conf_ca_chain(&ssl_server_conf, ssl_server_srvcert.next, NULL);
    }

    ret = mbedtls_ssl_conf_own_cert(&ssl_server_conf, &ssl_server_srvcert, &ssl_server_pkey);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl_server_ssl, &ssl_server_conf);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

exit:
    if (ret != 0) {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ALL, 1,"Last error was: %d - %s\n\n", ret, error_buf);
#endif
	ssl_server_fin();
    }

    return ret;
}

static void ssl_server_fin() {
    
    if (ra_tls_attest_lib) {
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
    free(der_crt);

    return;
}

static int lcl_du_con_accept() {
    int ret;
    size_t len;
    
    mbedtls_net_init(&lcl_client_fd);

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Waiting for a connection with local DU...\n");

    ret = mbedtls_net_accept(&lcl_listen_fd, &lcl_client_fd, NULL, 0, NULL);

    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 0," failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," Established TCP connection with local DU\n");

exit:
    if (ret != 0) {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Last error was: %d - %s\n\n", ret, error_buf);
#endif
	lcl_du_con_close();
    }

    return ret;
}

static void lcl_du_con_close() {
    mbedtls_net_free(&lcl_client_fd);

    return;
}

static int ssl_server_con_accept() {
    int ret;
    size_t len;
    
    mbedtls_net_init(&ssl_server_client_fd);
    
    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Waiting for a remote connection from a ssl client...");

    ret = mbedtls_net_accept(&ssl_server_listen_fd, &ssl_server_client_fd, NULL, 0, NULL);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_server_ssl, &ssl_server_client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_server_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto exit;
        }
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," Established SSL connection with remote ssl client\n");

    ret = 0;

exit:
    if (ret != 0) {
#ifdef MBEDTLS_ERROR_C
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ALL, 1,"Last error was: %d - %s\n\n", ret, error_buf);
#endif
	ssl_server_con_close();
    }

    return ret;
}

static void ssl_server_con_close() {
    int ret;
    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Closing the ssl connection...\n");

    (void)mbedtls_ssl_close_notify(&ssl_server_ssl);

    mbedtls_ssl_session_reset(&ssl_server_ssl);
    mbedtls_net_free(&ssl_server_client_fd);

    return;
}

static void execute_SetKey() {
    int ret;

    enclave_print_log(CP_LOG_LVL_ALL, 1,"Within the function: %s\n", __func__);

    ret = ssl_server_init();
    
    if(ret != 0) {
	enclave_print_log(CP_LOG_LVL_ALL, 1,"Failed setting up the ssl communication interface with the remote parties..!!\n");
	goto exit;
    }
exit:
    if(ret != 0) {
	ssl_server_fin();
    }

    return;
}

static void execute_LSetup() {
    enclave_print_log(CP_LOG_LVL_ALL, 1,"Within the function: %s\n", __func__);

    return;
}

static void execute_GetCode() {
    int ret;
    char filename[100];

    enclave_print_log(CP_LOG_LVL_ALL, 1,"Obtained request is: %s, %s, %s\n", req_s, du_ip, remote_du_enc_ssl_port);

    //TODO: Check the access

    ret = ssl_client_connect();
    
    if (ret < 0) {
        goto exit;
    }
   
#if 0
    ret = ssl_write_data(&ssl_client_ssl, GET_REQUEST, sizeof(GET_REQUEST));
    
    if (ret <= 0) {
        goto exit;
    }

    ret = ssl_read_data(&ssl_client_ssl, buf1, BUF1_SZ);
    
    if (ret <= 0) {
        goto exit;
    }

    for (int i = 0; i < 4; i++) {
        sprintf(filename, "./code_library/code_%d/code_%d.so", i,i);

        enclave_print_log(CP_LOG_LVL_ALL, 1,"Sending the file: %s from CP to the requested DU\n", filename);
    
        ret = ssl_send_file(&ssl_client_ssl, filename);
    
        if (ret < 0) {
            goto exit;
        }
    }
#endif
        sprintf(filename, "./code_library/code_%d/code_%d.so", 0,0);

        enclave_print_log(CP_LOG_LVL_ALL, 1,"Sending the file: %s from CP to the requested DU\n", filename);
    
        ret = ssl_send_padded_file(&ssl_client_ssl, filename, PADDED_CODE_SZ);

    
        if (ret < 0) {
            goto exit;
        }
        sprintf(filename, "./code_library/code_%d/code_%d.so", 4,4);

        enclave_print_log(CP_LOG_LVL_ALL, 1,"Sending the file: %s from CP to the requested DU\n", filename);
    
        ret = ssl_send_padded_file(&ssl_client_ssl, filename, PADDED_CODE_SZ);
    
        if (ret < 0) {
            goto exit;
        }
        sprintf(filename, "./code_library/code_%d/code_%d.so", 3,3);

        enclave_print_log(CP_LOG_LVL_ALL, 1,"Sending the file: %s from CP to the requested DU\n", filename);
    
        ret = ssl_send_padded_file(&ssl_client_ssl, filename, PADDED_CODE_SZ);
    
        if (ret < 0) {
            goto exit;
        }
        sprintf(filename, "./code_library/code_%d/code_%d.so", 9,9);

        enclave_print_log(CP_LOG_LVL_ALL, 1,"Sending the file: %s from CP to the requested DU\n", filename);
    
        ret = ssl_send_padded_file(&ssl_client_ssl, filename, PADDED_CODE_SZ);
    
        if (ret < 0) {
            goto exit;
        }
#if 0    
    enclave_print_log(CP_LOG_LVL_ALL, 1,"Receiving a file from server\n");
    
    ret = ssl_recv_file(&ssl_client_ssl, "./received_file_from_server");
    
    if (ret < 0) {
        goto exit;
    }
#endif

exit:
    ssl_client_close();

    return;
}

static void execute_SaveData() {
    int ret;
    int len;

    enclave_print_log(CP_LOG_LVL_ALL, 1,"Within the function: %s\n", __func__);
    
    ret = ssl_server_con_accept();

    if (ret < 0) {
        goto exit;
    }
    
    ret = ssl_read_data(&ssl_server_ssl, buf1, BUF1_SZ);
    
    if (ret <= 0) {
        goto exit;
    }
   
    len = sprintf((char*)buf1, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl_server_ssl));
    
    ret = ssl_write_data(&ssl_server_ssl, buf1, len);
    
    if (ret <= 0) {
        goto exit;
    }
    
    enclave_print_log(CP_LOG_LVL_ALL, 1,"Receiving a file from client\n");
    
    ret = ssl_recv_file(&ssl_server_ssl, "./received_file_from_client");
    
    if (ret < 0) {
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1,"Sending a file from server to client\n");
    
    ret = ssl_send_file(&ssl_server_ssl, "./received_file_from_client");
    
    if (ret < 0) {
        goto exit;
    }
   
exit:
    ssl_server_con_close();

    return;
}

static void execute_Compute() {
    enclave_print_log(CP_LOG_LVL_ALL, 1,"Within the function: %s\n", __func__);

    return;
}

static void enclave_print_log(int enclave_dbg_lvl, int do_flush, const char *fmt, ...) {
    int printed_size = 0;
    struct timezone tz;
    struct timeval tv;
    struct tm* now;
    va_list ap;
 
    if (CP_LOG_LVL >= enclave_dbg_lvl) {
        gettimeofday(&tv, &tz);
	now = localtime(&tv.tv_sec);

	if (now != NULL) {
            printed_size = snprintf(print_buf, PRINT_BUF_SZ, "[DU.] [%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
	}

        va_start(ap, fmt);
        vsnprintf(&print_buf[printed_size], (PRINT_BUF_SZ-printed_size-1), fmt, ap);
        va_end(ap);
        printf("%s", print_buf);

	if (do_flush != 0) {
	    fflush(stdout);
	}
    }

    return;
}

static void ssl_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

static int ssl_client_connect() {
    int ret;
    size_t len;
    int exit_code = EXIT_FAILURE;
    uint32_t flags;
    const char* pers = "cp_ssl_client";

    char* error;
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
    if (!ra_tls_verify_lib) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"%s\n", dlerror());
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Please make sure that you are using client_dcap.manifest\n");
        return 1;
    }

    if (non_sgx_du == true) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"!!!!!!!!!!!!!!!!!!!!!!!!! [ using normal TLS flows ]!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    } else {
        ra_tls_verify_callback_extended_der_f = dlsym(ra_tls_verify_lib,
                                                      "ra_tls_verify_callback_extended_der");
        if ((error = dlerror()) != NULL) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"%s\n", error);
            return 1;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"%s\n", error);
            return 1;
        }

        enclave_print_log(CP_LOG_LVL_ALL, 1,"[ using our own SGX-measurement verification callback"
                       " (via command line options) ]\n");

        g_verify_mrenclave   = true;
        g_verify_mrsigner    = true;
        g_verify_isv_prod_id = false;
        g_verify_isv_svn     = false;

        (*ra_tls_set_measurement_callback_f)(my_verify_measurements);
        
        if (parse_hex(MRENCLAVE_STR, g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot parse the mrenclave\n");
            return 1;
        }
    
        if (parse_hex(MRSIGNER_STR, g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot parse the mrsigner\n");
            return 1;
        }
        
        if (parse_hex(ISV_PROD_ID_STR, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)) < 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot parse the isv_prod_id\n");
            return 1;
        }
        
        if (parse_hex(ISV_SVN_STR, g_expected_isv_svn, sizeof(g_expected_isv_svn)) < 0) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot parse the isv_svn\n");
            return 1;
        }
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1,"\n  . Seeding the random number generator...");

    ret = mbedtls_ctr_drbg_seed(&ssl_client_ctr_drbg, mbedtls_entropy_func, &ssl_client_entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Connecting to tcp/%s/%s...", du_ip, remote_du_enc_ssl_port);

    ret = mbedtls_net_connect(&ssl_client_server_fd, du_ip, remote_du_enc_ssl_port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Setting up the SSL/TLS structure...");

    ret = mbedtls_ssl_config_defaults(&ssl_client_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse_file(&ssl_client_cacert, CA_CRT_PATH);
    if (ret < 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&ssl_client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&ssl_client_conf, &ssl_client_cacert, NULL);
    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    if ((ra_tls_verify_lib != NULL) && (non_sgx_du == false)) {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&ssl_client_conf, &my_verify_callback, &my_verify_callback_results);
        enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");
    }

    mbedtls_ssl_conf_rng(&ssl_client_conf, mbedtls_ctr_drbg_random, &ssl_client_ctr_drbg);
    mbedtls_ssl_conf_dbg(&ssl_client_conf, ssl_debug, stdout);//Sumit: Difference

    ret = mbedtls_ssl_setup(&ssl_client_ssl, &ssl_client_conf);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl_client_ssl, du_ip);
    if (ret != 0) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl_client_ssl, &ssl_client_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl_client_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
            enclave_print_log(CP_LOG_LVL_ERROR, 1,"  ! ra_tls_verify_callback_results:\n"
                           "    attestation_scheme=%d, err_loc=%d, \n",
                           my_verify_callback_results.attestation_scheme,
                           my_verify_callback_results.err_loc);
            switch (my_verify_callback_results.attestation_scheme) {
                case RA_TLS_ATTESTATION_SCHEME_EPID:
                    enclave_print_log(CP_LOG_LVL_ERROR, 1,"    epid.ias_enclave_quote_status=%s\n\n",
                                   my_verify_callback_results.epid.ias_enclave_quote_status);
                    break;
                case RA_TLS_ATTESTATION_SCHEME_DCAP:
                    enclave_print_log(CP_LOG_LVL_ERROR, 1,"    dcap.func_verify_quote_result=0x%x, "
                                   "dcap.quote_verification_result=0x%x\n\n",
                                   my_verify_callback_results.dcap.func_verify_quote_result,
                                   my_verify_callback_results.dcap.quote_verification_result);
                    break;
                default:
                    enclave_print_log(CP_LOG_LVL_ERROR, 1,"  ! unknown attestation scheme!\n\n");
                    break;
            }

            goto exit;
        }
    }

    enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&ssl_client_ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    } else {
        enclave_print_log(CP_LOG_LVL_ALL, 1," ok\n");
    }

    exit_code = EXIT_SUCCESS;
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Last error was: %d - %s\n\n", ret, error_buf);
        ssl_client_close();
    }
#endif

    return exit_code;
}

static int send_message_to_enclave(const char* msg_buf, unsigned int msg_sz) {
    int ret;
    size_t len;
    int exit_code = EXIT_FAILURE;
    uint32_t flags;
    exit_code = EXIT_SUCCESS;

    ret = mbedtls_net_send(&enclave_con_fd, msg_buf, msg_sz);
    if( msg_sz != ret)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Cannot send the entire message to the enclave, returned value is: %d\n\n", ret);
        goto exit;
    }

    /* Wait for receiving message*/
    ret = mbedtls_net_recv(&enclave_con_fd, buf1, BUF1_SZ);

    if(ret <= 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Error, enclave returned wrong value: %s\n\n", buf1);
        goto exit;
    }

    enclave_print_log(CP_LOG_LVL_ERROR, 1,"Enclave returned: %s\n", buf1);
    
exit:
#ifdef MBEDTLS_ERROR_C
    if (exit_code != EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Last error was: %d - %s\n\n", ret, error_buf);
        /* Do not close if there is not a problem */
        mbedtls_net_free(&enclave_con_fd);
    }
#endif
    
    return exit_code;
}

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
                                  const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);
    
    if (g_verify_mrenclave && 
            memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave))) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Mismatch in MRENCLAVE value\n");
        return -1;
    }

    if (g_verify_mrsigner &&
            memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner))) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Mismatch in MRSIGNER value\n");
        return -1;
    }
    
    if (g_verify_isv_prod_id &&
            memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id))) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Mismatch in ISV_PROD_ID value\n");
        return -1;
    }
    
    if (g_verify_isv_svn &&
            memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn))) {
        enclave_print_log(CP_LOG_LVL_ERROR, 1,"Mismatch in ISV_SVN value\n");
        return -1;
    }
    
    return 0;
}

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_extended_der_f(crt->raw.p, crt->raw.len,
                                                 (struct ra_tls_verify_callback_results*)data);
}

static void ssl_client_close() {
    enclave_print_log(CP_LOG_LVL_ALL, 1,"  . Closing the connection...\n");

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

static int ssl_read_data(mbedtls_ssl_context* p_ssl, char* read_buf, int max_read_len) {
    int ret;
    int len = max_read_len - 1;
    
    enclave_print_log(CP_LOG_LVL_ALL, 1,"  < Reading data from established ssl connection:");
    memset(read_buf, 0, max_read_len);
    
    do {
        /* Send a zero byte ack immediately */
        mbedtls_ssl_write(p_ssl, read_buf, 0);

        ret = mbedtls_ssl_read(p_ssl, read_buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    enclave_print_log(CP_LOG_LVL_ERROR, 1," connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    enclave_print_log(CP_LOG_LVL_ERROR, 1," connection was reset by peer\n");
                    break;

                /* 0 size may be obtained for ack from other end */
                case 0:
                    break;

                default:
                    enclave_print_log(CP_LOG_LVL_ERROR, 1," mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        enclave_print_log(CP_LOG_LVL_ALL, 1," %lu bytes read\n", len);

        if (ret > 0)
            break;
    } while (1);

    /* Returns read-size or error */    
    return ret;
}

static int ssl_write_data(mbedtls_ssl_context* p_ssl,char* write_buf, int write_len) {
    int ret;
    int written_len;

    enclave_print_log(CP_LOG_LVL_ALL, 1,"  > Write data to established ssl connection:");

    while ((ret = mbedtls_ssl_write(p_ssl, write_buf, write_len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! peer closed the connection\n\n");
            break;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            enclave_print_log(CP_LOG_LVL_ERROR, 1," failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            break;
        }
    }

    write_len = ret;
    enclave_print_log(CP_LOG_LVL_ALL, 1," %lu bytes written\n", write_len);

    /* Returns written length or the error code */
    return ret;
}

static ssize_t read_dev_file(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    
    if (!f) {
        return -errno;
    }

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
	enclave_print_log(CP_LOG_LVL_ERROR, 1,"Error during file read: %d\n", -errsv);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0) {
	enclave_print_log(CP_LOG_LVL_ERROR, 1,"Error during file close: %d\n", -errno);
        return -errno;
    }

    return bytes;
}

static ssize_t write_dev_file(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "a");
    if (!f) {
	enclave_print_log(CP_LOG_LVL_ERROR, 1,"Error during file open: %d\n", -errno);
        return -errno;
    }

    fseek(f, 0L, SEEK_END);

    ssize_t bytes = fwrite(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
	enclave_print_log(CP_LOG_LVL_ERROR, 1,"Error during file write: %d\n", -errsv);
	return -errsv;
    }

    fseek(f, 0L, SEEK_END);

    int close_ret = fclose(f);
    if (close_ret < 0) {
	enclave_print_log(CP_LOG_LVL_ERROR, 1,"Error during file close: %d\n", -errno);
        return -errno;
    }

    return bytes;
}

static int ssl_send_file(mbedtls_ssl_context* p_ssl, const char* file_path)
{
	int ret = -1;
	int read_sz;
	int str_sz;
	int send_sz;
	int cur_send_sz;
	int file_sz = 0;
	FILE* fp;

	fp = fopen(file_path, "rb");
	
	if (fp == NULL)
	{
		enclave_print_log(CP_LOG_LVL_ERROR, 1, "During SSL send, while opening the file: %s\n", file_path);
		goto exit;
	}
	
	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file


    /* Convert the file-size to string */
    str_sz = snprintf(buf1, BUF1_SZ, "%d", file_sz);

    if (ssl_write_data(p_ssl, buf1, (str_sz + 1)) != (str_sz + 1))
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot send the file-size properly\n");
        goto exit;
    }
    
    /* Wait for the SYNC message from receiver */
    if (ssl_read_data(p_ssl, buf1, BUF1_SZ) < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Error while receiving the SYNC message from the receiver\n");
        goto exit;
    }

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
				enclave_print_log(CP_LOG_LVL_ERROR, 1, "While sending the file: %s\n", file_path);
				goto exit;
			}

			cur_send_sz += ret;
		}

        send_sz += cur_send_sz;
	}

	enclave_print_log(CP_LOG_LVL_INFO, 1, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

exit:
	if (fp != NULL)
	{
		fclose(fp);
	}
    
    return ret;
}

static int ssl_recv_file(mbedtls_ssl_context* p_ssl, const char* file_path)
{
    int ret = -1;
    int write_sz;
    int cur_recv_sz;
    int cur_write_sz;
    int file_sz;
    int recv_sz;
    FILE* fp;

    fp = fopen(file_path, "wb");
    
    if (fp == NULL)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "While creating the file: %s\n", file_path);
        goto exit;
    }
        
    /* First read the file size */
    if(ssl_read_data(p_ssl, buf1, BUF1_SZ) < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Problem while receiving the file size\n");
        goto exit;
    }
    
    file_sz = atoi(buf1);
    if(file_sz < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Receiving file size is < 0\n");
        goto exit;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(ssl_write_data(p_ssl, buf1, 1) < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Problem while sending the SYNC message, during file-transfer\n");
        goto exit;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        cur_recv_sz = ssl_read_data(p_ssl, file_buf, FILE_BUF_SZ);

        if(cur_recv_sz < 0)
        {
            enclave_print_log(CP_LOG_LVL_ERROR, 1, "Problem while receiving data for the file: %d\n", cur_recv_sz);
            goto exit;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            ret = fwrite(&file_buf[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

            if (ret < 0)
            {
                enclave_print_log(CP_LOG_LVL_ERROR, 1, "Error while writing to the file: %d\n", ret);
                goto exit;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }

    enclave_print_log(CP_LOG_LVL_INFO, 1, "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = 0;

exit:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}

static int ssl_send_padded_file(mbedtls_ssl_context* p_ssl, const char* file_path, unsigned int padded_size)
{
	int ret = -1;
	int read_sz;
	int str_padded_sz;
	int dummy_data_end;
	int str_sz;
	int send_sz;
	int cur_send_sz;
	int file_sz = 0;
	FILE* fp;

	fp = fopen(file_path, "rb");
	
	if (fp == NULL)
	{
		enclave_print_log(CP_LOG_LVL_ERROR, 1, "During SSL send, while opening the file: %s\n", file_path);
		goto exit;
	}
	
	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    /* Send the padded size */
    str_padded_sz = snprintf(buf1, BUF1_SZ, "%d", padded_size);

    if (ssl_write_data(p_ssl, buf1, (str_padded_sz + 1)) != (str_padded_sz + 1))
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot send the file-size properly\n");
        goto exit;
    }
    
    /* Wait for the SYNC message from receiver */
    if (ssl_read_data(p_ssl, buf1, BUF1_SZ) < 0)
    {
        enclave_print_log(CP_LOG_LVL_ERROR, 1, "Error while receiving the SYNC message from the receiver\n");
        goto exit;
    }

    send_sz = 0;

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

       enclave_print_log(CP_LOG_LVL_ERROR, 1, "Sent file-size: %s\n", buf1);

    ret = 0;

exit:
	if (fp != NULL)
	{
		fclose(fp);
	}
    
    return ret;
}


static int setHashInPDS() {
    int ret;
    xmlDocPtr doc = NULL;
    xmlNode *root_element = NULL;
    xmlNode *node = NULL;
    xmlChar  xmlPath[100];
    mbedtls_sha256_context sha256_ctx;
    unsigned char sha256_buf[64];
    unsigned char sha256_hex_buf[32+1] = {0};

    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
    doc = xmlReadFile(pc_file_name, NULL, 0);

    strcpy(xmlPath,"PC/DH");
    if (doc == NULL) {
        printf("error: could not parse file %s\n", pc_file_name);
    }

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);
    node = xml_get_element_by_path(root_element, xmlPath);
    
    num_pd = xmlChildElementCount(node);

   #if 0 
    if(node != NULL) {
    	printf("The path: %s, has: %ld children\n", xmlGetNodePath(node), xmlChildElementCount(node));
	if(xmlChildElementCount(node) == 0) {
	    printf("It is a leaf element, having value: %s\n", xmlNodeGetContent(node));
	    //xmlNodeSetContent(node, "Airbus 380");
	    //xmlSaveFile("/home/sumit/phd-uottawa-research/Research/Experimentation/redactable-signature/xmlrss/testdata/vehicles_output.xml", doc);
	}  
	}
	#endif
    mbedtls_sha256_init(&sha256_ctx);

	/* TODO: Chance of performance improvement, receiving the chunk of a file and simultaneously update of sha256 can be */
	mbedtls_sha256_starts(&sha256_ctx, 0); /* SHA-256, not 224 */

	/* TODO: Required to remove the padding */

	/* TODO: Required to check, it is not dummy */

	/* TODO: Check auditor's signature */
	ret = sha256_file(ds_file_name, &sha256_ctx, sha256_buf);

	if (ret < 0)
	{
		printf("Cannot calculate the file-hash\n");
	}

	mbedtls_sha256_finish(&sha256_ctx, sha256_buf);
	bin_to_hex(sha256_buf, 32, sha256_hex_buf);
	xmlNodeSetContent(node, sha256_hex_buf);
	
        strcpy(xmlPath,"PC/PDS");
        node = xml_get_element_by_path(root_element, xmlPath);
    
        num_pd = xmlChildElementCount(node);	
	xmlSaveFileEnc(pc_file_name, doc, "UTF-8");

    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();


	return ret;
}

static int prepare_D_file() {
    int ret;
    xmlDocPtr doc = NULL;
    xmlNode *root_element = NULL;
    xmlNode *node = NULL;
    xmlChar  xmlPath[100];
    unsigned char signature_buf[350];//Size of the signature
    int file_sz = 0;
    FILE* fp;

    LIBXML_TEST_VERSION

    /*parse the file and get the DOM */
    doc = xmlReadFile(ds_file_name, NULL, 0);

    strcpy(xmlPath,"D/SRK");
    if (doc == NULL) {
        printf("error: could not parse file %s\n", pc_file_name);
    }

    /*Get the root element node */
    root_element = xmlDocGetRootElement(doc);
    node = xml_get_element_by_path(root_element, xmlPath);

    //*********** Note: This part is not implemented, but dummy
    //On average the signing takes 12247us by openssl in normal environment
    usleep(12247);
            
    //*********** Note: This part is not implemented, but dummy
    //Base 64 encoding of Signature has size 344 bytes
    memset(signature_buf, 'D', 350);
    xmlNodeSetContent(node, signature_buf);
	
    /* Next sibling node should be DOC */
    node = xmlNextElementSibling(node);

    fp = fopen(public_key_file, "rb");
	
    if (fp == NULL)
    {
	enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot open the public-key file: %s\n", public_key_file);
	goto exit;
    }
	
    /* Get the file size */
    fseek(fp, 0, SEEK_END); // seek to end of file
    file_sz = ftell(fp); // get current file pointer
    fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    if (fp == NULL)
    {
	enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot open the public-key file: %s\n", public_key_file);
	goto exit;
    }
        
    if(file_sz != fread(file_buf, 1, FILE_BUF_SZ, fp))
    {
	enclave_print_log(CP_LOG_LVL_ERROR, 1, "Cannot read the public-key file: %s\n", public_key_file);
	goto exit;
    }
    file_buf[file_sz] = '\0';
    
    xmlNodeSetContent(node, file_buf);
	
    xmlSaveFileEnc(ds_file_name, doc, "UTF-8");

exit:
    /*free the document */
    xmlFreeDoc(doc);

    /*
     *Free the global variables that may
     *have been allocated by the parser.
     */
    xmlCleanupParser();

    return ret;
}

static int redact_file(unsigned int num_red_pd) {
    int ret;
    char command[1000];

    /* Call the Java program to redact the pds file */
    sprintf(command, "java -jar xmlrss/xmlrss-1.0-SNAPSHOT.jar Red %s %d %s %s", pc_file, num_red_pd, exported_redkey_file, red_file);
    ret = system(command);
    
    if (ret != 0) {
        printf("The return of the command: %s is: %d\n", command, ret);
    }

    return ret;
}

static xmlNode* xml_get_element_by_path(xmlNode * root, xmlChar* path)
{
    xmlNode *cur_node = root;
    char *token;
    int children_num;
    int max_children_num;
    int i;
    xmlNode* node = NULL;
    
	token = strtok(path, "/:");
	while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE) {
	    //printf("Current path is: %s\n", xmlGetNodePath(cur_node));
	    //printf("Token is: %s\n", token);
	    if(xmlStrcmp(token, cur_node->name) != 0) {
	    	//printf("Mismatch with the document..!! Expected :%s, got: %s\n", token, cur_node->name);
	    	//printf("Current path is(%d): %s\n", __LINE__, xmlGetNodePath(cur_node));
		
			cur_node = xmlNextElementSibling(cur_node);
			//printf("Jumping to: %s\n", cur_node->name);
			continue;
	    } else {
	        //printf("Matched token: %s\n", token);
	
	        /* If match, then find whether there is any numerics mentioned  */
    	        token = strtok(NULL, "/:");

	        /* User specified path has completed */
	        if(token == NULL) {
	       	    //printf("Travarsal completed, the value of the path: %s, is: %s\n", xmlGetNodePath(cur_node), xmlNodeGetContent(cur_node));
		    	node = cur_node;
	            break;
	        } else {
	           //printf("Newly found token is: %s\n", token);
	           children_num = atoi(token);

		   /* Check whether it is a numeric one */
		   if (children_num != 0) {
	    	       //printf("Here(%d)\n",__LINE__);
	       	       //printf("Node is: %s\n",cur_node->name);
	       	       //printf("Parent is: %s\n", cur_node->parent->name);
	               max_children_num = xmlChildElementCount(cur_node->parent);
	               
		       if (children_num > max_children_num){
	       	           printf("Not enough number of children nodes. Expected :%d, has: %d\n", children_num, max_children_num);
	                   break;
	               }

	               /* Go to the i-th children. For first children no need to move to next */
	               for(i = 2; ((cur_node != NULL) && (i <= children_num)); i++) {
	                   cur_node = xmlNextElementSibling(cur_node);
	               }
               
    	               token = strtok(NULL, "/:");
	               printf("Current path is: %s\n", xmlGetNodePath(cur_node));

		       if(token == NULL) {
		       	   node = cur_node;
	       	    	   printf("Travarsal completed, the value of the path: %s, is: %s\n", xmlGetNodePath(cur_node), xmlNodeGetContent(cur_node));
		           break;
		       }
		   }
		       
	    	   //printf("Here(%d)\n",__LINE__);
		   cur_node = cur_node->children;
	        }
            }
        } else {
	    cur_node = cur_node->next;
	}
	
	//printf("Here(%d)\n",__LINE__);
    }

    return node;
}

int sha256_file(const char* file_path, mbedtls_sha256_context* ctx, unsigned char* sha256_buf) {
    int ret = -1;
    FILE* fp;
    int read_sz = 0;
    int file_sz = 0;
    int cur_read_sz;
    
    fp = fopen(file_path, "rb");
       
    if (fp == NULL)
    {
	//enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "During SHA256 calculation, cannot open the file: %s\n", file_path);
	printf("During SHA256 calculation, cannot open the file: %s\n", file_path);
	goto exit;
    }

	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file

    while(read_sz < file_sz) {
        cur_read_sz = fread(file_buf, 1, FILE_BUF_SZ, fp);
        
        if(cur_read_sz <= 0) {
    //        enclave_print_log(ENCLAVE_LOG_LVL_ERROR, 1, "Cannot read the file: %s\n", file_path);
	        printf("Cannot read the file: %s\n", file_path);
	    goto exit;
        }
        
        read_sz += cur_read_sz;
        
        /* As the file has not ended here, it may read the dummy data as well */
        if (read_sz > file_sz) {
            cur_read_sz -=(read_sz - file_sz);
        }
        
        mbedtls_sha256_update(ctx, file_buf, cur_read_sz);
    }
    
    ret = 0;
    
exit:
    if (fp != NULL) {
        fclose(fp);
    }
    
    return ret;
}

static void bin_to_hex(const unsigned char buf[], size_t len, unsigned char* op_buf)
{
    //printf("%s: ", title);

    for (size_t i = 0; i < len; i++) {
        sprintf(op_buf, "%02x", buf[i]);
        op_buf += 2;
    }

    //printf("%s", op_buf);

    //printf("\r\n");
}
