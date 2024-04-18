#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/ts.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "ts_verifier_info.h"

#define ENC_BUF_SZ 204800
#define ENC_DO_EXP_TIME_FILE "./data_exp_time.txt"
#define EXP_TIM_STR_SZ          11   /* Epoch time is a string of 10 digits */
#define CA_FILE "../test_data_creater/certs/ca-cert.pem"

char g_enc_buffer[ENC_BUF_SZ];
char g_enc_buffer1[ENC_BUF_SZ];
char g_do_priv_data[ENC_BUF_SZ];

char *g_server_cert;
char *g_server_priv_key;
char g_do_exp_tim[20];
char *g_ts_ip = "127.0.0.1";
int g_ts_port = 1240;

static int enc_trusted_time_comparison();
int enc_access_all_data(char *priv_data_file, int *p_file_sz);
static int enc_get_trusted_time(time_t *p_cur_trusted_tim);
static int enc_create_ts_req(char* p_op_buf, int max_req_len, TS_REQ **p_ts_req);
static int enc_send_buff_to_file(int conn_sock, char *buff, int buff_size);
static int enc_recv_file_to_buf(int conn_sock, char *buff, int *p_recv_sz, int max_buf_sz);
static int enc_connect_to_ts_server(const char* ip, int port);
static int enc_get_ts_resp(char *req_buf, char *resp_buf, int req_sz, int *p_rsp_sz);
static int enc_verify_cb(int ok, X509_STORE_CTX *ctx);
static int enc_verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz, TS_REQ *ts_req, time_t *p_rcvd_ts);
int enc_get_priv_data_val(X509 *data_x509, int extension_num, char *return_buf, int *return_len);
void enc_private_data_file_close(X509* data_file_X509);
X509* enc_private_data_file_open(const char* data_file_path, int *file_data_sz);
int enc_check_data_expiry(const char* expiry_time_file);
void enc_print_log(const char *fmt, ...);
int enc_ssl_send_file(SSL* ssl, const char* file_path);
int enc_ssl_recv_file(SSL* ssl, const char* file_path, char* recv_buff, int *p_recv_sz);
int enc_ssl_recv_data(SSL* ssl, char* data_buf);
int enc_ssl_send_data(SSL* ssl, const char* data_buf, int data_sz);
int enc_data_usage();
int sample_client_client_cert_verify(int preverify_ok, X509_STORE_CTX *x509_ctx);

int sample_client_client_cert_verify(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    int ret = 1;

    /* Using all the variables for resolving the computation warnings */
    if (preverify_ok && (x509_ctx != NULL))
    {
        ret = 1;
    }

    return ret;
}

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, g_server_cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, g_server_priv_key, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;
    int port;
    struct sockaddr_in addr;
    unsigned int len = sizeof(addr);
    SSL *ssl;
    int client;
    int priv_data_sz;
    X509 *client_cert;
    char *str;
  STACK_OF(X509_NAME) *list;

    if (argc < 3)
    {
        printf("Usage: ./u_data_user <Listening port> <Server certificate> <Private key of the server> \n");
        exit(0);
    }
    else
    {
        port = atoi(argv[1]);
        g_server_cert = argv[2];
        g_server_priv_key = argv[3];
    }

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(port);

    /* Handle connections */

    client = accept(sock, (struct sockaddr*)&addr, &len);
    
    if (client < 0)
    {
        perror("Unable to accept");
        exit(EXIT_FAILURE);
    }

    list = SSL_load_client_CA_file(CA_FILE);
    
    if( list == NULL ) {
        perror("Unable to load client CA file");
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_client_CA_list(ctx, list );

    if(SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) < 1)
    {
        printf("TLS server: unable to set verify location\n");
        goto exit;
    }
    
    
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, sample_client_client_cert_verify);
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);

    client_cert = SSL_get_peer_certificate(ssl);
    
    if(client_cert != NULL) {
        printf("Client certificate: \n");

        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        printf("\t subject: %s\n", str);
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        printf("\t issuer: %s\n", str);
        OPENSSL_free(str);

        X509_free(client_cert);
    }
    
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        goto exit;
    }
    else
    {
        if(enc_ssl_recv_data(ssl, g_do_exp_tim) <= 0)
        {
            printf("Problem during receiving the expiry time\n");
            goto exit;
        }
       
        /* Receive the private data into a file, in memory */
        if(enc_ssl_recv_file(ssl, "./do_priv_data.tmp", NULL, &priv_data_sz) != 0)
        {
            printf("Problem during receiving the file containing the certified private data of the data owner\n");
            goto exit;
        }
        
        enc_data_usage();
        
        enc_print_log("Data-user: After accessing the data\n"); 
    }

exit:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    close(sock);
    SSL_CTX_free(ctx);
}

int enc_ssl_send_data(SSL* ssl, const char* data_buf, int data_sz)
{
    int ret = 0;
    int error = 0;
    int bytes_written = 0;
    int total_bytes_written = 0;
    
    while (data_sz != total_bytes_written)
    {
        bytes_written = SSL_write(ssl, &data_buf[total_bytes_written], (size_t)(data_sz - total_bytes_written));

        error = SSL_get_error(ssl, bytes_written);
        if ((error != SSL_ERROR_WANT_WRITE) && (bytes_written <= 0))
        {
            /* Actual error */
            printf( "Failed! SSL_write returned %d, only %d bytes out of %d bytes written successfully\n", error, total_bytes_written, data_sz);
            ret = -1;
            break;
        }

        total_bytes_written += bytes_written;
        ret = total_bytes_written;
    }
            
    //printf( "Successfully sent %d bytes of ssl-data\n", total_bytes_written);

    return ret;
}

int enc_ssl_recv_data(SSL* ssl, char* data_buf)
{
    int ret = -1;
    int error = 0;
    int bytes_read = 0;
    int total_bytes_read = 0;
        
    //memset(data_buf, 0, ENC_BUF_SZ);
    
    do
    {
        bytes_read = SSL_read(ssl, &data_buf[total_bytes_read], (ENC_BUF_SZ - total_bytes_read));
        error = SSL_get_error(ssl, bytes_read);
       
        if ((bytes_read <= 0) && (error != SSL_ERROR_WANT_READ))
        {
            printf( "Failed! SSL_read returned error = %d, till now successfully received = %d bytes\n", error, total_bytes_read);
            goto exit;
        }
        else if ((bytes_read > 0) && (error == SSL_ERROR_NONE))
        {
            total_bytes_read += bytes_read;
            ret = total_bytes_read;
            break;
        }
            
        total_bytes_read += bytes_read;

    } while (1);

    ret = total_bytes_read;
        
    //printf( " %d bytes read\n", total_bytes_read);
  
exit: 
    /* Returns the number of bytes read */ 
    return ret;
}

/* Receive a file over a SSL connection */
int enc_ssl_recv_file(SSL* ssl, const char* file_path, char* recv_buff, int *p_recv_sz)
{
    int ret = -1;
    int cur_recv_sz;
    int cur_write_sz;
    int file_sz;
    int recv_sz;
    FILE* fp = NULL;
    /* By default the reading happens in global buffer */
    char* read_buff = g_enc_buffer;

    if(p_recv_sz != NULL)
    {
        *p_recv_sz = 0;
    }
    
    /* User may send NULL pointer to receive data into the buffer only */
    if (file_path != NULL)
    {
        fp = fopen(file_path, "wb");
    
        if (fp == NULL)
        {
            printf( "While creating the file: %s\n", file_path);
            goto error_handling;
        }
    }

    if (recv_buff != NULL)
    {
        read_buff = recv_buff;
        printf( "Reading file into the user-provided buffer\n");
    }
        
    //bzero(g_enc_buffer, ENC_BUF_SZ);

    /* First read the file size */
    if(enc_ssl_recv_data(ssl, g_enc_buffer) < 0)
    {
        printf( "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(g_enc_buffer);
    if(file_sz < 0)
    {
        printf( "Receiving file size is < 0\n");
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(enc_ssl_send_data(ssl, g_enc_buffer, 1) < 0)
    {
        printf( "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        cur_recv_sz = enc_ssl_recv_data(ssl, &read_buff[recv_sz]);

        if(cur_recv_sz < 0)
        {
            printf( "Problem while receiving data\n");
            goto error_handling;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            if (file_path != NULL)
            {
                ret = fwrite(&read_buff[recv_sz + cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

                if (ret < 0)
                {
                    printf( "While writing to the file\n");
                    goto error_handling;
                }
            }
            else
            {
                /* If file path was not mentioned then write to the buffer only */
                ret = cur_recv_sz;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }
    
    if(p_recv_sz != NULL)
    {
        *p_recv_sz = recv_sz;
    }

    //printf( "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = 0;

error_handling:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/* Send a file over an SSL connection */
int enc_ssl_send_file(SSL* ssl, const char* file_path)
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
		printf( "While opening the file\n");
		goto error_handling;
	}
	
	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file

	//bzero(g_enc_buffer, ENC_BUF_SZ);

    /* Convert the file-size to string */
    str_sz = snprintf(g_enc_buffer, ENC_BUF_SZ, "%d", file_sz);

    if (enc_ssl_send_data(ssl, g_enc_buffer, (str_sz + 1)) != (str_sz + 1))
    {
        printf( "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (enc_ssl_recv_data(ssl, g_enc_buffer) < 0)
    {
        printf( "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != file_sz)
	{
		//bzero(g_enc_buffer, ENC_BUF_SZ);

		read_sz = fread(g_enc_buffer, 1, ENC_BUF_SZ, fp);

        cur_send_sz = 0;

		while (read_sz != cur_send_sz)
		{
			ret = enc_ssl_send_data(ssl, &g_enc_buffer[cur_send_sz], (read_sz - cur_send_sz));

			if (ret < 0)
			{
 				printf( "While sending the file: %s\n", file_path);
				goto error_handling;
			}

			cur_send_sz += ret;
		}

        send_sz += cur_send_sz;
	}

	//printf( "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
	if (fp != NULL)
	{
		fclose(fp);
	}
    
    return ret;
}

int enc_data_usage()
{
    int ret = -1;
    int file_sz = 0;
    
    char *priv_data_file = "./do_priv_data.tmp";

    ret = enc_access_all_data(priv_data_file, &file_sz);
       
    return ret;
}

//void enc_print_log(int enc_debug_level, const char *fmt, ...)
void enc_print_log(const char *fmt, ...)
{
    int printed_size;
    struct timeval tv;
    struct tm* now;
    va_list ap;
    struct timezone tz;
  
    //if (ENC_LOG_LEVEL >= enc_debug_level)
    if (1)
    { 
        gettimeofday(&tv, &tz);
        now = localtime(&tv.tv_sec);
        va_start(ap, fmt);
        printed_size = snprintf(g_enc_buffer, BUFSIZ, "[%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
        vsnprintf(&g_enc_buffer[printed_size], (BUFSIZ-printed_size-1), fmt, ap);
        va_end(ap);
        printf("%s", g_enc_buffer);
    }
}

int enc_access_all_data(char *priv_data_file, int *p_file_sz)
{
    int ret = -1;
    X509* priv_data_x509 = NULL;
    const STACK_OF(X509_EXTENSION) *ext_list;
    int num_ext, i;
    long long int computation_result = 0;

    priv_data_x509 = enc_private_data_file_open(priv_data_file, p_file_sz);

    if (priv_data_x509 == NULL)
    {
        printf( "Cannot access the private data-file of the data-owner\n");
        goto exit;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    
    ext_list = X509_get0_extensions(priv_data_x509);
    num_ext = sk_X509_EXTENSION_num(ext_list);
    
    if(num_ext <= 0)
    {
        printf( "There is no data in this file to access\n");
        goto exit;
    }

    /* The result should be the inner product = 
     * [1 2 3 ... n]*[x1 x2 x3 ... xn] =
     * 1*x1 + 2*x2 + 3*x3 + ... + n*xn */
    
    for (i = 0; i < num_ext; i++) 
    {
        X509_EXTENSION *ext;
        ASN1_OCTET_STRING *value;
        int length;
        const unsigned char *raw_data;
        const unsigned char *actual_data;
        int cur_attbr;

        ext = sk_X509_EXTENSION_value(ext_list, i);
        value = X509_EXTENSION_get_data(ext);
        length = ASN1_STRING_length(value);
        raw_data = ASN1_STRING_get0_data(value);

        /* First two bytes are dummy */
        actual_data = (raw_data + 2);
        length -=2;

        cur_attbr = atoi((const char*)actual_data);

        /* Generate a random number and multiply with it*/
        computation_result += (cur_attbr * (i+1));
    }

    /* Send the computation result to the host */
    ret = (int)computation_result;
    
exit:
    if (priv_data_x509 != NULL)
    {
        enc_private_data_file_close(priv_data_x509);
    }

    return ret;
}

static int enc_get_trusted_time(time_t *p_cur_trusted_tim)
{
    TS_REQ *ts_req = NULL;
    int ts_req_len = 0;
    int ts_rsp_len = 0;
    int ret = -1;
    
    ts_req_len = enc_create_ts_req(g_enc_buffer, ENC_BUF_SZ, &ts_req);
    
    if ((ts_req_len <=0) || (ts_req == NULL))
    {
        printf( "Cannot generate the timestamp request file\n");
        goto exit;
    }

    if (enc_get_ts_resp(g_enc_buffer, g_enc_buffer1, ts_req_len, &ts_rsp_len) != 0)
    {
        printf( "Error during getting timestamping response from the trusted-timestamping server\n");
        goto exit;
    }

    if (enc_verify_ts_rsp(g_enc_buffer1, ts_rsp_len, ts_req, p_cur_trusted_tim) != 0)
    {
        printf( "Error during verification of the timestamp response\n");
        goto exit;
    }

    ret = 0;
exit:
    if (ts_req != NULL)
    {
        TS_REQ_free(ts_req);
    }

    return ret;
}

int enc_check_data_expiry(const char* expiry_time_file)
{
    int ret = -1;
    FILE* fp = NULL;

    fp = fopen(expiry_time_file, "rb");

    if(fread(g_do_exp_tim, 1, EXP_TIM_STR_SZ, fp) <= 0)
    {
        printf( "Cannot get the expiry time\n");
        goto exit;
    }

    if(enc_trusted_time_comparison() < 0)
    {
        printf( "User provided personal data has expired\n");
        goto exit;
    }

    ret = 0;
exit:
    if (fp != NULL)
    {
        fclose(fp);
    }
     
    return ret;
}

static int enc_trusted_time_comparison()
{
    int ret = -1;
    time_t cur_trusted_tim;
    char time_str[EXP_TIM_STR_SZ] = {0};

    /* Get the trusted time */
    if (enc_get_trusted_time(&cur_trusted_tim) != 0)
    {
        printf( "Cannot get the current time-stamping information\n");
    }
    else 
    {
        /* Convert the time to string */
        snprintf(time_str, EXP_TIM_STR_SZ, "%010lu", cur_trusted_tim);

        /* Get trusted time and compare with g_do_exp_tim, simple string comparison will do */
        /* The string value of the expiry time should be more than the current time */
        if (strcmp(g_do_exp_tim, time_str) > 0)
        {
            ret = 0;
            //printf( "Expiry time (%s) is greater than the current time (%s)\n", g_do_exp_tim, time_str);
        }
        else
        {
            printf( "Expiry time (%s) is smaller than the current time (%s)\n", g_do_exp_tim, time_str);
        }
    }

    return ret;
}

/* https://fm4dd.com/openssl/certextensions.shtm  */
X509* enc_private_data_file_open(const char* data_file_path, int *file_data_sz)
{
    FILE* fp = NULL;
    int pem_data_sz;
    BIO* certBio = NULL;
    X509* certX509 = NULL;

    if (enc_check_data_expiry(ENC_DO_EXP_TIME_FILE) < 0)
    {
        printf( "Problem during opening the data-expiry date related file\n");
        goto exit;
    }

    enc_print_log("Data-user: Before accessing the data\n"); 
    
    fp = fopen(data_file_path,"rb");

    /* Determine the file size */
    fseek(fp, 0L, SEEK_END);
    pem_data_sz = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    
    *file_data_sz = pem_data_sz;

    if(fread(g_enc_buffer, 1, pem_data_sz, fp) != (size_t)pem_data_sz)
    {
        printf( "Problem during opening the certificate file of data-owner\n");
        goto exit;
    }
    
    certBio = BIO_new_mem_buf((void*)g_enc_buffer, -1); 
    
    if(certBio == NULL)
    {
        printf( "Cannot create the BIO file\n");
        goto exit;
    }

    certX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);

    if (certX509 == NULL)
    {
        printf( "Cannot read the BIO file to X509\n");
        goto exit;
    }
  
exit: 
    if (certBio != NULL)
    {
        BIO_free_all(certBio);
    }

    if (fp != NULL)
    {
        fclose(fp);
    }
    
    /* Success case, return from here */
    return certX509;
}

void enc_private_data_file_close(X509* data_file_X509)
{
    if (data_file_X509 != NULL)
    {
        X509_free(data_file_X509);
    }
    
    return;
}

int enc_get_priv_data_val(X509 *data_x509, int extension_num, char *return_buf, int *return_len)
{
    const STACK_OF(X509_EXTENSION) *ext_stk;
    X509_EXTENSION *ext;
    
    *return_len = 0;
    ext_stk = X509_get0_extensions(data_x509);
    
    if (ext_stk == NULL) 
    {
        printf( "Cannot extract the extension-stack from x509\n");
        return -1;
    }    

    ext = sk_X509_EXTENSION_value(ext_stk, extension_num);

    if (ext == NULL)
    {
        printf( "Cannot extract the extention number from the extension-stack from x509\n");
        return -1;
    }

    /* First two charecters of ASN1_STRING_get0_data are dummy charecter */
    *return_len = ASN1_STRING_length(X509_EXTENSION_get_data(ext)) - 2;
    memcpy(return_buf, ASN1_STRING_get0_data(X509_EXTENSION_get_data(ext)) + 2, *return_len);

    /* Add ending NULL charecter */
    return_buf[*return_len] = '\0';
    *return_len += 1;
    
    return 0;
}

/* TODO: API spec, https://pub.sortix.org/sortix/release/nightly/man/man3/i2d_TS_REQ.3.html */

static int enc_create_ts_req(char* p_op_buf, int max_req_len, TS_REQ **p_ts_req)
{
    /* TODO: Inspired from: https://cpp.hotexamples.com/it/examples/-/-/TS_MSG_IMPRINT_set_algo/cpp-ts_msg_imprint_set_algo-function-examples.html */

    int ret = -1;
    TS_REQ *ts_req = NULL;
    TS_MSG_IMPRINT *msg_imprint = NULL;
    X509_ALGOR *algo = NULL;
    ASN1_INTEGER *nonce_asn1 = NULL;
    unsigned char *p_ts_req_der = NULL;
    int der_len = 0;
    
    /* Work with dummy digest */
    char dummy_digest[] = { (char)0x3a, (char)0x30, (char)0x94, (char)0x8f, (char)0x8c, (char)0xd5, (char)0x65, (char)0x5f, (char)0xed, (char)0xe3, (char)0x89, (char)0xd7, (char)0x3b, (char)0x5f, (char)0xec, (char)0xd9, (char)0x12, (char)0x51, (char)0xdf, (char)0x4a };

    //printf( "Creating a time-stamping request\n");

    ts_req = TS_REQ_new();
    
    if (ts_req == NULL)
    {
       printf(  "Cannot allocate a new time-stamp request object\n");
        goto exit;
    }

    /* All the viewed examples used version 1 */
    if (TS_REQ_set_version(ts_req, 1) == 0)
    {
       printf(  "Cannot set the version to the time-stamp request\n");
        goto exit;
    }

    msg_imprint = TS_MSG_IMPRINT_new();
    
    if (msg_imprint == NULL)
    {
       printf(  "Cannot create new message imprint\n");
        goto exit;
    }

    algo = X509_ALGOR_new();

    if (algo == NULL)
    {
       printf(  "Cannot create new algo object\n");
        goto exit;
    }

    if ((algo->algorithm = OBJ_nid2obj(EVP_MD_type(EVP_get_digestbyname("sha1")))) == NULL)
    {
       printf(  "Cannot set the algorithm\n");
        goto exit;
    }

    if ((algo->parameter = ASN1_TYPE_new()) == NULL)
    {
       printf(  "Cannot create the parameter object for the algo\n");
        goto exit;
    }
    
    algo->parameter->type = V_ASN1_NULL;

    if (TS_MSG_IMPRINT_set_algo(msg_imprint, algo) != 1)
    {
       printf(  "Cannot set the algo to the message imprint\n");
        goto exit;
    }
   
    if (TS_MSG_IMPRINT_set_msg(msg_imprint, (unsigned char*)dummy_digest, 20) != 1)
    {
       printf(  "Cannot set the data to the message imprint\n");
        goto exit;
    }
    
    if (TS_REQ_set_msg_imprint(ts_req, msg_imprint) != 1)
    {
       printf(  "Cannot set the message imprint to the time-stamping request\n");
        goto exit;
    }

    nonce_asn1 = ASN1_INTEGER_new();

    if (nonce_asn1 == NULL)
    {
       printf(  "Cannot create asn1 integer for the nonce\n");
        goto exit;
    }

    ASN1_INTEGER_set(nonce_asn1, 0);

    if (TS_REQ_set_nonce(ts_req, nonce_asn1) != 1)
    {
       printf(  "Cannot set the nonce to the time-stamping request\n");
        goto exit;
    }
    
    der_len = i2d_TS_REQ(ts_req, &p_ts_req_der);
    
    if (der_len <= 0)
    {
       printf(  "Cannot convert the time-response to the DER format\n");
        goto exit;
    }

    if (der_len > max_req_len)
    {
        printf(  "Output buffer cannot hold the time-response buffer\n");
        goto exit;
    }

    if (memcpy(p_op_buf, p_ts_req_der, der_len) != p_op_buf)
    {
       printf(  "Problem during copying data to the output buffer\n");
        goto exit;
    }

    ret = der_len;

    *p_ts_req = ts_req;

exit:
    if (p_ts_req_der != NULL)
    {
        OPENSSL_free(p_ts_req_der);
    }

    if (nonce_asn1  != NULL)
    {
        ASN1_INTEGER_free(nonce_asn1);
    }

    if (algo != NULL)
    {
        X509_ALGOR_free(algo);
    }

    if (msg_imprint != NULL)
    {
        TS_MSG_IMPRINT_free(msg_imprint);
    }
    
    return ret;
}


static int enc_verify_ts_rsp(char* ts_rsp_buff, int ts_rsp_sz, TS_REQ *ts_req, time_t *p_rcvd_ts)
{
    /* https://cpp.hotexamples.com/it/examples/-/-/TS_RESP_verify_response/cpp-ts_resp_verify_response-function-examples.html */

    int ret = -1;
    unsigned char* ts_ca_der_ptr = g_ts_ca_cert_buff;
    unsigned char* ts_signer_der_ptr = g_ts_signer_cert_buff;
    int ts_ca_der_size = sizeof(g_ts_ca_cert_buff);
    int ts_signer_der_size = sizeof(g_ts_signer_cert_buff);
    TS_RESP *ts_resp = NULL;
    BIO *ts_rsp_bio = NULL;
    TS_VERIFY_CTX *verify_ctx = NULL;
    X509_STORE *store_ctx = NULL;
    X509 *x509_ca = NULL;
    X509 *x509_signing_cert = NULL;
    STACK_OF(X509) *stack_certs = NULL;
    TS_TST_INFO *ts_tst_info = NULL;
    ASN1_GENERALIZEDTIME *asn1_time = NULL;
    struct tm cur_tm;
   
    /* Copy the time-stamping request response to buffer */ 
    //printf( "Verifying a time-stamping response file\n");
    
    if (ts_req ==  NULL)
    {
        printf(  "Time-stamping request is not available\n");
        goto exit;
    }
    
    ts_rsp_bio = BIO_new_mem_buf((void*)ts_rsp_buff, ts_rsp_sz);
    
    if (ts_rsp_bio == NULL)
    {
        printf(  "Cannot convert the time-stamp response to a BIO\n");
        goto exit;
    }
    
    ts_resp = d2i_TS_RESP_bio(ts_rsp_bio, &ts_resp);
    
    if (ts_resp ==  NULL)
    {
        printf(  "Cannot obtain the response from the BIO\n");
        goto exit;
    }
    
    /* Create a new verify context from previous request */
    verify_ctx = TS_REQ_to_TS_VERIFY_CTX(ts_req, NULL);
    
    if (verify_ctx == NULL)
    {
        printf(  "Cannot create the verify context\n");
        goto exit;
    }
    
    /* Prepare verifier related information */
    store_ctx = X509_STORE_new();
    
    if (store_ctx == NULL) 
    {
        printf(  "Cannot create the certificate store context\n");
        goto exit;
    }

    X509_STORE_set_verify_cb(store_ctx, enc_verify_cb);
   
    x509_ca = d2i_X509(NULL, (const unsigned char **)&ts_ca_der_ptr, ts_ca_der_size);

    if (x509_ca == NULL)
    {
        printf(  "Cannot read x509 from CA certificate's BIO\n");
        goto exit;
    }

    if (X509_STORE_add_cert(store_ctx, x509_ca) == 0)
    {
        printf(  "Cannot add the CA certificate to the store\n");
        goto exit;
    }

    if (TS_VERIFY_CTX_set_store(verify_ctx, store_ctx) == NULL)
    {
        printf(  "Cannot set the verifier's information into the verifying context\n");
        goto exit;
    }

    stack_certs = sk_X509_new_null(); 

    if (stack_certs == NULL)
    {
        printf(  "Cannot create the stack for the certificate\n");
        goto exit;
    }

    x509_signing_cert = d2i_X509(NULL, (const unsigned char **)&ts_signer_der_ptr, ts_signer_der_size);

    if (x509_signing_cert == NULL)
    {
        printf(  "Cannot read x509 from singing certificate's BIO\n");
        goto exit;
    }

    if (sk_X509_push(stack_certs, x509_signing_cert) == 0)
    {
        printf(  "Cannot push the signing certificate to the stack\n");
        goto exit;
    }
   
    if(TS_VERIFY_CTS_set_certs(verify_ctx, stack_certs) == NULL)
    {
        printf(  "Cannot set the signing certificate to the verifying context\n");
        goto exit;
    }

    /* Add verifiers information to the verification context */
    if (TS_RESP_verify_response(verify_ctx, ts_resp) == 0)
    {
        printf(  "Timestamp response verification failed\n");
        printf(  "Check whether the timestamp server's certificate and timestamp server's ca certificate are in sync..!!\n");
        goto exit;
    }
        
    ts_tst_info = TS_RESP_get_tst_info(ts_resp);

    if (ts_tst_info == NULL)
    {
        printf(  "Cannot extract status information from the time-response\n");
        goto exit;
    }
    
    asn1_time = (ASN1_GENERALIZEDTIME*)TS_TST_INFO_get_time(ts_tst_info);
    
    if (asn1_time == NULL)
    {
        printf(  "Cannot get the timestamp\n");
        goto exit;
    }

    if (ASN1_TIME_to_tm(asn1_time, &cur_tm) == 0)
    {
        printf(  "Cannot convert the received timestamp to struct tm\n");
        goto exit;
    }

    *p_rcvd_ts = mktime(&cur_tm);
    
    //printf(  "Timestamp response verification passed\n");
    
    ret = 0;

exit:
#if 0/* Free operation causes segmentation fault*/
    if (stack_certs != NULL)
    {
        sk_X509_pop_free(stack_certs, X509_free);
    }
#endif

    if (x509_signing_cert != NULL)
    {
        X509_free(x509_signing_cert);
    }

    if (x509_ca != NULL)
    {
        X509_free(x509_ca);
    }

#if 0/* Free operation causes segmentation fault*/
    if (store_ctx != NULL)
    {
        X509_STORE_free(store_ctx);
    }
#endif
    
    if (verify_ctx != NULL)
    {
        TS_VERIFY_CTX_free(verify_ctx);
    }
    
    if (ts_rsp_bio != NULL)
    {
        BIO_free_all(ts_rsp_bio);
    }

    if (ts_resp != NULL)
    {
        TS_RESP_free(ts_resp);
    }
    
    return ret;
}

static int enc_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    /* Using the variable for resolving the warning */
    if (ctx != NULL)
    {   
        return ok;
    }
    else
    {
        return ok;
    }
}

static int enc_get_ts_resp(char *req_buf, char *resp_buf, int req_sz, int *p_rsp_sz)
{
    int ret = -1;
    int ts_server_sock = -1;

    ts_server_sock = enc_connect_to_ts_server(g_ts_ip, g_ts_port);

    if(ts_server_sock < 0)
    {
        printf( "Problem during connection with the timestamping server\n");
        goto exit;
    }

    if(enc_send_buff_to_file(ts_server_sock, req_buf, req_sz) != 0)
    {
        printf( "Error while sending the timestamping request to the timestamping-server\n");
        goto exit;
    }

    if(enc_recv_file_to_buf(ts_server_sock, resp_buf, p_rsp_sz, ENC_BUF_SZ) != 0)
    {
        printf( "Error while receiving the timestamping response from the timestamping-server\n");
        goto exit;
    }

    ret = 0;

exit:
    if(ts_server_sock >= 0)
    {
        close(ts_server_sock);
    }

    return ret;
}

/* Establish connection with the time-stamping server */
static int enc_connect_to_ts_server(const char* ip, int port)
{
    int ret = -1;
    int srv_sock;
    struct sockaddr_in srv_addr;

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = inet_addr(ip);

    srv_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(srv_sock < 0)
    {
        printf( "Problem during socket creation for connecting with: %s:%d\n", ip, port);
        goto error_handling;
    }

    /* Connect with the data-owner */
    ret = connect(srv_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    
    if(ret < 0)
    {
        printf( "Problem during connection with data-user(%s:%d)\n", ip, port);
        goto error_handling;
    }

    return srv_sock;

error_handling:
    if (srv_sock > 0)
    {
        close(srv_sock);
    }

    return ret;
}

static int enc_recv_file_to_buf(int conn_sock, char *buff, int *p_recv_sz, int max_buf_sz)
{
    int ret = -1;
    int cur_recv_sz;
    int file_sz;
    int recv_sz;

    /* Size should not be more than 20 charecter long */
    bzero(buff, 20);

    /* First read the file size */
    if(recv(conn_sock, buff, 20, 0) < 0)
    {
        printf( "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(buff);
    
    if(file_sz < 0)
    {
        printf( "Receiving file size is < 0\n");
        goto error_handling;
    }
    
    if(file_sz > max_buf_sz)
    {
        printf( "Receiving file size is more than the maximum buffer-size\n");
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(send(conn_sock, buff, 1, 0) < 0)
    {
        printf( "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        bzero(buff, max_buf_sz);

        cur_recv_sz = recv(conn_sock, &buff[recv_sz], (max_buf_sz - recv_sz), 0);

        if(cur_recv_sz < 0)
        {
            printf( "Problem while receiving data for the file: %s\n", buff);
            goto error_handling;
        }

        recv_sz += cur_recv_sz;
    }

    *p_recv_sz = recv_sz;
    
    //printf( "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = 0;

error_handling:

    return ret;
}

static int enc_send_buff_to_file(int conn_sock, char *buff, int buff_size)
{
	int ret = -1;
	int str_sz;
	int send_sz;
    char l_buff[50];

    /* File size should not more than 20 charecte long */
	bzero(l_buff, 20);

    /* Convert the file-size to string */
    str_sz = snprintf(l_buff, 20, "%d", buff_size);

    if (send(conn_sock, l_buff, (str_sz + 1), 0) != (str_sz + 1))
    {
        printf( "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (recv(conn_sock, l_buff, 1, 0) < 0)
    {
        printf( "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != buff_size)
	{
	    ret = send(conn_sock, &buff[send_sz], (buff_size - send_sz), 0);

		if (ret < 0)
		{
 			printf( "While sending the buffer to a file in receiver-side\n");
			goto error_handling;
		}

        send_sz += ret;
	}

	//printf( "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
    
    return ret;
}

