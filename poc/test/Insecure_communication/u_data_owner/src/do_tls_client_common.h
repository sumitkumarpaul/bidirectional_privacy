#ifndef TLS_CLIENT_H
#define TLS_CLIENT_H

#include "sgx_utls.h"
#include <openssl/ssl.h>

#define TLS_CLIENT "TLS client: "

#define CLIENT_PAYLOAD "GET / HTTP/1.0\r\n\r\n"
#define SERVER_PAYLOAD                                   \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection : </p>\r\n"                \
    "A message from TLS server inside enclave\r\n"

#define CLIENT_PAYLOAD_SIZE strlen(CLIENT_PAYLOAD)
#define SERVER_PAYLOAD_SIZE strlen(SERVER_PAYLOAD)

#define PRINT printf
#define GETCURRTIME time
#define GETCURRTIME time
#define VERIFY_CALLBACK  tee_verify_certificate_with_evidence_host
#define FREE_SUPDATA tee_free_supplemental_data_host



extern void p_sgx_tls_qv_err_msg(sgx_ql_qv_result_t error_code);
extern void p_sgx_tls_qe_err_msg(quote3_error_t error_code);
extern int do_ssl_send_data(SSL* ssl, const char* data_buf, int data_sz);
extern int do_ssl_recv_data(SSL* ssl, char* data_buf);
extern int do_ssl_recv_file(SSL* ssl, const char* file_path);
extern int do_ssl_send_file(SSL* ssl, const char* file_path);
extern int do_start_tls_client(char* server_name, char* server_port, int& ssl_enc_sock, SSL_CTX** p_ctx, SSL** p_ssl);
extern void do_stop_tls_client(int serversocket, SSL_CTX* ctx, SSL* ssl);

#endif
