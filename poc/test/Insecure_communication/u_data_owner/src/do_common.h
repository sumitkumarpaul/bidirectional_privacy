#ifndef DO_COMMON_H
#define DO_COMMON_H

#define LIBENC_CMD_GET_DESC         (1)
#define LIBENC_CMD_GET_MRENCLAVE    (2)
#define LIBENC_CMD_GET_ENC          (3)
#define LIBENC_CMD_GET_EDL          (4)
#define LIBENC_CMD_GET_CNF          (5)
#define DO_BUF_SZ                   204800U
#define DO_SIGNED_ENC_PATH          "./materials/enc.signed.so"
#define DO_ENC_MRSIGNER_PATH        "./materials/enc.mrsigner"
#define DO_ENC_MRENCLAVE_PATH       "./materials/enc.mrenclave"
#define DO_RCV_UNSIGNED_ENC_PATH    "./materials/enc.so"
#define DO_RCV_EDL_FILE_PATH        "./materials/enc.edl"
#define DO_RCV_CNF_FILE_PATH        "./materials/enc.cnf"
#define DO_RCV_DU_CERT_FILE         "./materials/du_cert.pem"
#define CLIENT_CERT_FILE            "../test_data_creater/certs/client-cert.pem"
#define CLIENT_PRIVATE_KEY_FILE     "../test_data_creater/certs/client-key.pem"

extern char    g_buffer[DO_BUF_SZ];
extern char    *g_do_pri_key_file;
extern char    *g_do_cert_file;
extern char    *g_libenc_ip;
extern char    *g_du_ip;
extern char    *g_do_priv_data_file;
extern char    *g_do_exp_tim;
extern char    g_enc_ip[16];
extern char    g_enc_port[6];
extern int     g_libenc_port;
extern int     g_du_port;
extern int     g_srv_req_id;
extern int     g_du_sock;

int do_send_file(int conn_sock, const char* file_path);
int do_recv_file(int conn_sock, const char* file_path);
int do_cmd_rsp_with_libenc(const char* ip, int port, int cmd, int enc_id);
int do_connect_to_server(const char* ip, int port);
int do_disconnect(int *p_sock);

#endif /* DO_COMMON_H */ 
