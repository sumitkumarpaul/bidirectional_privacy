/**********************************************************************
 * This file contains the code required for initial approval process
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

int do_initial_approval_stage();
int do_sign_and_send_enc(int enc_id);
int do_save_enc_details();

/* Save the mrenclave and mrsigner value of the signed enclave */
int do_save_enc_details()
{
    int ret = -1;
    FILE *tmp_fp = NULL;
    FILE *mrenclave_fp = NULL;
    FILE *mrsigner_fp = NULL;
    char *line;
    int i;
    int loc;

    /* Get the listening IP address and port number of the deployed enclave */
    //bzero(g_buffer, DO_BUF_SZ);
    if(recv(g_du_sock, g_buffer, DO_BUF_SZ, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving the listening IP and port of enclave\n");
        goto error_handling;
    }
	
    /* Save the IP address and port in the global variables*/
    strncpy(g_enc_ip, strtok(g_buffer, " "), 16);
    strncpy(g_enc_port, strtok(NULL, " "), 6);
    print_log(DEBUG_LEVEL_INFO, "Received listening enclave's information. IP: %s, Port: %s\n", g_enc_ip, g_enc_port);

	//bzero(g_buffer, DO_BUF_SZ);
    snprintf(g_buffer, DO_BUF_SZ, "sgx_sign dump -enclave %s -dumpfile ./.tmp.dump > /dev/null\n", DO_SIGNED_ENC_PATH);

    /* Generate a temporary file using sgx_enclave dump command */
    if (system(g_buffer) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during execution of the shell command: %s\n", g_buffer);
        goto error_handling;
    }

    /* Open the temporary dump file */
    tmp_fp = fopen("./.tmp.dump", "rb");
    
    if (tmp_fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the temporary dumpfile\n");
        goto error_handling;
    }
    
    /* Open the mrenclave file */
    mrenclave_fp = fopen(DO_ENC_MRENCLAVE_PATH, "wb");
    
    if (mrenclave_fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the mrenclave file\n");
        goto error_handling;
    }
    
    /* Open the mrsigner file */
    mrsigner_fp = fopen(DO_ENC_MRSIGNER_PATH, "wb");
    
    if (mrsigner_fp == NULL)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during opening the mrsigner file\n");
        goto error_handling;
    }
    
    /* Dummy read first 80 lines, initialize line with not-null */
    for (i = 1; i <= 142; i++)
    {
        /* 81 and 82 lines contain MRENCLAVE value */
        if ((i == 81) || (i == 82))
        {
            //bzero(g_buffer, DO_BUF_SZ);
            line = fgets(g_buffer, DO_BUF_SZ, tmp_fp);
            
            if(EOF == fputs(g_buffer, mrenclave_fp))
            {
                print_log(DEBUG_LEVEL_ERROR, "Problem during getting mrenclave value\n");
                goto error_handling;
            }
        }
        else if ((i == 141) || (i == 142))
        {
            //bzero(g_buffer, DO_BUF_SZ);
            line = fgets(g_buffer, DO_BUF_SZ, tmp_fp);
            
            if(EOF == fputs(g_buffer, mrsigner_fp))
            {
                print_log(DEBUG_LEVEL_ERROR, "Problem during getting mrsigner value\n");
                goto error_handling;
            }
        }
        else
        {
            /* Perform a dummy read line */
            fgets(g_buffer, DO_BUF_SZ, tmp_fp);
        }
    }

    ret = 0;

error_handling:
    /* Close the temporary file */
    if (tmp_fp != NULL)
    {
        fclose(tmp_fp);
    }

    /* Close the mrenclave file */
    if (mrenclave_fp != NULL)
    {
        fclose(mrenclave_fp);
    }
    
    /* Close the mrsigner file */
    if (mrsigner_fp != NULL)
    {
        fclose(mrsigner_fp);
    }
    
    /* Delete the temporary file */
    system("rm -rf ./.tmp.dump > /dev/null");

    return ret;
}

/* Process the initial approval */
int do_initial_approval_stage()
{
    int ret = -1;
    int cmd_sz = 0;
    int enc_id;
    char answer;

    /* Connect to the data-user */  
    g_du_sock = do_connect_to_server(g_du_ip, g_du_port);

    if (g_du_sock <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while connecting with the data-user\n");
        goto error_handling;
    }

    /* Receive the data-user's certificate file */
    if(do_recv_file(g_du_sock, DO_RCV_DU_CERT_FILE) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving the data-user's certificate file\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Received the data-user's certificate file\n");

    /* Send requesting service request ID */
    //bzero(g_buffer, DO_BUF_SZ);
    cmd_sz = snprintf(g_buffer, DO_BUF_SZ, "%d \n", g_srv_req_id);
        
    if(send(g_du_sock, g_buffer, cmd_sz, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending service request to the data-user(service provider)\n");
        goto error_handling;
    }

    /* Print the data-requirement for availing this service */
    //bzero(g_buffer, DO_BUF_SZ);
    if(recv(g_du_sock, g_buffer, DO_BUF_SZ, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving response of service request\n");
        goto error_handling;
    }

    printf("\nFollowing are the data-requirements asked by data-user:\n\n");
    printf("%s", ((sr_details*)g_buffer)->data_req_desc);
   
    /* Save the enclave ID */
    enc_id = ((sr_details*)g_buffer)->enc_id;
    
    /* Fetch the description of Enclave from LibEnc */
    if(do_cmd_rsp_with_libenc(g_libenc_ip, g_libenc_port, LIBENC_CMD_GET_DESC, enc_id) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving description of the enclave from LibEnc\n");
        goto error_handling;
    }
   
    /* Print the description of the Enclave's operation */
    printf("\nFollowing is the description of enclave(%d), fetched from LibEnc:\n\n", enc_id);
    printf("%s", g_buffer);
   
    /* Check whether the user is ok with this data-usage? */
    answer = '?';

    while(!((answer == 'Y') || (answer == 'y') || (answer == 'N') || (answer == 'n')))
    {
        printf("\nDo you agree with it?, please provide a valid answer: [y or n]: ");
        answer = getc(stdin);
    }
    
    /* In the meantime, the data user is expecting to get
     * the file size of data-owner's certificate.
     * If data-owner does not approve to provide the asked
     * data, then send a (-1), which will be
     * treated as negative response in data user side */
    if(!((answer == 'Y') || (answer == 'y')))
    {
        /* Send "-1" string and size of it is 3 bytes */
        send(g_du_sock, "-1", 3, 0);

        print_log(DEBUG_LEVEL_INFO, "According to your decision, further steps are not required\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_SPECIAL, "Approval-stage start\n");
    
    /* Send data-owner's certificate */
    if(do_send_file(g_du_sock, g_do_cert_file) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending the data-owner's certificate file\n");
        goto error_handling;
    }
    
    /* Sign the enclave using private key and send it */
    if(do_sign_and_send_enc(enc_id) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending the signed enclave file\n");
        goto error_handling;
    }
    
    print_log(DEBUG_LEVEL_INFO, "Sent signed enclave\n");
    
    /* Save enclave details for future */
    if(do_save_enc_details() < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during saving enclave details\n");
        goto error_handling;
    }
    
    ret = 0;

error_handling:
    if (g_du_sock > 0)
    {
        close(g_du_sock);
    }

    return ret;
}

/* Sign and send enclave */
int do_sign_and_send_enc(int enc_id)
{
    /* Fetch the unsigned enclave from LibEnc */
    if(do_cmd_rsp_with_libenc(g_libenc_ip, g_libenc_port, LIBENC_CMD_GET_ENC, enc_id) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving the unsigned enclave from LibEnc\n");
        return -1;
    }

    /* Fetch the configuration file */
    if(do_cmd_rsp_with_libenc(g_libenc_ip, g_libenc_port, LIBENC_CMD_GET_CNF, enc_id) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during receiving the configuration file from LibEnc\n");
        return -1;
    }

    print_log(DEBUG_LEVEL_INFO, "Got unsigned enclave from LibEnc\n");
    
    /* Form the system command */
	//bzero(g_buffer, DO_BUF_SZ);

    /* Silently run the command */
    snprintf(g_buffer, DO_BUF_SZ, "sgx_sign sign -enclave %s -key %s -config %s -out %s > /dev/null 2>&1\n", DO_RCV_UNSIGNED_ENC_PATH, g_do_pri_key_file, DO_RCV_CNF_FILE_PATH, DO_SIGNED_ENC_PATH);
    
    /* Sign the received enclave file with private key */
    if (system(g_buffer) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during execution of the shell command: %s\n", g_buffer);
        return -1;
    }

    print_log(DEBUG_LEVEL_INFO, "Signed enclave\n");
    
    /* Send signed file */
    if(do_send_file(g_du_sock, DO_SIGNED_ENC_PATH) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during sending the signed enclave to data-user\n");
        return -1;
    }

    return 0;
}

/* Establish connection with a server */
int do_connect_to_server(const char* ip, int port)
{
    int ret;
    int srv_sock;
    struct sockaddr_in srv_addr;

    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = inet_addr(ip);

    srv_sock = socket(AF_INET, SOCK_STREAM, 0);
    
    if(srv_sock < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during socket creation for connecting with: %s:%d\n", ip, port);
        goto error_handling;
    }

    /* Connect with the data-owner */
    ret = connect(srv_sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr));
    
    if(ret < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem during connection with data-user(%s:%d)\n", ip, port);
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




