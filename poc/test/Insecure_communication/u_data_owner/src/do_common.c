/**********************************************************************
 * This file contains common code required for the operation of data-owner
 * *******************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include "do_debug.h"
#include "do_common.h"

/* Receive a file over the connected socket */
int do_recv_file(int conn_sock, const char* file_path)
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
        print_log(DEBUG_LEVEL_ERROR, "While creating the file: %s\n", file_path);
        goto error_handling;
    }
        
    //bzero(g_buffer, DO_BUF_SZ);

    /* First read the file size */
    if(recv(conn_sock, g_buffer, DO_BUF_SZ, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while receiving the file size\n");
        goto error_handling;
    }
    
    file_sz = atoi(g_buffer);
    if(file_sz < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Receiving file size is < 0\n");
        goto error_handling;
    }
    
    /* Send-back a single byte sync message to the server after receiving the file size */
    if(send(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        //bzero(g_buffer, DO_BUF_SZ);

        cur_recv_sz = recv(conn_sock, g_buffer, DO_BUF_SZ, 0);

        if(cur_recv_sz < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem while receiving data for the file: %s\n", g_buffer);
            goto error_handling;
        }

        cur_write_sz = 0;

        while (cur_recv_sz != cur_write_sz)
        {
            ret = fwrite(&g_buffer[cur_write_sz], 1, (cur_recv_sz - cur_write_sz), fp);

            if (ret < 0)
            {
                print_log(DEBUG_LEVEL_ERROR, "While writing to the file: %s\n", g_buffer);
                goto error_handling;
            }

            cur_write_sz += ret;
        }

        recv_sz += cur_recv_sz;
    }

    print_log(DEBUG_LEVEL_INFO, "Successfully received file having size: %d bytes\n", recv_sz);
    
    ret = 0;

error_handling:
    if (fp != NULL)
    {
        fclose(fp);
    }

    return ret;
}

/* Send a file over the connected socket */
int do_send_file(int conn_sock, const char* file_path)
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
		print_log(DEBUG_LEVEL_ERROR, "While opening the file\n");
		goto error_handling;
	}
	
	/* Get the file size */
	fseek(fp, 0, SEEK_END); // seek to end of file
	file_sz = ftell(fp); // get current file pointer
	fseek(fp, 0, SEEK_SET); // seek back to beginning of file

	//bzero(g_buffer, DO_BUF_SZ);

    /* Convert the file-size to string */
    str_sz = snprintf(g_buffer, DO_BUF_SZ, "%d", file_sz);

    if (send(conn_sock, g_buffer, (str_sz + 1), 0) != (str_sz + 1))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (recv(conn_sock, g_buffer, 1, 0) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Error while receiving the SYNC message from the receiver\n");
        goto error_handling;
    }

    send_sz = 0;

	while (send_sz != file_sz)
	{
		//bzero(g_buffer, DO_BUF_SZ);

		read_sz = fread(g_buffer, 1, DO_BUF_SZ, fp);

        cur_send_sz = 0;

		while (read_sz != cur_send_sz)
		{
			ret = send(conn_sock, &g_buffer[cur_send_sz], (read_sz - cur_send_sz), 0);

			if (ret < 0)
			{
 				print_log(DEBUG_LEVEL_ERROR, "While sending the file: %s\n", file_path);
				goto error_handling;
			}

			cur_send_sz += ret;
		}

        send_sz += cur_send_sz;
	}

	print_log(DEBUG_LEVEL_INFO, "Successfully sent: %d bytes of file data to the receiver\n", send_sz);
	
    ret = 0;

error_handling:
	if (fp != NULL)
	{
		fclose(fp);
	}
    
    return ret;
}

/* Send command and get response from the LibEnc */
int do_cmd_rsp_with_libenc(const char* ip, int port, int cmd, int enc_id)
{
    int ret = -1;
    int libenc_sock = -1;
    int cmd_sz = 0;

    libenc_sock = do_connect_to_server(ip, port);

    if(libenc_sock <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "While connecting with the LibEnc(%s:%d)\n", ip, port);
        goto error_handling;
    }

    if(cmd == LIBENC_CMD_GET_DESC)
    {
        /* Send command for getting description */
        //bzero(g_buffer, DO_BUF_SZ);
        cmd_sz = snprintf(g_buffer, DO_BUF_SZ, "GET-DESC %d ", enc_id);
        
        if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-DESC\n");
            goto error_handling;
        }

        //bzero(g_buffer, DO_BUF_SZ);
        if(recv(libenc_sock, g_buffer, DO_BUF_SZ, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during receiving response of GET-DESC\n");
            goto error_handling;
        }
    }
    else if(cmd == LIBENC_CMD_GET_MRENCLAVE)
    {
        /* Send command for getting MRENCLAVE */
        //bzero(g_buffer, DO_BUF_SZ);
        cmd_sz = snprintf(g_buffer, DO_BUF_SZ, "GET-MRENCLAVE %d ", enc_id);
        
        if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-MRENCLAVE\n");
            goto error_handling;
        }

        //bzero(g_buffer, DO_BUF_SZ);
        if(recv(libenc_sock, g_buffer, DO_BUF_SZ, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during receiving response of GET-MRENCLAVE\n");
            goto error_handling;
        }
    }
    else if(cmd == LIBENC_CMD_GET_ENC)
    {
        /* Send command for getting the enclave */
        //bzero(g_buffer, DO_BUF_SZ);
        cmd_sz = snprintf(g_buffer, DO_BUF_SZ, "GET-ENC %d ", enc_id);
        
        if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-ENC\n");
            goto error_handling;
        }
   
        /* Unsigned enclave will be stored in a fixed location */ 
        if(do_recv_file(libenc_sock, DO_RCV_UNSIGNED_ENC_PATH) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during receiving unsigned enclave file\n");
            goto error_handling;
        }
    }
    else if(cmd == LIBENC_CMD_GET_EDL)
    {
        /* Send command for getting the EDL file */
        //bzero(g_buffer, DO_BUF_SZ);
        cmd_sz = snprintf(g_buffer, DO_BUF_SZ, "GET-EDL %d ", enc_id);
        
        if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-EDL\n");
            goto error_handling;
        }
   
        /* EDL file will be stored in a fixed location */ 
        if(do_recv_file(libenc_sock, DO_RCV_EDL_FILE_PATH) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during receiving EDL file\n");
            goto error_handling;
        }
    }
    else if(cmd == LIBENC_CMD_GET_CNF)
    {
        /* Send command for getting the configuration file */
        //bzero(g_buffer, DO_BUF_SZ);
        cmd_sz = snprintf(g_buffer, DO_BUF_SZ, "GET-CNF %d ", enc_id);
        
        if(send(libenc_sock, g_buffer, cmd_sz, 0) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during sending command GET-CNF\n");
            goto error_handling;
        }
   
        /* Configuration file will be stored in a fixed location */ 
        if(do_recv_file(libenc_sock, DO_RCV_CNF_FILE_PATH) < 0)
        {
            print_log(DEBUG_LEVEL_ERROR, "Problem during receiving configuration file\n");
            goto error_handling;
        }
    }
    else
    {
        print_log(DEBUG_LEVEL_ERROR, "Invalid command requested\n");
        goto error_handling;
    }

    ret = 0;

    
error_handling:
    if(libenc_sock > 0)
    {
        close(libenc_sock);
    }

    return ret;
}


/* Disconnect from data-user */
int do_disconnect(int* p_sock)
{
    int ret = -1;

    if (p_sock != NULL)
    {
        if (*p_sock > 0)
        {
            close(*p_sock);
            *p_sock = -1;
            ret = 0;
        }
    }
    
    return ret;
}
