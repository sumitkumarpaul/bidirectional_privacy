/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sgx_utls.h"
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "do_tls_client_common.h"
#include "do_debug.h"
#include "do_common.h"

#define CA_FILE "../test_data_creater/certs/ca-cert.pem"

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
int create_socket(char* server_name, char* server_port);

int do_ssl_send_data(SSL* ssl, const char* data_buf, int data_sz)
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
            print_log(DEBUG_LEVEL_ERROR, "Failed! SSL_write returned %d, only %d bytes out of %d bytes written successfully\n", error, total_bytes_written, data_sz);
            ret = -1;
            break;
        }

        total_bytes_written += bytes_written;
        ret = total_bytes_written;
    }
            
    print_log(DEBUG_LEVEL_DUMP, "Successfully sent %d bytes of ssl-data\n", total_bytes_written);

    return ret;
}

int do_ssl_recv_data(SSL* ssl, char* data_buf)
{
    int ret = 0;
    int error = 0;
    int bytes_read = 0;
    int total_bytes_read = 0;
        
    //memset(data_buf, 0, DO_BUF_SZ);
    
    do
    {
        bytes_read = SSL_read(ssl, &data_buf[total_bytes_read], (DO_BUF_SZ - total_bytes_read));
        error = SSL_get_error(ssl, bytes_read);
       
        if ((bytes_read <= 0) && (error != SSL_ERROR_WANT_READ))
        {
            print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT "Failed! SSL_read returned error = %d, till now successfully received = %d bytes\n", error, total_bytes_read);
            ret = -1;
            break;
        }
        else if ((bytes_read > 0) && (error == SSL_ERROR_NONE))
        {
            total_bytes_read += bytes_read;
            ret = total_bytes_read;
            break;
        }
            
        total_bytes_read += bytes_read;

    } while (1);
        
    print_log(DEBUG_LEVEL_DUMP, "Successfully received %d bytes of ssl-data\n", total_bytes_read);
    
    return ret;
}

/* Receive a file over a SSL connection */
int do_ssl_recv_file(SSL* ssl, const char* file_path)
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
    if(do_ssl_recv_data(ssl, g_buffer) < 0)
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
    if(do_ssl_send_data(ssl, g_buffer, 1) < 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem while sending the SYNC message, during file-transfer\n");
        goto error_handling;
    }
    
    recv_sz = 0;
    
    while (recv_sz != file_sz)
    {
        //bzero(g_buffer, DO_BUF_SZ);

        cur_recv_sz = do_ssl_recv_data(ssl, g_buffer);

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

/* Send a file over an SSL connection */
int do_ssl_send_file(SSL* ssl, const char* file_path)
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

    if (do_ssl_send_data(ssl, g_buffer, (str_sz + 1)) != (str_sz + 1))
    {
        print_log(DEBUG_LEVEL_ERROR, "Cannot send the file-size properly\n");
        goto error_handling;
    }
    
    /* Wait for the SYNC message from receiver */
    if (do_ssl_recv_data(ssl, g_buffer) < 0)
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
			ret = do_ssl_send_data(ssl, &g_buffer[cur_send_sz], (read_sz - cur_send_sz));

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

// create a socket and connect to the server_name:server_port
int create_socket(char* server_name, char* server_port)
{
    int sockfd = -1;
    struct addrinfo hints, *dest_info, *curr_di;
    int res;

    hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((res = getaddrinfo(server_name, server_port, &hints, &dest_info)) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR,
            TLS_CLIENT "Error: Cannot resolve hostname %s. %s\n",
            server_name,
            gai_strerror(res));
        goto done;
    }

    curr_di = dest_info;
    while (curr_di)
    {
        if (curr_di->ai_family == AF_INET)
        {
            break;
        }

        curr_di = curr_di->ai_next;
    }

    if (!curr_di)
    {
        print_log(DEBUG_LEVEL_ERROR,
            TLS_CLIENT "Error: Cannot get address for hostname %s.\n",
            server_name);
        goto done;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    if (connect(
            sockfd,
            (struct sockaddr*)curr_di->ai_addr,
            sizeof(struct sockaddr)) == -1)
    {
        print_log(DEBUG_LEVEL_ERROR,
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_name,
            server_port,
            errno);
        close(sockfd);
        sockfd = -1;
        goto done;
    }
    print_log(DEBUG_LEVEL_INFO,TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

done:
    if (dest_info)
        freeaddrinfo(dest_info);

    return sockfd;
}

void do_stop_tls_client(int serversocket, SSL_CTX* ctx, SSL* ssl)
{
    print_log(DEBUG_LEVEL_INFO, "Stopping TLS client..\n");

    if (serversocket != -1)
    {
        close(serversocket);
    }

    if (ssl)
    {
        SSL_free(ssl);
    }

    if (ctx)
    {
        SSL_CTX_free(ctx);
    }

    return;
}

int do_start_tls_client(char* server_name, char* server_port, int& serversocket, SSL_CTX** p_ctx, SSL** p_ssl)
{
    int ret = 1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int error = 0;
    *p_ctx = nullptr;
    *p_ssl = nullptr;
    serversocket = -1;

    print_log(DEBUG_LEVEL_INFO,"Starting" TLS_CLIENT "\n");

    // initialize openssl library and register algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT
               "TLS client: could not initialize the OpenSSL library !\n");
        goto error_handling;
    }

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == nullptr)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT "TLS client: unable to create a new SSL context\n");
        goto error_handling;
    }

    // choose TLSv1.2 by excluding SSLv2, SSLv3 ,TLS 1.0 and TLS 1.1
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);

    if(SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) < 1)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT "TLS client: unable to set the CA file for verification\n");
        goto error_handling;
    }

    // specify the verify_callback for custom verification
    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verify_callback);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if ((ssl = SSL_new(ctx)) == nullptr)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT
               "Unable to create a new SSL connection state object\n");
        goto error_handling;
    }

    if (SSL_use_certificate_file(ssl, CLIENT_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT "Cannot set the client-certificate\n");
        goto error_handling;
    }
    
    if (SSL_use_PrivateKey_file(ssl, CLIENT_PRIVATE_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT "Cannot set the private-key\n");
        goto error_handling;
    }

    serversocket = create_socket(server_name, server_port);
    if (serversocket == -1)
    {
        print_log(DEBUG_LEVEL_ERROR,
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto error_handling;
    }

    print_log(DEBUG_LEVEL_INFO,
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "\n",
            server_name,
            server_port);
    // setup ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl, serversocket);
    if ((error = SSL_connect(ssl)) != 1)
    {
        print_log(DEBUG_LEVEL_ERROR,
            TLS_CLIENT "Error: Could not establish an SSL session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl, error));
        goto error_handling;
    }
    print_log(DEBUG_LEVEL_INFO,
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(ssl));

    *p_ssl = ssl;
    *p_ctx = ctx;
    ret = 0;

    return (ret);

error_handling:
    if (serversocket != -1)
        close(serversocket);

    if (ssl)
        SSL_free(ssl);

    if (ctx)
        SSL_CTX_free(ctx);

    print_log(DEBUG_LEVEL_ERROR,TLS_CLIENT " failed\n");
    return (ret);
}
