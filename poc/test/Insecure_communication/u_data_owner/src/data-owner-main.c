/**********************************************************************
 * This file contains the main code for data-owner
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
#include "do_initial_approval.h"
#include "do_data_provision.h"

char    g_buffer[DO_BUF_SZ];
char    *g_do_pri_key_file;
char    *g_do_cert_file;
char    *g_do_priv_data_file;
char    *g_do_exp_tim;
char    *g_libenc_ip;
char    *g_du_ip;
char    g_enc_ip[16] = {0};/*  IP address is maximum 16 bytes long*/
char    g_enc_port[6] = {0};/* Store listening port in string format */
int     g_libenc_port;
int     g_du_port;
int     g_srv_req_id;
int     g_du_sock = -1;

int do_input_check(int argc, char *argv[]);

/* data-owner entry */
int main(int argc, char *argv[])
{
    int ret = -1;

    if(do_input_check(argc, argv) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Input error\n");
        goto stop;
    }

#if 0/* No need of initial approval stage */
    if(do_initial_approval_stage() != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem in initial approval stage\n");
        goto stop;
    }
    
    print_log(DEBUG_LEVEL_SPECIAL, "Successfully completed initial approval stage with data-user\n");

    /* Wait for some time, before communicating with the enclave, in the mean-time the enclave is getting ready */
    sleep(5);
#endif
    print_log(DEBUG_LEVEL_SPECIAL, "Data-owner: Starting data-provision stage\n");
    
    if(do_data_provision_stage(g_enc_ip, g_enc_port) != 0)
    {
        print_log(DEBUG_LEVEL_ERROR, "Problem in data-provision stage\n");
        goto stop;
    }
    
    print_log(DEBUG_LEVEL_SPECIAL, "Data-owner: Successfully completed data-provision stage\n");

    ret = 0;
stop:    
    return ret;

}

/* Checks the input from the user  */
int do_input_check(int argc, char *argv[])
{
    int ret = 0;

    if (argc != 5)
    {
        ret = -1;
        
        printf("Usage: u_data-owner <u_srv-ip> <u_srv-port> <do-pri-data-file> <exp-tim>\n");
        printf("Inputs:\n");
        printf("      - u_srv-ip            : IP-address of the untrusted-server\n");
        printf("      - u_srv-port          : Listening port of the untrusted-server\n");
        printf("      - do-pri-data-file    : This file contains the required data in the specified format\n");
        printf("      - exp-tim             : Expiry time in terms of epoch seconds\n");
    }
    else
    {
        /* Set global variables */
        strncpy(g_enc_ip, argv[1], 16);
        strncpy(g_enc_port, argv[2], 6);
        g_do_priv_data_file = argv[3];
        g_do_exp_tim        = argv[4];
    }

    return ret;
}


