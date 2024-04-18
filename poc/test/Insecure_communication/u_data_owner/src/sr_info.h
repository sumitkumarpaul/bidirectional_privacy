/* This file contains the formate of service request-response formats.
 * This should be known by both data-owner and data-user */

#ifndef SR_INFO_H 
#define SR_INFO_H 

typedef struct sr_details {
    unsigned int ID; /* Stores the ID of the service request */
    char data_req_desc[1024];/* 1024 charecters to write the required data from data-owner and their usage */
    unsigned int enc_id; /* The ID of the enclave, which will process the data-owner's data */
} sr_details;

#endif /* SR_INFO_H */
