/*
 * Copyright (c) 2018 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>


#include "cifer/test.h"

#include "cifer/innerprod/fullysec/damgard.h"
#include "cifer/sample/uniform.h"

#define PRINT_BUFSIZ 1024
char g_print_buffer[PRINT_BUFSIZ];

void print_log(const char *fmt, ...)
{
    int printed_size;
    struct timeval tv;
    struct tm* now;
    va_list ap;
    struct timezone tz;

    gettimeofday(&tv, &tz);
    now = localtime(&tv.tv_sec);
    va_start(ap, fmt);
    printed_size = snprintf(g_print_buffer, PRINT_BUFSIZ, "\n[%02d-%02d-%04d %02d:%02d:%02d.%06ld] ", now->tm_mday, (now->tm_mon + 1), (now->tm_year + 1900), now->tm_hour, now->tm_min, now->tm_sec, tv.tv_usec);
    vsnprintf(&g_print_buffer[printed_size], (PRINT_BUFSIZ-printed_size-1), fmt, ap);
    va_end(ap);
    printf("%s", g_print_buffer);
}



MunitResult test_damgard_end_to_end(const MunitParameter *params, void *data) {
    size_t l;
    mpz_t bound, bound_neg, key1, key2, xy_check, xy;
    mpz_inits(bound, bound_neg, key1, key2, xy_check, xy, NULL);
    mpz_set_ui(bound, 2);
    mpz_pow_ui(bound, bound, 10);
    mpz_neg(bound_neg, bound);
    cfe_damgard s, encryptor, decryptor;
    cfe_error err;

    size_t modulus_len = 2048;
    
    const char *vect_len = munit_parameters_get(params, "parameters");
 
    l = atoi(vect_len);
    
    cfe_vec mpk, ciphertext, x, y;
    cfe_vec ciphertext_recovered;

    cfe_vec_inits(l, &x, &y, NULL);
    cfe_uniform_sample_range_vec(&x, bound_neg, bound);
    cfe_uniform_sample_range_vec(&y, bound_neg, bound);
    cfe_vec_dot(xy_check, &x, &y);

    cfe_damgard_sec_key msk;
    
    err = cfe_damgard_precomp_init(&s, l, modulus_len, bound);
    
    munit_assert(err == 0);
 
    print_log("One time-setup start\n");
    
    err = cfe_damgard_precomp_init(&s, l, modulus_len, bound);
    
    munit_assert(err == 0);

 
    print_log("One time-setup start\n");

    cfe_damgard_sec_key_init(&msk, &s);
    cfe_damgard_pub_key_init(&mpk, &s);
    cfe_damgard_generate_master_keys(&msk, &mpk, &s);

    cfe_damgard_fe_key key;
    cfe_damgard_fe_key_init(&key);
    err = cfe_damgard_derive_fe_key(&key, &s, &msk, &y);
    munit_assert(err == 0);

    cfe_damgard_copy(&encryptor, &s);
    cfe_damgard_ciphertext_init(&ciphertext, &encryptor);
    err = cfe_damgard_encrypt(&ciphertext, &encryptor, &x, &mpk);
    munit_assert(err == 0);

    
    print_log("One time-setup end");
  
#if 0 
    {
        FILE* output = fopen("serialized.bin", "wb");
        mpz_out_raw(output, l);
        //mpz_out_raw(output, 0);
        //mpz_out_raw(output, ciphertext.get_num_mpz_t());
        //mpz_out_raw(output, ciphertext.get_den_mpz_t());
        fclose(output);
    }

    {
        FILE* input = fopen("serialized.bin", "rb");
        mpz_inp_raw(ciphertext_recovered, l);
        //mpz_inp_raw(ciphertext_recovered, 0);
        //mpz_inp_raw(ciphertext_recovered.get_num_mpz_t(), input);
        //mpz_inp_raw(ciphertext_recovered.get_den_mpz_t(), input);
        fclose(input);
    }

#endif

    print_log("Data-access start for %d parameters\n", l);

    cfe_damgard_copy(&decryptor, &s);
    err = cfe_damgard_decrypt(xy, &decryptor, &ciphertext, &key, &y);
    
    print_log("Data-access end\n");
    
    munit_assert(err == 0);
    
    //gmp_printf("The inner product of a random encrypted vector x and y = [1, 1,...,1] is %Zd\n", xy);

    munit_assert(mpz_cmp(xy, xy_check) == 0);

    mpz_clears(bound, bound_neg, key1, key2, xy_check, xy, NULL);
    cfe_vec_frees(&x, &y, &mpk, &ciphertext, NULL);

    cfe_damgard_sec_key_free(&msk);
    cfe_damgard_fe_key_free(&key);
    cfe_damgard_free(&s);
    cfe_damgard_free(&encryptor);
    cfe_damgard_free(&decryptor);

    return MUNIT_OK;
}

char *damgard_param[] = {
        //(char *) "precomputed", (char *) "random", NULL
        (char *) "1", 
        (char *) "10", 
        (char *) "100", 
        (char *) "1000", 
        (char *) "10000", 
        NULL
};

MunitParameterEnum damgard_params[] = {
        {(char *) "parameters", damgard_param},
        {NULL,                  NULL},
};

MunitTest simple_ip_damgard_tests[] = {
        {(char *) "/end-to-end", test_damgard_end_to_end, NULL, NULL, MUNIT_TEST_OPTION_NONE, damgard_params},
        {NULL,                   NULL,                    NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

MunitSuite damgard_suite = {
        (char *) "/innerprod/fullysec/damgard", simple_ip_damgard_tests, NULL, 1, MUNIT_SUITE_OPTION_NONE
};
