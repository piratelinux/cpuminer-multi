/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0 
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#define _GNU_SOURCE 1

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "argon2.h"
#include "core.h"

#define T_COST_DEF 3
#define LOG_M_COST_DEF 12 /* 2^12 = 4 MiB */
#define LANES_DEF 1
#define THREADS_DEF 1
#define OUTLEN_DEF 32
#define MAX_PASS_LEN 128

#define UNUSED_PARAMETER(x) (void)(x)

static void usage(const char *cmd) {
    printf("Usage:  %s [-h] salt [-i|-d|-id] [-t iterations] [-m memory] "
           "[-p parallelism] [-l hash length] [-e|-r]\n",
           cmd);
    printf("\tPassword is read from stdin\n");
    printf("Parameters:\n");
    printf("\tsalt\t\tThe salt to use, at least 8 characters\n");
    printf("\t-i\t\tUse Argon2i (this is the default)\n");
    printf("\t-d\t\tUse Argon2d instead of Argon2i\n");
    printf("\t-id\t\tUse Argon2id instead of Argon2i\n");
    printf("\t-t N\t\tSets the number of iterations to N (default = %d)\n",
           T_COST_DEF);
    printf("\t-m N\t\tSets the memory usage of 2^N KiB (default %d)\n",
           LOG_M_COST_DEF);
    printf("\t-p N\t\tSets parallelism to N threads (default %d)\n",
           THREADS_DEF);
    printf("\t-l N\t\tSets hash output length to N bytes (default %d)\n",
           OUTLEN_DEF);
    printf("\t-e\t\tOutput only encoded hash\n");
    printf("\t-r\t\tOutput only the raw bytes of the hash\n");
    printf("\t-h\t\tPrint %s usage\n", cmd);
}

static void fatal(const char *error) {
    fprintf(stderr, "Error: %s\n", error);
    exit(1);
}

static void print_hex(uint8_t *bytes, size_t bytes_len) {
    size_t i;
    for (i = 0; i < bytes_len; ++i) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

/*
Runs Argon2 with certain inputs and parameters, inputs not cleared. Prints the
Base64-encoded hash string
@out output array with at least 32 bytes allocated
@pwd NULL-terminated string, presumably from argv[]
@salt salt array
@t_cost number of iterations
@m_cost amount of requested memory in KB
@lanes amount of requested parallelism
@threads actual parallelism
@type Argon2 type we want to run
@encoded_only display only the encoded hash
@raw_only display only the hexadecimal of the hash
*/
static void run(uint32_t outlen, char *pwd, char *salt, uint32_t t_cost,
                uint32_t m_cost, uint32_t lanes, uint32_t threads,
                argon2_type type, int encoded_only, int raw_only) {
    clock_t start_time, stop_time;
    size_t pwdlen, saltlen, encodedlen;
    int result;
    unsigned char * out = NULL;
    char * encoded = NULL;

    start_time = clock();

    if (!pwd) {
        fatal("password missing");
    }

    if (!salt) {
        clear_internal_memory(pwd, strlen(pwd));
        fatal("salt missing");
    }

    pwdlen = strlen(pwd);
    saltlen = strlen(salt);
    if(UINT32_MAX < saltlen) {
        fatal("salt is too long");
    }

    UNUSED_PARAMETER(lanes);

    out = malloc(outlen + 1);
    if (!out) {
        clear_internal_memory(pwd, strlen(pwd));
        fatal("could not allocate memory for output");
    }

    encodedlen = argon2_encodedlen(t_cost, m_cost, lanes, (uint32_t)saltlen, outlen, type);
    encoded = malloc(encodedlen + 1);
    if (!encoded) {
        clear_internal_memory(pwd, strlen(pwd));
        fatal("could not allocate memory for hash");
    }

    result = argon2_hash(t_cost, m_cost, threads, pwd, pwdlen, salt, saltlen,
                         out, outlen, encoded, encodedlen, type,
                         ARGON2_VERSION_NUMBER);
    if (result != ARGON2_OK)
        fatal(argon2_error_message(result));

    stop_time = clock();

    if (encoded_only)
        puts(encoded);

    if (raw_only)
        print_hex(out, outlen);

    if (encoded_only || raw_only) {
        free(out);
        free(encoded);
        return;
    }

    printf("Hash:\t\t");
    print_hex(out, outlen);
    free(out);

    printf("Encoded:\t%s\n", encoded);

    printf("%2.3f seconds\n",
           ((double)stop_time - start_time) / (CLOCKS_PER_SEC));

    result = argon2_verify(encoded, pwd, pwdlen, type);
    if (result != ARGON2_OK)
        fatal(argon2_error_message(result));
    printf("Verification ok\n");
    free(encoded);
}
