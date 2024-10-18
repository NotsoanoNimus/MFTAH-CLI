/**
 * @file mftahcrypt.h
 * @brief Header file with declarations for the 'mftahcrypt' CLI application.
 *
 * @author Puhl, Zachary (Zack) <zack@crows.dev>
 * @date 2024-10-17
 * 
 * @copyright Copyright (C) 2024 Zack Puhl
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 3.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 */

#ifndef MFTAHCRYPT_H
#define MFTAHCRYPT_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include <pthread.h>

/* This program assumes that `libmftah` is already installed.
    If not, fetch it from https://github.com/NotsoanoNimus/MFTAH. */
#include <mftah.h>



/* Semantic versioning in case we want it. */
#define MFTAHCRYPT_VERSION_MAJOR 1
#define MFTAHCRYPT_VERSION_MINOR 1
#define MFTAHCRYPT_VERSION_PATCH 0

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define MFTAHCRYPT_VERSION \
    STRINGIFY(MFTAHCRYPT_VERSION_MAJOR) "." STRINGIFY(MFTAHCRYPT_VERSION_MINOR) "." STRINGIFY(MFTAHCRYPT_VERSION_PATCH)


#define MAX(x,y) \
    (((x) >= (y)) ? (x) : (y))
#define MIN(x,y) \
    (((x) <= (y)) ? (x) : (y))


#define PRINT(x, ...) \
    if (!sOptions.Quiet) fprintf(stderr, x, ##__VA_ARGS__);
#define PRINTLN(x, ...) \
    if (!sOptions.Quiet) fprintf(stderr, x "\n", ##__VA_ARGS__);

#ifdef MFTAHCRYPT_DEBUG
#define DPRINT(x, ...) \
    if (!sOptions.Quiet) fprintf(stderr, x, ##__VA_ARGS__);
#define DPRINTLN(x, ...) \
    if (!sOptions.Quiet) fprintf(stderr, "[MFTAHCRYPT] DEBUG:  " x "\n", ##__VA_ARGS__);
#define MEMDUMP(ptr, len) \
    if (!sOptions.Quiet) { \
        for (int i = 0; i < (len); ++i) { \
        fprintf(stderr, "%02x%c", *((uint8_t *)(ptr)+i), !((i+1) % 16) ? '\n' : ' '); \
        } \
        if (!(len % 16)) fprintf(stderr, "\n"); \
    }
#else
#define DPRINT(x, ...)
#define DPRINTLN(x, ...)
#define MEMDUMP(ptr, len)
#endif   /* MFTAHCRYPT_DEBUG */

#define NOTICE(x, ...) \
    fprintf(stderr, "[MFTAHCRYPT] NOTICE:  " x "\n", ##__VA_ARGS__);

#define ABORT(x, ...) \
    fprintf(stderr, "[MFTAHCRYPT] ERROR:  " x "\n\n", ##__VA_ARGS__); \
    exit(1);

/* Default MFTAH compilation date. This is usually set in the Makefile. */
#ifndef MFTAH_RELEASE_DATE
#   define MFTAH_RELEASE_DATE 0x20240506
#endif

#define MFTAH_RELEASE_DATE_STRING \
    STRINGIFY(MFTAH_RELEASE_DATE)

/* The amount of threads to create when encrypting or rekeying files. */
#ifndef MFTAH_DEFAULT_THREAD_COUNT
#   define MFTAH_DEFAULT_THREAD_COUNT       16
#endif

/* The length requirements of the password buffer. */
#define MFTAH_MAX_PW_LEN 32
#define MFTAH_MIN_PW_LEN 8

#define MFTAH_MIN_PW_FILE_LEN                64
#define MFTAH_MAX_PW_FILE_LEN                2048
#define MFTAH_MAX_PW_FILE_LEN_WITH_OVERRIDE  65536



/* An easy-to-adjust settings enum for the current encryption mode. */
typedef
enum {
    MFTAH_MODE_UNKNOWN   = 0,
    MFTAH_MODE_ENCRYPT   = (1 << 1),
    MFTAH_MODE_DECRYPT   = (1 << 2),
    MFTAH_MODE_REKEY     = (1 << 3)
} MftahMode;

/* An easy-to-adjust settings enum for the password mode. */
typedef
enum {
    MFTAH_PASSWORD_STRING = 1,
    MFTAH_PASSWORD_FILE   = (1 << 1)
} MftahPasswordType;


/* Options set from CLI arguments. */
typedef
struct {
    /* Controls whether this call of the program is encrypting, rekeying, or decrypting. */
    MftahMode           Mode;
    /* Controls forced acceptance of a given password during encryption or rekeying. */
    bool                ForcePassword;
    /* Controls the interactivity of the program. Set TRUE by CLI option '-n'. */
    bool                IsNonInteractive;
    /* If set, suppresses progress markers and debugging information (if enabled). */
    bool                Quiet;
    /* Set the amount of threads to use during encryption/re-keying. */
    uint8_t             Threads;
} MftahOptions;


/* Other useful structures. */
typedef
struct {
    const char          *Filename;
    FILE                *Handle;
} MftahFile;

typedef
struct {
    void                *BufferOriginal;
    void                *BufferScroll;
    uint64_t            BufferLength;
} MftahBuffer;


/* Password-related structures. */
typedef
struct {
    MftahPasswordType   Type;
    const char          *RawValue;
    uint64_t            RawValueLength;
    uint8_t             Sha256Hash[32];
    const char          *Path;
} MftahPasswordContext;


/* Threading-related structures. */
typedef
struct {
    mftah_protocol_t    *protocol_instance;
    mftah_work_order_t  work_order;
    immutable_ref_t     sha256_key;
    immutable_ref_t     iv;
    uint64_t            progress;
    bool                finished;
} CommonThreadContext;

typedef
struct {
    pthread_t           Thread;
    CommonThreadContext *Context;
} ThreadMeta;



#endif   /* MFTAHCRYPT_H */
