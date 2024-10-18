/**
 * @file main.c
 * @brief Primary implementation for the `mftahcrypt` CLI tool.
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

#include "include/mftahcrypt.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>



/* Inclusion of the Signature value. */
extern const char *const MftahPayloadSignature;

/* A protocol handle for the MFTAH library. */
static mftah_protocol_t *MFTAH = NULL;

/* A set of characters permitted for use in MFTAH passwords. */
static const char *const MftahPermittedPasswordCharacters =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "`~!@#$%^&*()[]{};:,.<>/?|-_=+'\"\\";

/* Program context from provided CLI options at runtime. */
static MftahOptions sOptions = {0};

/* The payload being operated on. Allocated at runtime. */
static mftah_payload_t *sPayload = NULL;

/* Controls features related to obtaining and storing the password. */
static MftahPasswordContext sPassword = {0};
static MftahPasswordContext sRekeyPassword = {0};

/* Input and output filename paths from CLI options. */
/*  A NULL Filename value indicates no filename was selected (unused option). */
static MftahFile sInput  = {0};
static MftahFile sOutput = {0};

/* The input buffer allocated for the selected operation. */
static MftahBuffer sDataIn = {0};

/* A thread context pool to access live thread data. */
static volatile ThreadMeta sThreads[MFTAH_MAX_THREAD_COUNT] = {0};



static void usage()
{
    printf(
        "This application encrypts and decrypts MFTAH payloads provided either\n"
        "   by STDIN or by a file path. It sends the en/decrypted content to either\n"
        "   STDOUT or to a destination file.\n"
        "\n"
        "USAGE:\n"
        "   Encrypt a file:     ./mftahcrypt -ep 'eee' -i /mnt/usb/mydisk.IMG -o mydisk.GDEI\n"
        "   Decrypt from STDIN: ./mftahcrypt -dP ~/.payload_pass <payload.GDEI >payload.IMG\n"
        "   Piped decryption:   dd if=/some/file | ./mftahcrypt -dp 'wow123' | tee out.IMG\n"
        "\n"
        "OPTIONS:\n"
        "   -h,--help       Shows this usage information.\n"
        "   -d,--decrypt    Specifies that the program should decrypt input data.\n"
        "   -e,--encrypt    Specifies that the program should encrypt input data.\n"
        "   -r,--rekey      Enable re-key mode. Changes the input payload's password.\n"
        "   -o,--output     Writes the en/decrypt output to the given file path.\n"
        "   -i,--input      Specifies a file to read from for the operation.\n"
        "                    The '-' character specifies STDIN, but this is implied.\n"
        "   -p,--password   A password string to use for encryption or decryption.\n"
        "                    When changing a MFTAH password, this is the CURRENT password.\n"
        "   -P,--passfile   A path to a file containing the password to use.\n"
        "                    When changing a MFTAH password, this is the CURRENT password file.\n"
        "   -c,--new-password\n"
        "                   A new password to use for the input payload during re-keying.\n"
        "   -C,--new-passfile\n"
        "                   A new password file to use for the input payload during\n"
        "                    re-keying operations.\n"
        "   -F,--force-password\n"
        "                   Force acceptance of all given passwords when encrypting or\n"
        "                    rekeying a target payload.\n"
        "   -t,--threads\n"
        "                   For encryption and re-keying only. Specify how many parallel\n"
        "                    threads should be used to encrypt the data. Defaults to %u.\n"
        "   -n,--noninteractive\n"
        "                   Runs the operation in a non-interactive mode. This will\n"
        "                    perform the crypto operation without any confirmations.\n"
        "                    USE WITH CAUTION.\n"
        "   -q,--quiet      Suppress all progress bars and other output.\n"
        "   -v,--version    Print version information and exit.\n"
        "\n"
        "\n", MFTAH_DEFAULT_THREAD_COUNT
    );

    exit(1);
}


static void libmftah_print_hook(
    mftah_log_level_t level,
    const char *format,
    ...
);

static void evaluate_options(
    int argc,
    char *argv[]
);

static void load_password(
    MftahPasswordContext *password_ctx
);

static void *work(void *context);
static mftah_status_t spawn_worker(
    mftah_immutable_protocol_t self,
    mftah_work_order_t *work_order,
    immutable_ref_t sha256_key,
    immutable_ref_t iv,
    mftah_progress_t *progress
);

static void spin(
    uint64_t *queued_bytes
);

static void initialize();
static void pre_check_password();
static void read_input_buffer();
static void clean_threads();


static
void
fwrite_wrapper(uint8_t *at, uint64_t size)
{
    fwrite(at, 1, size, sOutput.Handle);
}


static
void
print_progress(const uint64_t *const current_value,
               const uint64_t *const out_of_value)
{
    uint8_t percent_done, percent_by_five;
    double percent_raw;
    
    if (NULL == current_value || NULL == out_of_value || 0 == *out_of_value)
        return;

    percent_raw = (double)(*current_value) / (double)(*out_of_value);
    percent_done = MIN(100, (int)(percent_raw * 100.0f));
    percent_by_five = MIN(20, (percent_done / 5));

    PRINT("\r  %3u%% [", percent_done);
    for (int i = 0; i < percent_by_five; ++i) PRINT("=");
    for (int i = 0; i < (20 - percent_by_five); ++i) PRINT(" ");
    PRINT("] (%16lx / %16lx)   ", *current_value, *out_of_value);
}

static
void
print_progress_wrapper(const uint64_t *const curr,
                       const uint64_t *const out_of,
                       void *ctx)
{
    print_progress(curr, out_of);
}



/**********************************************/
/**********************************************/
/************** MAIN APPLICATION **************/
/**********************************************/
/**********************************************/
int
main(int  argc,
     char *argv[])
{
    mftah_status_t status = MFTAH_SUCCESS;

    DPRINTLN("Initializing.");
    initialize();

    DPRINTLN("Evaluating CLI options.");
    evaluate_options(argc, argv);
    
    DPRINTLN("Reading input buffer information.");
    read_input_buffer();

    /* NOTE: The sDataIn is consumed and reallocated by the MFTAH API here. */
    DPRINTLN("Forming payload object scaffolding.");
    sPayload = (mftah_payload_t *)calloc(1, sizeof(mftah_payload_t));
    status = MFTAH->create_payload(MFTAH,
                                  sDataIn.BufferOriginal,
                                  sDataIn.BufferLength,
                                  sPayload,
                                  NULL);
    if (MFTAH_ERROR(status)) {
        ABORT("Failed to create the payload structure in memory. Exit code '%d'.", status);
    }
    sDataIn.BufferOriginal = sDataIn.BufferScroll = NULL;
    sDataIn.BufferLength = 0;

    PRINTLN("Working. Please be patient.");
    switch (sOptions.Mode) {
        case MFTAH_MODE_ENCRYPT:
            status = MFTAH->encrypt(MFTAH,
                                   sPayload,
                                   sPassword.RawValue,
                                   sPassword.RawValueLength,
                                   sOptions.Threads,
                                   spawn_worker,
                                   spin);
            break;
        case MFTAH_MODE_DECRYPT:
            status = MFTAH->decrypt(MFTAH,
                                   sPayload,
                                   sPassword.RawValue,
                                   sPassword.RawValueLength,
                                   spawn_worker,
                                   spin);
            break;
        case MFTAH_MODE_REKEY:
            status = MFTAH->rekey(MFTAH,
                                 sPayload,
                                 sPassword.RawValue,
                                 sPassword.RawValueLength,
                                 sRekeyPassword.RawValue,
                                 sRekeyPassword.RawValueLength,
                                 sOptions.Threads,
                                 spawn_worker,
                                 spawn_worker,
                                 spin);
            break;
        default:
            ABORT("Unknown operating mode.");
    }

    if (MFTAH_ERROR(status)) {
        ABORT("Failed to complete the operation. Exit code '%d'.", status);
    }

    DPRINTLN("Crypto operation complete. Yielding and cleaning up.");

    PRINTLN("Writing output...");
    fseek(sOutput.Handle, 0L, SEEK_SET);
    status = MFTAH->yield_payload(MFTAH,
                                 sPayload,
                                 65536,
                                 fwrite_wrapper,
                                 stdout == sOutput.Handle ? NULL : print_progress_wrapper);
    if (MFTAH_ERROR(status)) {
        ABORT("Failed to write the output payload. Exit code '%d'.", status);
    }

    if (NULL != sInput.Handle  && stdin  != sInput.Handle)     fclose(sInput.Handle);
    if (NULL != sOutput.Handle && stdout != sOutput.Handle)    fclose(sOutput.Handle);

    PRINTLN("\nAll done!\n");
    return EXIT_SUCCESS;
}


static
void
initialize()
{
    mftah_status_t status = MFTAH_SUCCESS;

    DPRINTLN("Creating MFTAH protocol and registering function hooks.");
    MFTAH = (mftah_protocol_t *)calloc(1, sizeof(mftah_protocol_t));
    if (NULL == MFTAH) {
        ABORT("Could not allocate or acquire the MFTAH protocol instance.");
    }

    status = mftah_protocol_factory__create(MFTAH);
    if (MFTAH_ERROR(status)) {
        ABORT("Invalid default hook registration in the MFTAH library.");
    }

    mftah_registration_details_t *registration
        = (mftah_registration_details_t *)calloc(1, sizeof(mftah_registration_details_t));
    
    registration->calloc    = calloc;
    registration->malloc    = malloc;
    registration->realloc   = realloc;
    registration->memcpy    = memcpy;
    registration->memset    = memset;
    registration->memmove   = memmove;
    registration->memcmp    = memcmp;
    registration->printf    = libmftah_print_hook;
    registration->free      = free;

    status = MFTAH->register_hooks(MFTAH, registration);
    if (MFTAH_ERROR(status)) {
        ABORT("There was a problem registering libmftah hooks. Exit code '%d'.", status);
    }

    free(registration);
}



static
void
evaluate_options(int argc,
                 char *argv[])
{
    if (1 >= argc) {
        PRINTLN("ERROR: No options were provided.\n");
        usage();
    }

    int option_index = 0;
    int option_value = 0;

    static struct option long_options[] = {
        { "help",           no_argument,    NULL,   'h' },
        { "password",       1,              NULL,   'p' },
        { "passfile",       1,              NULL,   'P' },
        { "new-password",   1,              NULL,   'c' },
        { "new-passfile",   1,              NULL,   'C' },
        { "decrypt",        no_argument,    NULL,   'd' },
        { "encrypt",        no_argument,    NULL,   'e' },
        { "rekey",          no_argument,    NULL,   'r' },
        { "output",         1,              NULL,   'o' },
        { "input",          1,              NULL,   'i' },
        { "threads",        no_argument,    NULL,   't' },
        { "noninteractive", no_argument,    NULL,   'n' },
        { "force-password", no_argument,    NULL,   'F' },
        { "quiet",          no_argument,    NULL,   'q' },
        { "version",        no_argument,    NULL,   'v' },
        { NULL,             no_argument,    NULL,   0   }
    };

    DPRINTLN("Parsing command-line options...");

    while (-1 != (option_value = getopt_long(argc, argv, "hp:P:c:C:dero:i:t:nFqv", long_options, &option_index))) {
        switch (option_value) {
            case 'p':
                DPRINTLN("Using password string '%s'.", optarg);
                sPassword.Type = MFTAH_PASSWORD_STRING;
                sPassword.RawValue = optarg;
                break;
            case 'P':
                DPRINTLN("Using password file '%s'.", optarg);
                sPassword.Type = MFTAH_PASSWORD_FILE;
                sPassword.Path = optarg;
                break;
            case 'c':
                DPRINTLN("Using NEW password string '%s'.", optarg);
                sRekeyPassword.Type = MFTAH_PASSWORD_STRING;
                sRekeyPassword.RawValue = optarg;
                break;
            case 'C':
                DPRINTLN("Using NEW password file '%s'.", optarg);
                sRekeyPassword.Type = MFTAH_PASSWORD_FILE;
                sRekeyPassword.Path = optarg;
                break;
            case 'd':
                DPRINTLN("Decryption mode set.");
                sOptions.Mode = MFTAH_MODE_DECRYPT;
                break;
            case 'e':
                DPRINTLN("Encryption mode set.");
                sOptions.Mode = MFTAH_MODE_ENCRYPT;
                break;
            case 'r':
                DPRINTLN("Rekey mode set.");
                sOptions.Mode = MFTAH_MODE_REKEY;
                break;
            case 'o':
                DPRINTLN("Attempt to set an output file path.");
                sOutput.Filename = optarg;
                break;
            case 'i':
                DPRINTLN("Attempt to set an input file path.");
                sInput.Filename = optarg;
                break;
            case 't':
                DPRINTLN("Attempt to set a thread count of '%s'.", optarg);
                for (char *c = optarg; *c; ++c) {
                    if (*c < 0x30 || *c > 0x39) {
                        ABORT("The threads (-t) value must be a number.");
                    }
                }
                sOptions.Threads = (uint8_t)(atoi(optarg));
                break;
            case 'n':
                DPRINTLN("Non-interactive flag set.");
                sOptions.IsNonInteractive = true;
                break;
            case 'F':
                NOTICE("Forcing password accommodation outside of normal limits.");
                sOptions.ForcePassword = true;
                break;
            case 'q':
                sOptions.Quiet = true;
                break;
            case 'v':
                printf(
                    "mftahcrypt (MFTAH-CLI), version %s.\n"
                    "\tUsing `libmftah` version %s.\n"
                    "\tWritten by Zack Puhl <zack@crows.dev> (https://github.com/NotsoanoNimus/MFTAH-CLI)\n"
                    "\tRelease Code: %s\n\n",
                    MFTAHCRYPT_VERSION,
                    LIBMFTAH_VERSION,
                    MFTAH_RELEASE_DATE_STRING
                );
                exit(2);
            case 'h':
                DPRINTLN("Displaying usage details by explicit '-h' parameter.");
            default:
                usage();
        }
    }

    DPRINTLN("Validating user inputs and execution parameters.");

    DPRINTLN("Checking threads.");
    if (sOptions.Threads > MFTAH_MAX_THREAD_COUNT) {
        ABORT("The maximum thread count for MFTAH is limited to %u.", MFTAH_MAX_THREAD_COUNT);
    } else if (MFTAH_MODE_DECRYPT == sOptions.Mode && sOptions.Threads) {
        PRINTLN("WARNING: You specified a 'threads' value, but this is a decryption operation. Ignoring.");
    }

    if (sOptions.Threads < 1) {
        PRINTLN("WARNING: Threads not set or less than 0. Defaulting to %u.", MFTAH_DEFAULT_THREAD_COUNT);
        sOptions.Threads = MFTAH_DEFAULT_THREAD_COUNT;
    }

    DPRINTLN("Checking crypto mode.");
    if (MFTAH_MODE_UNKNOWN == sOptions.Mode) {
        ABORT("You must explicitly choose either '-d' (decrypt), '-r' (rekey), or '-e' (encrypt).");
    }

    load_password(&sPassword);
    if (MFTAH_MODE_REKEY == sOptions.Mode) {
        if (NULL == sRekeyPassword.RawValue || 0 == strnlen(sRekeyPassword.RawValue, 1)) {
            ABORT("Missing rekey password. You must use the '-c' or '-C' options to provide a new one.");
        }
        load_password(&sRekeyPassword);
    }

    /* Set up input file details. */
    if (NULL == sInput.Filename) {
        sInput.Handle = stdin;
    } else {
        sInput.Handle = fopen(sInput.Filename, "rb");
        if (NULL == sInput.Handle) {
            ABORT("Unable to read the specified input file.");
        }
    }

    /* Set up output file details. */
    if (NULL == sOutput.Filename) {
        sOutput.Handle = stdout;
    } else {
        /* Check file existence first and confirm if interactive. */
        if (0 == access(sOutput.Filename, F_OK)) {
            if (false == sOptions.IsNonInteractive) {
                ABORT(
                    "The destination file already exists.\n"
                    "   Re-run this program with the '-n' option to confirm you would like to overwrite it."
                );
            } else {
                /* Delete the target output file that's there now. */
                if (0 != remove(sOutput.Filename)) {
                    ABORT("Failed to overwrite the output file.");
                }
            }
        }
        sOutput.Handle = fopen(sOutput.Filename, "wb");
        if (NULL == sOutput.Handle) {
            ABORT(
                "Unable to write to the specified output file.\n"
                "   Please check that the directory exists and that you have\n"
                "   sufficient permissions to write there, then try again."
            );
        }
    }
}


static
void
load_password(MftahPasswordContext *password_ctx)
{
    mftah_status_t status = MFTAH_SUCCESS;

    DPRINTLN("Loading and validating a password.");

    if (MFTAH_PASSWORD_STRING == password_ctx->Type) {
        if (NULL == password_ctx->RawValue) {
            ABORT("A valid string password was not provided to the program.");
        }

        DPRINTLN("Using password string mode.");

        uint64_t pass_len = strlen(password_ctx->RawValue);
        DPRINTLN("   Password length: %lu", pass_len);

        if (0 == pass_len) {
            ABORT("Empty password! Even a forced override will not allow an empty value.");
        } else if (pass_len > MFTAH_MAX_PW_LEN) {
            ABORT("MFTAH passwords can NEVER be greater than %u characters.", MFTAH_MAX_PW_LEN);
        }

        password_ctx->RawValueLength = pass_len;

        /* Ensure no invalid characters are present when this is an encryption operation. */
        /*  Don't do this for decryption, since the password could have been set outside
            the approved character set elsewhere. */
        if (MFTAH_MODE_DECRYPT != sOptions.Mode && false == sOptions.ForcePassword) {
            if (pass_len < MFTAH_MIN_PW_LEN) {
                ABORT("MFTAH passwords cannot be less than %u characters.", MFTAH_MIN_PW_LEN);
            }

            for (int i = 0; i < pass_len; ++i) {
                for (int j = 0; j < strlen(MftahPermittedPasswordCharacters); ++j) {
                    if (password_ctx->RawValue[i] == MftahPermittedPasswordCharacters[j]) {
                        goto Label__AcceptedPasswordCharacter;
                    }
                }
                ABORT("The character '%c' is not a legal MFTAH password input.", password_ctx->RawValue[i]);
            Label__AcceptedPasswordCharacter:
                (void)0;   /* NO-OP */
            }
        }
    } else if (MFTAH_PASSWORD_FILE == password_ctx->Type) {
        if (NULL == password_ctx->Path || 0 == strlen(password_ctx->Path)) {
            ABORT("Loading a password file was specified, but the path was not set at runtime.");
        }

        if (MFTAH_MODE_ENCRYPT == sOptions.Mode) {
            DPRINTLN("");
            DPRINTLN(
                "The MFTAH-UEFI bootloader WILL NOT interpret file-based passwords.\n"
                "   Use a string password with '-p' if you are using this program\n"
                "      to create a MFTAH image for use on boot media.\n"
                "\n"
            );
        }

        password_ctx->RawValue = (const char *)calloc(1, MFTAH_MAX_PW_FILE_LEN_WITH_OVERRIDE + 1);

        uint64_t pass_file_read_size = 0;
        FILE *pass_file_handle = fopen(password_ctx->Path, "rb");
        if (NULL == pass_file_handle) {
            ABORT("Failed to read the specified password file.");
        }

        /* Ingest the password data. */
        pass_file_read_size = fread((void *)(password_ctx->RawValue),
                                    1,
                                    MFTAH_MAX_PW_FILE_LEN_WITH_OVERRIDE + 1,
                                    pass_file_handle);
        DPRINTLN("Read %lu bytes from the given password file.", pass_file_read_size);

        if (0 == pass_file_read_size) {
            fclose(pass_file_handle);
            ABORT("An empty file cannot be used as a password.")
        } else if (false == sOptions.ForcePassword) {
            if (pass_file_read_size < MFTAH_MIN_PW_FILE_LEN) {
                fclose(pass_file_handle);
                ABORT(
                    "A password file must contain at least %u bytes of pseudo-random noise.\n"
                    "  To override this, use the '-F' option.", MFTAH_MIN_PW_FILE_LEN
                );
            } else if (pass_file_read_size > MFTAH_MAX_PW_FILE_LEN) {
                fclose(pass_file_handle);
                ABORT(
                    "A password file must contain more than %u bytes of pseudo-random noise.\n"
                    "  To override this, use the '-F' option.", MFTAH_MAX_PW_FILE_LEN
                );
            }
        }

        if (pass_file_read_size > MFTAH_MAX_PW_FILE_LEN_WITH_OVERRIDE) {
            ABORT(
                "The maximum password file size is %u bytes.\n"
                "\tThis cannot be overridden.", MFTAH_MAX_PW_FILE_LEN_WITH_OVERRIDE
            );
        }

        uint8_t *readjusted = (uint8_t *)realloc((void *)(password_ctx->RawValue), pass_file_read_size);
        if (NULL == readjusted) {
            /* Do not abort because of this. */
            NOTICE("Could not readjust the input buffer size for the password file's contents.");
        } else {
            password_ctx->RawValue = (const char *)readjusted;
        }

        password_ctx->RawValueLength = pass_file_read_size;
        fclose(pass_file_handle);
    }

    /* Hash the password in case we need it later on. */
    status = MFTAH->create_hash(MFTAH,
                               password_ctx->RawValue,
                               password_ctx->RawValueLength,
                               password_ctx->Sha256Hash,
                               NULL);
    if (MFTAH_ERROR(status)) {
        ABORT("Failed to hash the input password. Exit code '%d'.", status);
    }

    DPRINT("[MFTAHCRYPT] DEBUG:  Got loaded password hash '");
    for (int i = 0; i < SIZE_OF_SHA_256_HASH; ++i)
        DPRINT("%02x", password_ctx->Sha256Hash[i]);
    DPRINT("'.\n");
}


/* The point of this function is to return FAST password check failures on BIG data.
    Without using this, inputs >2G might take over 20 seconds to come back with errors
    from an invalid input password. */
static
void
pre_check_password()
{
    uint64_t bytes_read = fread(sDataIn.BufferScroll, 1, sizeof(mftah_payload_header_t), sInput.Handle);

    sDataIn.BufferScroll += bytes_read;

    /* NOTE: bytes_read is now equivalent to the size of a MFTAH header.
        We thus don't need to keep calling this external library method. */
    if (bytes_read != sizeof(mftah_payload_header_t)) {
        ABORT("The input payload is too short to be decrypted (read %lu bytes).", bytes_read);
    }

    uint8_t *decrypted_header = (uint8_t *)calloc(1, bytes_read);
    memcpy(decrypted_header, sDataIn.BufferOriginal, bytes_read);

    uint8_t *signature_location = decrypted_header + bytes_read - MFTAH_PAYLOAD_SIGNATURE_SIZE;

    mftah_work_order_t *new_order = (mftah_work_order_t *)calloc(1, sizeof(mftah_work_order_t));
    /* Glorious hacks and hacks... Go back yet another 16 bytes. Thanks to Cipher Block Chain (CBC)
        mode with AES, we MUST decrypt from the starting point where the payload was encrypted. In
        the case of MFTAH headers, that's 32 bytes from its tail end. */
    new_order->location = signature_location - MFTAH_PAYLOAD_SIGNATURE_SIZE;
    new_order->length = MFTAH_PAYLOAD_SIGNATURE_SIZE * 2;
    new_order->type = MFTAH_WORK_TYPE_DECRYPT;

    mftah_status_t status = MFTAH_CRYPT_HOOK_DEFAULT(MFTAH,
                                                   new_order,
                                                   (immutable_ref_t)sPassword.Sha256Hash,
                                                   /* Yet another Hack (TM) -- the IV is always one AES_BLOCKLEN in. */
                                                   (immutable_ref_t)(decrypted_header + AES_BLOCKLEN),
                                                   NULL);
    if (MFTAH_ERROR(status)) {
        ABORT("Decryption returned error.");
    }

    if (0 != memcmp(signature_location, MftahPayloadSignature, MFTAH_PAYLOAD_SIGNATURE_SIZE)) {
        ABORT("Invalid password. Try again.");
    }

    free(new_order);
    free(decrypted_header);
}


static
void
read_input_buffer()
{
    uint64_t read_file_size = 0;
    uint64_t bytes_read = 0;
    uint8_t *reallocated_buffer = NULL;

    if (stdin == sInput.Handle) {
        /* Start with a modest 64KiB buffer size, and double its size until it
            fits the input data or reaches a maximum allocation size. */
        sDataIn.BufferLength += (64ULL * 1024);
        sDataIn.BufferOriginal = (uint8_t *)malloc(sDataIn.BufferLength);
        sDataIn.BufferScroll = sDataIn.BufferOriginal;

        if (NULL == sDataIn.BufferOriginal) {
            ABORT("Not enough memory to read that input (%lu bytes).", sDataIn.BufferLength);
        }

        /* For decryptions, read in the header block and check whether the password is correct. */
        if (MFTAH_MODE_DECRYPT == sOptions.Mode || MFTAH_MODE_REKEY == sOptions.Mode) {
            pre_check_password();

            /* Since the header is read, account for it in the resulting malloc/realloc. */
            read_file_size += sizeof(mftah_payload_header_t);
        }

        do {
            bytes_read = fread(sDataIn.BufferScroll, 1, AES_BLOCKLEN, sInput.Handle);

            sDataIn.BufferScroll += bytes_read;
            read_file_size += bytes_read;

            /* If a block size was read, there's likely more data. In that case, make sure the 
                buffer has room for another block by reallocating it by a power of two. */
            if ((read_file_size + AES_BLOCKLEN) > sDataIn.BufferLength && AES_BLOCKLEN == bytes_read) {
                sDataIn.BufferLength <<= 1;
                DPRINTLN("Reallocating buffer to %lu bytes.", sDataIn.BufferLength);

                reallocated_buffer = (uint8_t *)realloc(sDataIn.BufferOriginal, sDataIn.BufferLength);

                /* Any reallocation failures MUST abort the operation and program. */
                if (NULL == reallocated_buffer) {
                    ABORT("Not enough memory to read STDIN. Last requested size: %lu bytes.", sDataIn.BufferLength);
                }

                /* Move all pointer positions to account for any reallocations. */
                sDataIn.BufferOriginal = reallocated_buffer;
                sDataIn.BufferScroll = (reallocated_buffer + read_file_size);
            }
        } while (AES_BLOCKLEN == bytes_read);
    } else {
        /* Since the input is a file, seek can tell us the size ahead of time. */
        fseek(sInput.Handle, 0L, SEEK_END);
        read_file_size += ftell(sInput.Handle);
        fseek(sInput.Handle, 0L, SEEK_SET);

        sDataIn.BufferOriginal = (uint8_t *)malloc(read_file_size);
        if (NULL == sDataIn.BufferOriginal) {
            ABORT("Not enough memory to read that input file (%lu bytes).", read_file_size);
        }

        sDataIn.BufferScroll = sDataIn.BufferOriginal;

        if (MFTAH_MODE_DECRYPT == sOptions.Mode || MFTAH_MODE_REKEY == sOptions.Mode) {
            pre_check_password();
        }

        /* Finally, read the file into the buffer. */
        while (AES_BLOCKLEN == (bytes_read = fread(sDataIn.BufferScroll, 1, AES_BLOCKLEN, sInput.Handle))) {
            sDataIn.BufferScroll += bytes_read;
        }
    }

    /* Make sure the buffer length is the true file size, not the size of a malloc. */
    sDataIn.BufferLength = read_file_size;

    DPRINTLN("Loaded input data pool (%p : %lu)", sDataIn.BufferOriginal, sDataIn.BufferLength);
}


/* This is annoying, but it's a per-thread hook function to provide
    real-time updates on progress. */
static void thread_progress(const uint64_t *cur,
                            const uint64_t *out_of,
                            void *extra)
{
    *((uint64_t *)extra) = *cur;
}

/* THREADED ROUTINE. Ensure synchronicity where required. */
/*  This does the thread's leg-work by calling back into the MFTAH_xxCRYPT crypt_hook. */
static
void *
work(void *context)
{
    mftah_status_t status = MFTAH_SUCCESS;
    CommonThreadContext *ctx = (CommonThreadContext *)context;

    mftah_progress_t progress = {
        .context = (void *)&(ctx->progress),
        .hook = thread_progress
    };

    status = MFTAH_CRYPT_HOOK_DEFAULT((mftah_immutable_protocol_t)(ctx->protocol_instance),
                                     &ctx->work_order,
                                     ctx->sha256_key,
                                     ctx->iv,
                                     &progress);
    
    if (MFTAH_ERROR(status)) {
        ABORT("A failure was reported during the operation. Exit code '%d'.", status);
    }

    ctx->finished = true;
    return NULL;
}


/* This hook is called by the MFTAH library to perform a chunk of work. */
/*  It should take care to spawn a new thread and track it accordingly. */
static
mftah_status_t
spawn_worker(mftah_immutable_protocol_t protocol_instance,
             mftah_work_order_t *work_order,
             immutable_ref_t sha256_key,
             immutable_ref_t iv,
             mftah_progress_t *progress)
{
    volatile ThreadMeta *my_thread = NULL;

    if (
        NULL == protocol_instance
        || NULL == work_order
        || NULL == sha256_key
        || NULL == iv
    ) {
        return MFTAH_INVALID_PARAMETER;
    }

    if (!work_order->length) return MFTAH_SUCCESS;

    /* The library should never return a thread index higher or lower than what is possible. */
    if (work_order->thread_index < 0 || work_order->thread_index >= MFTAH_MAX_THREAD_COUNT) {
        ABORT(
            "Invalid thread index of %u. MFTAH has a thread limit of %u.",
            work_order->thread_index,
            MFTAH_MAX_THREAD_COUNT
        );
    }
    
    my_thread = &(sThreads[work_order->thread_index]);

    my_thread->Context = (CommonThreadContext *)calloc(1, sizeof(CommonThreadContext));
    my_thread->Context->protocol_instance = (mftah_protocol_t *)protocol_instance;

    memcpy((void *)&(my_thread->Context->work_order), work_order, sizeof(mftah_work_order_t));

    /* Cheating a bit here to override 'immutable' values but whatever. */
    memcpy((void *)&(my_thread->Context->sha256_key), &sha256_key, sizeof(immutable_ref_t));
    memcpy((void *)&(my_thread->Context->iv), &iv, sizeof(immutable_ref_t));
    my_thread->Context->finished = false;
    my_thread->Context->progress = 0;

    DPRINTLN(
        "Initializing new worker thread (#%u : %p : %lu : %u)",
        work_order->thread_index,
        work_order->location,
        work_order->length,
        work_order->type
    );
    MEMDUMP(work_order->location, MIN(64, work_order->length));

    pthread_create((pthread_t *)&(my_thread->Thread),
                    NULL,
                    work,
                    (void *)(my_thread->Context));

    return MFTAH_SUCCESS;
}


/* Callback function.
    Monitors progress while awaiting completion of all threads. */
static
void
spin(uint64_t *queued_bytes)
{
    bool completed = true;
    bool suppress_progress = false;
    uint64_t progress = 0;
    uint64_t total_progress = *queued_bytes;

    DPRINTLN("Initiating main thread spin and awaiting.");
    DPRINTLN("Got payload size to launder: %lu", total_progress);

    if (0 == total_progress) {
        ABORT("Total progress indicates the payload size is 0.");
    }

    /* Quickly check whether any of the threads indicate progress suppression. */
    for (int i = 0; i < MFTAH_MAX_THREAD_COUNT; ++i)
        if (NULL != sThreads[i].Context)
            suppress_progress |= sThreads[i].Context->work_order.suppress_progress;

    do {
        completed = true;
        progress = 0;
        for (int i = 0; i < MFTAH_MAX_THREAD_COUNT; ++i) {
            if (NULL == sThreads[i].Context) {
                /* If a thread isn't active or has no context pointer, skip it. */
                continue;
            }
            completed &= sThreads[i].Context->finished;
            progress += sThreads[i].Context->progress;
        }

        if (!suppress_progress) {
            print_progress(&progress, &total_progress);
        }

        usleep(50 * 1000);
    } while (!completed && progress < total_progress);

    /* Be sure the 100% message always gets out. */
    if (!suppress_progress) {
        print_progress(&total_progress, &total_progress);
        PRINT("\n\t~~~ OK ~~~\n\n");
    }

    /* Always clean up threads after a spin cycle completes. Laundry puns. :) */
    clean_threads();
}


static
void
clean_threads()
{
    DPRINTLN("Cleaning thread pool.");

    for (int i = 0; i < sOptions.Threads; ++i) {
        if (NULL != (void *)(sThreads[i].Thread)) {
            DPRINTLN("Joining thread #%d.", i);
            pthread_join(sThreads[i].Thread, NULL);
        }
        if (NULL != sThreads[i].Context) {
            free(sThreads[i].Context);
        }
    }

    memset((void *)sThreads, 0x00, (MFTAH_MAX_THREAD_COUNT * sizeof(ThreadMeta)));
}


static
void
libmftah_print_hook(mftah_log_level_t level,
                   const char *format,
                   ...)
{
    va_list args;
    char *with_level;
    const char *tag = "[LIBMFTAH]  %s:  ";

    va_start(args, format);

    if (sOptions.Quiet) goto libmftah_print_hook__end;
#ifndef MFTAHCRYPT_DEBUG
    if (MFTAH_LEVEL_DEBUG == level) goto libmftah_print_hook__end;
#endif

    with_level = (char *)calloc(1, 128);

    switch (level) {
        case MFTAH_LEVEL_DEBUG:
            sprintf(with_level, tag, "DEBUG");
            break;
        case MFTAH_LEVEL_INFO:
            sprintf(with_level, tag, "INFO");
            break;
        case MFTAH_LEVEL_NOTICE:
            sprintf(with_level, tag, "NOTICE");
            break;
        case MFTAH_LEVEL_WARNING:
            sprintf(with_level, tag, "WARNING");
            break;
        case MFTAH_LEVEL_ERROR:
            sprintf(with_level, tag, "ERROR");
            break;
        default:
            sprintf(with_level, tag, "?????");
            break;
    }

    if (MFTAH_LEVEL_DEBUG != level) {
        fprintf(stderr, "%s", with_level);
    }
    free(with_level);

    vfprintf(stderr, format, args);

libmftah_print_hook__end:
    va_end(args);
    return;
}
