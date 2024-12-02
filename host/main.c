/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

void create_output_filename(const char *input_file, const char *suffix, char *output_file, size_t size) {
    char base[256] = {0};
    char *dot = strrchr(input_file, '.');

    if (dot) {
        strncpy(base, input_file, dot - input_file);
        base[dot - input_file] = '\0';
        snprintf(output_file, size, "%s_%s%s", base, suffix, dot);
    }  else {
        snprintf(output_file, size, "%s_%s", input_file, suffix);
    }
}
void encrypt_file(const char *input_file, TEEC_Context *ctx, TEEC_Session *sess) {
    char plaintext[1024] = {0};
    char ciphertext[1024] = {0};
    uint8_t enc_key;
    size_t plaintext_len, ciphertext_len = sizeof(ciphertext), enc_key_len = sizeof(enc_key);
    TEEC_Operation op;

    char cipher_filename[256] = {0};
    char key_filename[256] = {0};

    FILE *file = fopen(input_file, "r");
    if (!file) {
        errx(1, "Failed to open input file: %s", input_file);
    }
    fread(plaintext, 1, sizeof(plaintext), file);
    fclose(file);
    plaintext_len = strlen(plaintext);

    printf("Plaintext read from file: %s\n", plaintext);

    // 암호화 요청 설정
    memset(&op, 0, sizeof(TEEC_Operation));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, 
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_NONE);

    op.params[0].tmpref.buffer = plaintext;
    op.params[0].tmpref.size = plaintext_len;
    op.params[1].tmpref.buffer = ciphertext;
    op.params[1].tmpref.size = ciphertext_len;
    op.params[2].tmpref.buffer = &enc_key;
    op.params[2].tmpref.size = enc_key_len;

   // 암호화 수행
    printf("Invoking TA for encryption...\n");
    TEEC_Result res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, NULL);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x", res);

    ciphertext_len = op.params[1].tmpref.size;
    enc_key = *(uint8_t *)op.params[2].tmpref.buffer;

    printf("Ciphertext: %s\n", ciphertext);
    printf("Encrypted Key: %d\n", enc_key);

    // 결과 파일 이름 생성
    create_output_filename(input_file, "ciphertext", cipher_filename, sizeof(cipher_filename));
    create_output_filename(input_file, "encryptedkey", key_filename, sizeof(key_filename));
    // 결과 저장
    FILE *cipher_file = fopen(cipher_filename, "w");
    if (!cipher_file) {
        errx(1, "Failed to open %s for writing", cipher_filename);
    }
    fwrite(ciphertext, 1, ciphertext_len, cipher_file);
    fclose(cipher_file);
    printf("Ciphertext saved to %s\n", cipher_filename);

    FILE *key_file = fopen(key_filename, "w");
    if (!key_file) {
        errx(1, "Failed to open %s for writing", key_filename);
    }
    fprintf(key_file, "%d", enc_key);
    fclose(key_file);
    printf("Encrypted key saved to %s\n", key_filename);
}

void decrypt_file(const char *ciphertext_file, const char *key_file, TEEC_Context *ctx, TEEC_Session *sess) {
    char ciphertext[1024] = {0};
    char plaintext[1024] = {0};
    uint8_t enc_key;
    size_t ciphertext_len, plaintext_len = sizeof(plaintext);
    TEEC_Operation op;
    char decrypted_filename[256] = {0};
    // 암호문 읽기
    FILE *file = fopen(ciphertext_file, "r");
    if (!file) {
        errx(1, "Failed to open ciphertext file: %s", ciphertext_file);
    }
    fread(ciphertext, 1, sizeof(ciphertext), file);
    fclose(file);
    ciphertext_len = strlen(ciphertext);

    // 암호화된 키 읽기
    file = fopen(key_file, "r");
    if (!file) {
        errx(1, "Failed to open key file: %s", key_file);
    }
    fscanf(file, "%hhu", &enc_key);
    fclose(file);

    printf("Ciphertext read from file: %s\n", ciphertext);
    printf("Encrypted Key read from file: %d\n", enc_key);

    // 복호화 요청 설정
    memset(&op, 0, sizeof(TEEC_Operation));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                      TEEC_MEMREF_TEMP_OUTPUT,
                                      TEEC_VALUE_INPUT,
                                      TEEC_NONE);

    op.params[0].tmpref.buffer = ciphertext;
    op.params[0].tmpref.size = ciphertext_len;
    op.params[1].tmpref.buffer = plaintext;
    op.params[1].tmpref.size = plaintext_len;
    op.params[2].value.a = enc_key;

    // 복호화 수행
    printf("Invoking TA for decryption...\n");
    TEEC_Result res = TEEC_InvokeCommand(sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, NULL);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand failed with code 0x%x", res);

    plaintext_len = op.params[1].tmpref.size;

    printf("Decrypted Plaintext: %s\n", plaintext);

    create_output_filename(ciphertext_file, "decrypted", decrypted_filename, sizeof(decrypted_filename));
    // 결과 저장
    FILE *plaintext_file = fopen(decrypted_filename, "w");
    if (!plaintext_file) {
        errx(1, "Failed to open decrypted.txt for writing");
    }
    fwrite(plaintext, 1, plaintext_len, plaintext_file);
    fclose(plaintext_file);
    printf("Decrypted plaintext saved to %s\n", decrypted_filename);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s -e <input_file>\n", argv[0]);
        printf("       %s -d <ciphertext_file> <key_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_UUID uuid = TA_TEEencrypt_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);


    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    

    if (strcmp(argv[1], "-e") == 0) {
        encrypt_file(argv[2], &ctx, &sess);
    } else if (strcmp(argv[1], "-d") == 0 && argc == 4) {
        decrypt_file(argv[2], argv[3], &ctx, &sess);
    } else {
        printf("Invalid arguments.\n");
        return EXIT_FAILURE;
    }

    // OP-TEE 정리
    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return EXIT_SUCCESS;
}


