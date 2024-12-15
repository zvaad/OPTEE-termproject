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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include <TEEencrypt_ta.h>


static uint8_t key;
static const uint8_t root_key = 5;
static TEE_ObjectHandle rsa_keypair;
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
	if (rsa_keypair)
		TEE_FreeTransientObject(rsa_keypair);
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	IMSG("Goodbye!\n");
}

static TEE_Result generate_rsa_key_pair(void) {
    TEE_Result res;

    // RSA 키 객체 생성
    res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, 2048, &rsa_keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate RSA keypair: 0x%x", res);
        return res;
    }

    // RSA 키 생성
    res = TEE_GenerateKey(rsa_keypair, 2048, NULL, 0);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to generate RSA key: 0x%x", res);
        TEE_FreeTransientObject(rsa_keypair);
        return res;
    }

    DMSG("RSA key pair generated successfully.");
    return TEE_SUCCESS;
}

static TEE_Result rsa_encrypt(uint32_t param_types, TEE_Param params[4]) {
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *plaintext = (char *)params[0].memref.buffer;  // 평문 입력
    size_t plaintext_len = params[0].memref.size;
    char *ciphertext = (char *)params[1].memref.buffer; // 암호문 출력
    size_t ciphertext_len = params[1].memref.size;

    TEE_Result res;
    TEE_OperationHandle operation = NULL;
    // RSA 키 페어 생성
    res = generate_rsa_key_pair();
    if (res != TEE_SUCCESS) {
        return res;
    }

    // RSA Operation 생성
    res = TEE_AllocateOperation(&operation, TEE_ALG_RSAES_PKCS1_V1_5, TEE_MODE_ENCRYPT, 2048);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to allocate operation: 0x%x", res);
        return res;
    }

    // 키 설정
    res = TEE_SetOperationKey(operation, rsa_keypair);
    if (res != TEE_SUCCESS) {
        EMSG("Failed to set key: 0x%x", res);
        TEE_FreeOperation(operation);
        return res;
    }

    uint32_t cipher_len_32 = (uint32_t)ciphertext_len;

    // RSA 암호화 수행
    res = TEE_AsymmetricEncrypt(operation, NULL, 0,
                                plaintext, plaintext_len,
                                ciphertext, &cipher_len_32);
    if (res != TEE_SUCCESS) {
        EMSG("RSA encryption failed: 0x%x", res);
        TEE_FreeOperation(operation);
        return res;
    }
    // 암호문 크기 갱신
    params[1].memref.size = (size_t)cipher_len_32;

    DMSG("Encryption successful. Ciphertext size: %zu", params[1].memref.size);

    // Operation 해제
    TEE_FreeOperation(operation);
    return TEE_SUCCESS;
}

static void generate_random_key(uint8_t *keyBuffer) {
    uint8_t randomValue;

    // 랜덤 값 생성
    TEE_GenerateRandom(&randomValue, sizeof(randomValue));

    // 키를 1~25 범위로 조정
    *keyBuffer = (randomValue % 25) + 1;
    
}

static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4]) {
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *plaintext = (char *)params[0].memref.buffer;  // 평문 입력
    size_t plaintext_len = params[0].memref.size;
    char *ciphertext = (char *)params[1].memref.buffer; // 암호문 출력
    size_t ciphertext_len = params[1].memref.size;

    uint8_t *enc_key = (uint8_t *)params[2].memref.buffer; // 암호화된 랜덤 키 출력
    size_t enc_key_len = params[2].memref.size;

    // 랜덤 키 생성
    generate_random_key(&key);

    params[2].memref.size = sizeof(uint8_t);

    // 평문 암호화
    for (size_t i = 0; i < plaintext_len; i++) {
        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            ciphertext[i] = 'a' + ((plaintext[i] - 'a' + key) % 26);
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            ciphertext[i] = 'A' + ((plaintext[i] - 'A' + key) % 26);
        } else {
            ciphertext[i] = plaintext[i]; // 기타 문자는 그대로 유지
        }
    }
    params[1].memref.size = plaintext_len;
    // 랜덤 키 암호화
    *enc_key = key + root_key;
    return TEE_SUCCESS;
}

// 복호화 함수
static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4]) {
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_VALUE_INPUT,
                                       TEE_PARAM_TYPE_NONE)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    char *ciphertext = (char *)params[0].memref.buffer;  // 암호문 입력
    size_t ciphertext_len = params[0].memref.size;
    char *plaintext = (char *)params[1].memref.buffer;   // 복호화된 평문 출력
    size_t plaintext_len = params[1].memref.size;

    uint8_t enc_key = params[2].value.a; // 암호화된 랜덤 키 입력

    // 암호화된 키를 복호화하여 랜덤 키 복원
    key = enc_key - root_key;

    // 암호문 복호화
    for (size_t i = 0; i < ciphertext_len; i++) {
        if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = 'a' + ((ciphertext[i] - 'a' - key + 26) % 26);
        } else if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = 'A' + ((ciphertext[i] - 'A' - key + 26) % 26);
        } else {
            plaintext[i] = ciphertext[i]; // 기타 문자는 그대로 유지
        }
    }
    params[1].memref.size = ciphertext_len;

    return TEE_SUCCESS;
}




/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);

	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);

	case TA_TEEencrypt_CMD_RSA_ENC:
        	return rsa_encrypt(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
