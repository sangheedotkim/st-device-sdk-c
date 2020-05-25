/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "security/iot_security_crypto.h"
#include "security/backend/iot_security_be.h"

iot_error_t iot_security_cipher_init(iot_security_context_t *context)
{
	iot_error_t err;
	iot_security_cipher_params_t *cipher_params;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	cipher_params = (iot_security_cipher_params_t *)iot_os_malloc(sizeof(iot_security_cipher_params_t));
	if (!cipher_params) {
		IOT_ERROR("failed to malloc for cipher info");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(cipher_params, 0, sizeof(iot_security_cipher_params_t));

	context->cipher_params = cipher_params;

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->cipher_init) {
		err = context->be_context->fn->cipher_init(context);
		if (err) {
			iot_os_free(context->cipher_params);
			context->cipher_params = NULL;
			return IOT_ERROR_SECURITY_CIPHER_INIT;
		}
	}

	context->sub_system |= IOT_SECURITY_SUB_CIPHER;

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_cipher_deinit(iot_security_context_t *context)
{
	iot_error_t err;

	if (!context) {
		return IOT_ERROR_SECURITY_CONTEXT_NULL;
	}

	if (context->be_context &&
		context->be_context->fn &&
		context->be_context->fn->cipher_deinit) {
		err = context->be_context->fn->cipher_deinit(context);
		if (err) {
			return err;
		}
	}

	if (context->cipher_params) {
		memset(context->cipher_params, 0, sizeof(iot_security_cipher_params_t));
		iot_os_free(context->cipher_params);
		context->cipher_params = NULL;
	}

	context->sub_system &= ~IOT_SECURITY_SUB_CIPHER;

	return IOT_ERROR_NONE;
}

size_t iot_security_cipher_get_align_size(iot_security_key_type_t key_type, size_t data_size)
{
	const mbedtls_cipher_info_t *cipher_info;
	mbedtls_cipher_context_t cipher_ctx;
	mbedtls_cipher_type_t cipher_alg;
	unsigned int block_size;
	int ret;

	IOT_DEBUG("data size = %d, type = %d", (int)data_size, key_type);

	if (key_type == IOT_SECURITY_KEY_TYPE_AES256) {
		cipher_alg = MBEDTLS_CIPHER_AES_256_CBC;
	} else {
		IOT_ERROR("'%d' is not supported cipher algorithm", key_type);
		return 0;
	}

	if (!data_size) {
		IOT_ERROR("input size is zero");
		return 0;
	}

	cipher_info = mbedtls_cipher_info_from_type(cipher_alg);
	if (!cipher_info) {
		IOT_ERROR("mbedtls_cipher_info_from_type returned null");
		return 0;
	}

	mbedtls_cipher_init(&cipher_ctx);

	ret = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
	if (ret) {
		IOT_ERROR("mbedtls_cipher_setup = -0x%04X", -ret);
		mbedtls_cipher_free(&cipher_ctx);
		return 0;
	}

	block_size = mbedtls_cipher_get_block_size(&cipher_ctx);

	data_size = data_size + (block_size - (data_size % block_size));

	mbedtls_cipher_free(&cipher_ctx);

	IOT_DEBUG("align size = %d", (int)data_size);

	return data_size;
}

iot_error_t iot_security_cipher_set_params(iot_security_context_t *context, iot_security_cipher_params_t *cipher_set_params)

{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (!cipher_set_params) {
		IOT_ERROR("cipher set params is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!context->be_context->fn->cipher_set_params) {
		IOT_ERROR("be->fn->cipher_set_params is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->cipher_set_params(context, cipher_set_params);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_cipher_aes_encrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buf is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!output_buf) {
		IOT_ERROR("output buf is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_DEBUG("input = %d@%p", (int)input_buf->len, input_buf->p);

	memset(output_buf, 0, sizeof(iot_security_buffer_t));

	if (!context->be_context->fn->cipher_aes_encrypt) {
		IOT_ERROR("be->fn->cipher_aes_encrypt is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->cipher_aes_encrypt(context, input_buf, output_buf);
	if (err) {
		return err;
	}

	IOT_DEBUG("output = %d@%p", (int)output_buf->len, output_buf->p);

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_cipher_aes_decrypt(iot_security_context_t *context, iot_security_buffer_t *input_buf, iot_security_buffer_t *output_buf)
{
	iot_error_t err;

	err = iot_security_check_backend_funcs_entry_is_valid(context);
	if (err) {
		return err;
	}

	if (!input_buf || !input_buf->p || (input_buf->len == 0)) {
		IOT_ERROR("input buf is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if (!output_buf) {
		IOT_ERROR("output buf is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	IOT_DEBUG("input = %d@%p", (int)input_buf->len, input_buf->p);

	memset(output_buf, 0, sizeof(iot_security_buffer_t));

	if (!context->be_context->fn->cipher_aes_decrypt) {
		IOT_ERROR("be->fn->cipher_aes_decrypt is null");
		return IOT_ERROR_SECURITY_BE_FUNC_NULL;
	}

	err = context->be_context->fn->cipher_aes_decrypt(context, input_buf, output_buf);
	if (err) {
		return err;
	}

	IOT_DEBUG("output = %d@%p", (int)output_buf->len, output_buf->p);

	return IOT_ERROR_NONE;
}