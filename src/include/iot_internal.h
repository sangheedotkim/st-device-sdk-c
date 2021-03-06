/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifndef _IOT_INTERNAL_H_
#define _IOT_INTERNAL_H_

#include "iot_capability.h"
#include "iot_crypto.h"

#define IOT_TASK_NAME "iot-task"
#define IOT_TASK_STACK_SIZE (1024*5)
#define IOT_TASK_PRIORITY (4)
#define IOT_QUEUE_LENGTH (10)
#define IOT_PUB_QUEUE_LENGTH (10)

#define IOT_TOPIC_SIZE (100)
#define IOT_PAYLOAD_SIZE (1024)

#define IOT_PUB_TOPIC_REGISTRATION	"/v1/registrations"
#define IOT_SUB_TOPIC_REGISTRATION	"/v1/registrations/notification/%s"

#define IOT_PUB_TOPIC_EVENT			"/v1/deviceEvents/%s"
#define IOT_SUB_TOPIC_COMMAND		"/v1/commands/%s"
#define IOT_SUB_TOPIC_NOTIFICATION	"/v1/notifications/%s"

/* MQTT Pre-defined constant */
#define IOT_DEFAULT_TIMEOUT 		12000	/* milli-seconds */
#define IOT_MQTT_KEEPALIVE_INTERVAL	120		/* seconds */

/* Core */
/**
 * @brief	send command to iot main task
 * @details	this function sends specific command to iot-task via queue
 * @param[in]	ctx					iot-core context
 * @param[in]	cmd_type			actual specific command type
 * @param[in]	param				additional parameter data for each command
 * @param[in]	param_size			additional parameter size
 * @retval	IOT_ERROR_NONE			success.
 * @retval	IOT_ERROR_MEM_ALLOC		memory allocation failed
 * @retval	IOT_ERROR_BAD_REQ		queue send error
 */
iot_error_t iot_command_send(struct iot_context *ctx,
	enum iot_command_type cmd_type, const void *param, int param_size);

/**
 * @brief	update iot state
 * @details	this function tries to update iot-state using iot_command_send internally
 * @param[in]	ctx					iot-core context
 * @param[in]	new_state			new iot-state to update
 * @param[in]	need_interact			additional parameter data for each command
 * @retval	IOT_ERROR_NONE			success.
 * @retval	IOT_ERROR_MEM_ALLOC		memory allocation failed
 * @retval	IOT_ERROR_BAD_REQ		queue send error
 */
iot_error_t iot_state_update(struct iot_context *ctx,
	iot_state_t new_state, int need_interact);

/**
 * @brief	send easysetup cgi payload manipulation request
 * @details	easysetup cgi payload manipulation should be done at iot-task. This function sends payload to iot-task via queue
 * @param[in]	ctx				iot-core context
 * @param[in]	step			indicates which uri(command) is dealing with
 * @param[in]	payload			payload data - mostly json data
 * @retval	IOT_ERROR_NONE		success.
 * @retval	IOT_ERROR_BAD_REQ	queue send error
 */
iot_error_t iot_easysetup_request(struct iot_context *ctx,
	enum iot_easysetup_step step, const void *payload);

/**
 * @brief	load "onboarding_config.json" from application source directory
 * @details	"onboarding_config.json" can be downloaded from SmartThings Developer Workspace <br>
 * 		This function parses downloaded "onboarding_config.json" to be used for EasySetup
 * @param[in]	onboarding_config		start pointer of json data
 * @param[in]	onboarding_config_len	json data length
 * @param[out]	devconf		"onboarding_config.json" will be parsed and mapped to this internal structure
 * @retval	IOT_ERROR_NONE                      success.
 * @retval	IOT_ERROR_UNINITIALIZED             invalid json value.
 * @retval	IOT_ERROR_MEM_ALLOC                 memory allocation failure.
 * @retval	IOT_ERROR_CRYPTO_SHA256             sha256 error.
 * @retval	IOT_ERROR_CRYPTO_BASE64             base64 error.
 * @retval	IOT_ERROR_CRYPTO_BASE64_URLSAFE     base64 urlsafe error.
 * @par example
 * @code
 {
    "onboardingConfig": {
        "deviceOnboardingID": "NAME", // max. 13 character. this will be prefix of soft-ap ssid.
        "mnId": "MNID", // mnId for developer and/or manufacturer. "MNID" shouldn't be used.
        "setupId": "999", // 3-digit Device onboarding ID for this device.
        "vid": "VID", // VID(Vendor ID) for this profile.
        "deviceTypeId": "TYPE", // Device type which is selected from Developer Workspace.
        "ownershipValidationType": [ "JUSTWORKS", "BUTTON", "PIN", "QR" ],
            // "JUSTWORKS" for confirming without user interaction.
            // "BUTTON" for confirming by pressing builtin button.
            // "PIN" for confirming by matching 8-digit number PIN
            // "QR" for confirming by scanning a QR code by SmartThings app.
        "identityType": "ED25519 or CERTIFICATE" // ED25519 or X.509 CERTIFICATE
     }
 }
 * @endcode
 */
iot_error_t iot_api_onboarding_config_load(unsigned char *onboarding_config,
		unsigned int onboarding_config_len, struct iot_devconf_prov_data *devconf);

/**
 * @brief	load "device_info.json" from application source directory
 * @details	"device_info.json" should be updated by application developer <br>
 * 		This function parses downloaded "device_info.json" to be used for EasySetup<br>
 * 		Only firmwareVersion will be parsed by this api. others are handled by another api
 *
 * @param[in]	device_info			start pointer of json data
 * @param[in]	device_info_len		json data length
 * @param[out]	info		"device_info.json" will be parsed and mapped to this internal structure
 * @retval	IOT_ERROR_NONE              success.
 * @retval	IOT_ERROR_UNINITIALIZED     invalid json value.
 * @retval	IOT_ERROR_MEM_ALLOC         memory allocation failure.
 * @par example
 * @code
{
	"deviceInfo": {
		"firmwareVersion": "FwVer0011A",
    ...
	}
}
 * @endcode
 */
iot_error_t iot_api_device_info_load(unsigned char *device_info,
		unsigned int device_info_len, struct iot_device_info *info);

/**
 * @brief	free onboarding config memory
 * @details	this function frees the loaded onboarding configuration
 * @param[in]	devconf		loaded onboarding configuration
 */
void iot_api_onboarding_config_mem_free(struct iot_devconf_prov_data *devconf);

/**
 * @brief	free device info memory
 * @details	this function frees the loaded device's information
 * @param[in]	info		loaded device's information
 */
void iot_api_device_info_mem_free(struct iot_device_info *info);

/**
 * @brief	free prov data memory
 * @details	this function frees the loaded provisioning data
 * @param[in]	prov		loaded provisioning data
 */
void iot_api_prov_data_mem_free(struct iot_device_prov_data *prov);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
/**
 * @brief	Extract required data from "device_info.json" which is located in application source directory
 * @details	"device_info.json" should be updated by application developer <br>
 * 		This function parses downloaded "device_info.json" to be used for EasySetup
 * @param[in]	device_nv_info		starting pointer of json data
 * @param[in]	device_nv_info_len	json data length
 * @param[in]	object				object name for searching json data.
 * @param[out]	nv_data		"device_info.json" will be parsed by "object" and mapped to this pointer
 * @retval	IOT_ERROR_NONE              success.
 * @retval	IOT_ERROR_UNINITIALIZED     invalid json value.
 * @retval	IOT_ERROR_MEM_ALLOC         memory allocation failure.
 * @par example
 * @code
   {
	"nvProfile": {
		"privateKey": "privateKey", // Client (= Device) Private key
		"publicKey": "publicKey", // Client (= Device) Public key
		"serialNumber": "serialNumber" // Device Serial Number
	}
   }
 * @endcode
 */
iot_error_t iot_api_read_device_identity(unsigned char *device_nv_info,
      unsigned int device_nv_info_len, const char *object, char **nv_data);
#endif

/**
 * @brief	device cleanup
 * @details	this function triggers clean-up process. All registered data will be removed
 * @param[in]	ctx	iot-core context
 * @retval	IOT_ERROR_NONE	success.
 */
iot_error_t iot_device_cleanup(struct iot_context *ctx);

/**
 * @brief	easy setup connect
 * @details	this function tries to connect server for registration or communication process
 * @param[in]	ctx		iot-core context
 * @param[in]	conn_type	set connection type. registration or communication with server
 * @retval	IOT_ERROR_NONE	success.
 */
iot_error_t iot_es_connect(struct iot_context *ctx, int conn_type);

/**
 * @brief	easy setup disconnect
 * @details	this function tries to disconnect server for registration or communication process
 * @param[in]	ctx		iot-core context
 * @param[in]	conn_type	set connection type. registration or communication with server
 * @retval	IOT_ERROR_NONE	success.
 */
iot_error_t iot_es_disconnect(struct iot_context *ctx, int conn_type);

/**
 * @brief	initialize the buffer for pubkey information
 * @details	this function uses to initialize
 * @param[in]	pk_info		pubkey information structure to initialize
 * @param[in]	type		pubkey type, RSA or ED25519
 */
void iot_es_crypto_init_pk(iot_crypto_pk_info_t *pk_info, iot_crypto_pk_type_t type);

/**
 * @brief	easy setup crypto to load pubkey
 * @details	this function loads pubkey information
 * @param[in]	pk_info			pubkey information pointer for loading
 * @retval	IOT_ERROR_NONE		success.
 */
iot_error_t iot_es_crypto_load_pk(iot_crypto_pk_info_t *pk_info);

/**
 * @brief	easy setup crypto to free pubkey
 * @details	this function frees the loaded pubkey information
 * @param[in]	pk_info		loaded pubkey information pointer
 */
void iot_es_crypto_free_pk(iot_crypto_pk_info_t *pk_info);

/**
 * @brief	mqtt connect
 * @details	this function connects ST server by mqtt
 * @param[in]	target_cli		mqtt handling context
 * @param[in]	username		username to connect ST server based on mqtt protocol
 * @param[in]	sign_data		specific password that was jwt token-based to connect ST server
 * @retval	IOT_ERROR_NONE		success.
 */
iot_error_t iot_mqtt_connect(struct iot_mqtt_ctx *target_cli,
		char *username, char *sign_data);

/**
 * @brief	pyblish mqtt message
 * @details	this function is used to publish command & notification message
 * @param[in]	ctx			iot-core context
 * @param[in]	payload			raw message sending to server
 * @retval	IOT_ERROR_NONE		success.
 */
iot_error_t iot_mqtt_publish(struct iot_context *ctx, void *payload);

/**
 * @brief	subscribe mqtt topic
 * @details	this function is used to subscribe command & notification topics
 * @param[in]	mqtt_ctx		mqtt handling context
 * @retval	IOT_ERROR_NONE		success.
 */
iot_error_t iot_mqtt_subscribe(struct iot_mqtt_ctx *mqtt_ctx);

/**
 * @brief	unsubscribe mqtt topic
 * @details	this function is used to unsubscribe command & notification topics
 * @param[in]	mqtt_ctx		mqtt handling context
 * @retval	IOT_ERROR_NONE		success.
 */
iot_error_t iot_mqtt_unsubscribe(struct iot_mqtt_ctx *mqtt_ctx);

/**
 * @brief	mqtt disconnect
 * @details	this function is used to disconnect from server
 * @param[in]	target_cli		mqtt handling context
 */
void iot_mqtt_disconnect(struct iot_mqtt_ctx *target_cli);

/**
 * @brief	register device to ST server
 * @details	this function is used to handle the registration process
 * @param[in]	mqtt_ctx		mqtt handling context
 * @retval	IOT_ERROR_NONE		success.
 */
iot_error_t iot_mqtt_registration(struct iot_mqtt_ctx *mqtt_ctx);

/**
 * @brief	callback for mqtt command msg
 * @details	this function is used to handle command message from server
 * @param[in]	cap_handle_list		allocated capability handle list
 * @param[in]	payload			received raw message from server
 */
void iot_cap_sub_cb(iot_cap_handle_list_t *cap_handle_list, char *payload);

/**
 * @brief	callback for mqtt noti msg
 * @details	this function is used to handle notification message from server
 * @param[in]	ctx		iot-core context
 * @param[in]	payload		received raw message from server
 */
void iot_noti_sub_cb(struct iot_context *ctx, char *payload);

/**
 * @brief	call init callback
 * @details	this function is used to call all allocated capability callbacks when target is connected
 * @param[in]	cap_handle_list		allocated capability handle list
 */
void iot_cap_call_init_cb(iot_cap_handle_list_t *cap_handle_list);

/* For universal purpose */
/**
 * @brief	get time data by sec
 * @details	this function tries to get time value in second by string
 * @param[in]	buf		buffer point to contain second based string value
 * @param[in]	buf_len		size of allocated buffer for string
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_time_in_sec(char *buf, size_t buf_len);

/**
 * @brief	get time data in msec
 * @details	this function tries to get time value in millisecond by string
 * @param[in]	buf		buffer point to contain millisecond based string value
 * @param[in]	buf_len		size of allocated buffer for string
 * @retval	IOT_ERROR_NONE                  success.
 */
iot_error_t iot_get_time_in_ms(char *buf, size_t buf_len);

#endif /* _IOT_INTERNAL_H_ */

