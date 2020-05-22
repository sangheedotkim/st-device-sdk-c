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

#ifndef _IOT_SECURITY_ERROR_H_
#define _IOT_SECURITY_ERROR_H_

#define IOT_ERROR_SECURITY_INIT                 (IOT_ERROR_SECURITY_BASE - 1)
#define IOT_ERROR_SECURITY_DEINIT               (IOT_ERROR_SECURITY_BASE - 2)
#define IOT_ERROR_SECURITY_CONTEXT_NULL         (IOT_ERROR_SECURITY_BASE - 3)
#define IOT_ERROR_SECURITY_BE_CONTEXT_NULL      (IOT_ERROR_SECURITY_BASE - 4)
#define IOT_ERROR_SECURITY_BE_FUNC_NULL         (IOT_ERROR_SECURITY_BASE - 5)
#define IOT_ERROR_SECURITY_BE_FUNCS_ENTRY_NULL  (IOT_ERROR_SECURITY_BASE - 6)
#define IOT_ERROR_SECURITY_BE_EXTERNAL_NULL     (IOT_ERROR_SECURITY_BASE - 7)
#define IOT_ERROR_SECURITY_PK_INIT              (IOT_ERROR_SECURITY_BASE - 20)
#define IOT_ERROR_SECURITY_PK_DEINIT            (IOT_ERROR_SECURITY_BASE - 21)
#define IOT_ERROR_SECURITY_PK_SIGN              (IOT_ERROR_SECURITY_BASE - 22)
#define IOT_ERROR_SECURITY_PK_VERIFY            (IOT_ERROR_SECURITY_BASE - 23)
#define IOT_ERROR_SECURITY_PK_PARSEKEY          (IOT_ERROR_SECURITY_BASE - 24)
#define IOT_ERROR_SECURITY_PK_KEY_LEN           (IOT_ERROR_SECURITY_BASE - 25)
#define IOT_ERROR_SECURITY_PK_KEY_TYPE          (IOT_ERROR_SECURITY_BASE - 26)
#define IOT_ERROR_SECURITY_PK_PARAMS_NULL       (IOT_ERROR_SECURITY_BASE - 27)
#define IOT_ERROR_SECURITY_PK_INVALID_PUBKEY    (IOT_ERROR_SECURITY_BASE - 28)
#define IOT_ERROR_SECURITY_PK_INVALID_SECKEY    (IOT_ERROR_SECURITY_BASE - 29)
#define IOT_ERROR_SECURITY_CIPHER_INIT          (IOT_ERROR_SECURITY_BASE - 40)
#define IOT_ERROR_SECURITY_CIPHER_DEINIT        (IOT_ERROR_SECURITY_BASE - 41)
#define IOT_ERROR_SECURITY_CIPHER_AES_ENCRYPT   (IOT_ERROR_SECURITY_BASE - 42)
#define IOT_ERROR_SECURITY_CIPHER_AES_DECRYPT   (IOT_ERROR_SECURITY_BASE - 43)
#define IOT_ERROR_SECURITY_CIPHER_SET_PARAMS    (IOT_ERROR_SECURITY_BASE - 44)
#define IOT_ERROR_SECURITY_CIPHER_PARAMS_NULL   (IOT_ERROR_SECURITY_BASE - 45)
#define IOT_ERROR_SECURITY_CIPHER_INVALID_MODE  (IOT_ERROR_SECURITY_BASE - 46)
#define IOT_ERROR_SECURITY_CIPHER_INVALID_ALGO  (IOT_ERROR_SECURITY_BASE - 47)
#define IOT_ERROR_SECURITY_CIPHER_INVALID_KEY   (IOT_ERROR_SECURITY_BASE - 48)
#define IOT_ERROR_SECURITY_CIPHER_INVALID_IV    (IOT_ERROR_SECURITY_BASE - 49)
#define IOT_ERROR_SECURITY_CIPHER_KEY_LEN       (IOT_ERROR_SECURITY_BASE - 50)
#define IOT_ERROR_SECURITY_CIPHER_IV_LEN        (IOT_ERROR_SECURITY_BASE - 51)
#define IOT_ERROR_SECURITY_CIPHER_BUF_OVERFLOW  (IOT_ERROR_SECURITY_BASE - 52)
#define IOT_ERROR_SECURITY_CIPHER_LIBRARY       (IOT_ERROR_SECURITY_BASE - 53)
#define IOT_ERROR_SECURITY_ECDH_INIT            (IOT_ERROR_SECURITY_BASE - 60)
#define IOT_ERROR_SECURITY_ECDH_DEINIT          (IOT_ERROR_SECURITY_BASE - 61)
#define IOT_ERROR_SECURITY_ECDH_SET_PARAMS      (IOT_ERROR_SECURITY_BASE - 62)
#define IOT_ERROR_SECURITY_ECDH_SHARED_SECRET   (IOT_ERROR_SECURITY_BASE - 63)
#define IOT_ERROR_SECURITY_ECDH_PARAMS_NULL     (IOT_ERROR_SECURITY_BASE - 64)
#define IOT_ERROR_SECURITY_ECDH_LIBRARY         (IOT_ERROR_SECURITY_BASE - 65)
#define IOT_ERROR_SECURITY_ECDH_INVALID_PUBKEY  (IOT_ERROR_SECURITY_BASE - 66)
#define IOT_ERROR_SECURITY_ECDH_INVALID_SECKEY  (IOT_ERROR_SECURITY_BASE - 67)
#define IOT_ERROR_SECURITY_KEY_INVALID_ID       (IOT_ERROR_SECURITY_BASE - 80)
#define IOT_ERROR_SECURITY_KEY_CONVERT          (IOT_ERROR_SECURITY_BASE - 81)
#define IOT_ERROR_SECURITY_KEY_NO_PERMISSION    (IOT_ERROR_SECURITY_BASE - 82)
#define IOT_ERROR_SECURITY_KEY_NOT_FOUND        (IOT_ERROR_SECURITY_BASE - 83)
#define IOT_ERROR_SECURITY_MANAGER_INIT         (IOT_ERROR_SECURITY_BASE - 100)
#define IOT_ERROR_SECURITY_MANAGER_DEINIT       (IOT_ERROR_SECURITY_BASE - 101)
#define IOT_ERROR_SECURITY_MANAGER_KEY_GET      (IOT_ERROR_SECURITY_BASE - 102)
#define IOT_ERROR_SECURITY_MANAGER_KEY_SET      (IOT_ERROR_SECURITY_BASE - 103)
#define IOT_ERROR_SECURITY_MANAGER_CERT_GET     (IOT_ERROR_SECURITY_BASE - 104)
#define IOT_ERROR_SECURITY_MANAGER_CERT_SET     (IOT_ERROR_SECURITY_BASE - 105)
#define IOT_ERROR_SECURITY_MANAGER_SN_GET       (IOT_ERROR_SECURITY_BASE - 107)
#define IOT_ERROR_SECURITY_CERT_INVALID_ID      (IOT_ERROR_SECURITY_BASE - 110)
#define IOT_ERROR_SECURITY_STORAGE_INIT         (IOT_ERROR_SECURITY_BASE - 120)
#define IOT_ERROR_SECURITY_STORAGE_DEINIT       (IOT_ERROR_SECURITY_BASE - 121)
#define IOT_ERROR_SECURITY_STORAGE_READ         (IOT_ERROR_SECURITY_BASE - 122)
#define IOT_ERROR_SECURITY_STORAGE_WRITE        (IOT_ERROR_SECURITY_BASE - 123)
#define IOT_ERROR_SECURITY_STORAGE_REMOVE       (IOT_ERROR_SECURITY_BASE - 124)
#define IOT_ERROR_SECURITY_STORAGE_PARAMS_NULL  (IOT_ERROR_SECURITY_BASE - 125)
#define IOT_ERROR_SECURITY_STORAGE_INVALID_ID   (IOT_ERROR_SECURITY_BASE - 126)
#define IOT_ERROR_SECURITY_FS_OPEN              (IOT_ERROR_SECURITY_BASE - 200)
#define IOT_ERROR_SECURITY_FS_READ              (IOT_ERROR_SECURITY_BASE - 201)
#define IOT_ERROR_SECURITY_FS_WRITE             (IOT_ERROR_SECURITY_BASE - 202)
#define IOT_ERROR_SECURITY_FS_CLOSE             (IOT_ERROR_SECURITY_BASE - 203)
#define IOT_ERROR_SECURITY_FS_REMOVE            (IOT_ERROR_SECURITY_BASE - 204)
#define IOT_ERROR_SECURITY_FS_BUFFER            (IOT_ERROR_SECURITY_BASE - 205)
#define IOT_ERROR_SECURITY_FS_ENCRYPT           (IOT_ERROR_SECURITY_BASE - 206)
#define IOT_ERROR_SECURITY_FS_DECRYPT           (IOT_ERROR_SECURITY_BASE - 207)
#define IOT_ERROR_SECURITY_FS_NOT_FOUND         (IOT_ERROR_SECURITY_BASE - 208)
#define IOT_ERROR_SECURITY_FS_INVALID_ARGS      (IOT_ERROR_SECURITY_BASE - 209)
#define IOT_ERROR_SECURITY_FS_INVALID_TARGET    (IOT_ERROR_SECURITY_BASE - 210)
#define IOT_ERROR_SECURITY_FS_UNKNOWN_TARGET    (IOT_ERROR_SECURITY_BASE - 211)
#define IOT_ERROR_SECURITY_BSP_FN_LOAD_NULL     (IOT_ERROR_SECURITY_BASE - 220)
#define IOT_ERROR_SECURITY_BSP_FN_STORE_NULL    (IOT_ERROR_SECURITY_BASE - 221)
#define IOT_ERROR_SECURITY_BSP_FN_REMOVE_NULL   (IOT_ERROR_SECURITY_BASE - 222)
#define IOT_ERROR_SECURITY_SHA256               (IOT_ERROR_SECURITY_BASE - 400)
#define IOT_ERROR_SECURITY_BASE64_ENCODE        (IOT_ERROR_SECURITY_BASE - 401)
#define IOT_ERROR_SECURITY_BASE64_DECODE        (IOT_ERROR_SECURITY_BASE - 402)
#define IOT_ERROR_SECURITY_BASE64_URL_ENCODE    (IOT_ERROR_SECURITY_BASE - 403)
#define IOT_ERROR_SECURITY_BASE64_URL_DECODE    (IOT_ERROR_SECURITY_BASE - 404)


#endif /* _IOT_SECURITY_ERROR_H_ */
