// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>

#define UUID_SIZE 0x10
#define SIGNATURE_SIZE 0x40
#define DIGEST_SIZE 0x20

#define CBOR_UINT_TYPE uint64_t

// #define MFST_CBOR_ENCODING
// #define MFST_STRUCTURAL_VALIDATION
#define MFST_STRUCT_EXTRACT

#ifdef MFST_STRUCT_EXTRACT
#define URI_MAX 0x100

struct mfst_s {
    const uint8_t signature[SIGNATURE_SIZE];
    CBOR_UINT_TYPE sequence_number;
    const uint8_t vendor_id[UUID_SIZE];
    const uint8_t class_id[UUID_SIZE];
    const uint8_t uri[URI_MAX];
    CBOR_UINT_TYPE payload_size;
    const uint8_t payload_digest[DIGEST_SIZE];
};
#endif

/**
 * @brief Consume an initialized signature verification context, update it with
 * COSE fragments to verify.
 *
 * @details This pushes the COSE signature verification content into the
 * signature verification algorithm. An algorithm that supports partial updates
 * is required in order to reduce memory footprint.
 *
 * @param[in,out] mfst A pointer to the manifest pointer. This pointer must be
 *                     updateable because other suit_minimal calls depend on its
 *                     being updated.
 * @param[out]    signature A pointer to update with the address of the
                  signature.
 * @param[in]     context The signature verification context
 * @param[in]     update_sig_ctx A pointer to a function that updates the
 *                               signature vexification context
 * @return 0 on success or non-zero on failure
 */
int suit_minimal_cose_signature_init(
    const uint8_t** mfst,
    const uint8_t** signature,
    void* context,
    int (*update_sig_ctx)(void*, const uint8_t*, size_t));

/**
 * @brief Extract the sequence number, the vendor ID, and class ID.
 *
 * @param[in,out] mfst A pointer to the manifest pointer. This pointer must be
 *                     updateable because other suit_minimal calls depend on its
 *                     being updated.
 * @param[out]     currentSeq the current sequence number
 * @param[out]     vid the device vendor ID
 * @param[out]     cid the device class ID
 * @return 0 on success or non-zero on failure
 */
int suit_minimal_get_preinstallation_info(const uint8_t** mfst, CBOR_UINT_TYPE* currenSeq, const uint8_t** vid, const uint8_t** cid);

/**
 * @brief Extract the resource URI
 *
 * @param[in,out] mfst A pointer to the manifest pointer. This pointer must be
 *                     updateable because other suit_minimal calls depend on its
 *                     being updated.
 * @param[out]     uri A pointer to update with the address of the URI
 * @param[out]     uri_len A pointer to update with the length of the URI
 * @return 0 on success or non-zero on failure
 */
int suit_minimal_get_install_info(const uint8_t** mfst, const uint8_t** uri, size_t* uri_len);

/** @brief Extract the payload size and payload digest
 *
 * @param[in,out] mfst A pointer to the manifest pointer. This pointer must be
 *                     updateable because other suit_minimal calls depend on its
 *                     being updated.
 * @param[out]     payload_size A pointer to update with the size of the payload
 * @param[out]     payload_digest A pointer to update with the payload digest
 * @return 0 on success or non-zero on failure
 */
int suit_minimal_get_payload_info(const uint8_t** mfst, size_t* payload_size, const uint8_t** payload_digest);
