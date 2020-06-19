// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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

#include "suit_parser.h"
#include "suit_bootloader.h"
#include "mbedtls/sha256.h" /* SHA-256 only */
// #include "mbedtls/md.h"     /* generic interface */
#include "uecc/uECC.h"
#include "mbed_application.h"

#include <stdio.h>
#include <string.h>




size_t bl_slot_index;

int suit_platform_do_run() {
    int rc = -1;
    if (bl_slot_index < n_entrypoints) {
        rc = 0;
        mbed_start_application((uintptr_t)entrypoints[bl_slot_index].app_offset);
    }
    return rc;
}

int suit_platform_get_image_ref(
    const uint8_t *component_id,
    const uint8_t **image
) {
    if (bl_slot_index >= n_entrypoints) {
        return -1;
    }

    *image = (const uint8_t *)((uintptr_t)entrypoints[bl_slot_index].app_offset);
    return 0;
}

void compute_sha256(uint8_t *hash, const uint8_t *msg, size_t msg_len) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts_ret (&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, msg, msg_len);
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);
}

int suit_platform_verify_image(
    const uint8_t *component_id,
    int digest_type,
    const uint8_t* expected_digest,
    size_t image_size
) {
    if (bl_slot_index >= n_entrypoints) {
        return -1;
    }

    const uint8_t *image = (const uint8_t *)((uintptr_t)entrypoints[bl_slot_index].app_offset);
    uint8_t hash[32];
    compute_sha256(hash, image, image_size);
    // no secret information in this hash, so memcmp is fine
    return memcmp(hash, expected_digest, sizeof(hash));

}

int suit_platform_verify_sha256(
    const uint8_t *expected_digest,
    const uint8_t *data,
    size_t data_len)
{
    uint8_t hash[32];

    compute_sha256(hash, data, data_len);
    if (0==memcmp(hash, expected_digest, sizeof(hash))) {
        return CBOR_ERR_NONE;
    }
    else {
        RETURN_ERROR( SUIT_ERROR_DIGEST_MISMATCH);
    }
}


int suit_platform_verify_digest(int alg, const uint8_t *exp, size_t exp_len, const uint8_t *data, size_t data_len)
{
    switch (alg) {
        // TODO: expected digest length.
        case SUIT_DIGEST_TYPE_SHA256:
            return suit_platform_verify_sha256(exp, data, data_len);
    }
    RETURN_ERROR(SUIT_ERROR_DIGEST_MISMATCH);
}

int ES256_verify(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *kid, size_t kid_len)
{
    //TODO: SHA
    uint8_t hash[32] = {0};
    compute_sha256(hash, msg, msg_len);

    //TODO: Lookup public key by key-id
    if (uECC_verify(public_key, hash, sig)) {
        return CBOR_ERR_NONE;
    }
    else {
        RETURN_ERROR(SUIT_ERR_SIG);
    }
}

int COSEAuthVerify(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *kid, size_t kid_len,                
                int alg)
{
    int rc;
    switch (alg) {
        case COSE_ES256:
            rc = ES256_verify(
                msg, msg_len,
                sig, sig_len,
                kid, kid_len);
            break;
        default:
            SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED);
            break;
    }
    return rc;
}

int suit_bootloader() {
    int rc = 1;
    size_t max_seq_idx = 0;
    uint64_t max_seq = -1;
    uint8_t ok = 0;

    while (!ok && max_seq) {
        uint64_t new_max_seq = 0;
        ok = 0;
        for (bl_slot_index = 0; bl_slot_index < n_entrypoints; bl_slot_index++) {
            uint64_t seqnum;
            rc = suit_get_seq(
                (const uint8_t *)entrypoints[bl_slot_index].manifest,
                SUIT_BOOTLOADER_HEADER_SIZE,
                &seqnum);
            if (rc == CBOR_ERR_NONE && seqnum < max_seq && seqnum > new_max_seq) {
                new_max_seq = seqnum;
                max_seq_idx = bl_slot_index;
                ok = 1;
            }
        }
        if (ok) {
            bl_slot_index = max_seq_idx;
            rc = suit_do_process_manifest(
                (const uint8_t *)entrypoints[bl_slot_index].manifest,
                SUIT_BOOTLOADER_HEADER_SIZE);
            if (rc != CBOR_ERR_NONE) {
                ok = 0;
            }
        }
        max_seq = new_max_seq;
    }
    return rc;
}
