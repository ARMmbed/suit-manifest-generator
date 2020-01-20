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

const uint8_t vendor_id[16] = {
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe
};
const uint8_t class_id[16] = {
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45
};

const uint8_t COSE_Sign1_context[] = "\x84\x6ASignature1";

const uint8_t public_key[] = {
    0x84, 0x96, 0x81, 0x1a, 0xae, 0x0b, 0xaa, 0xab,
    0xd2, 0x61, 0x57, 0x18, 0x9e, 0xec, 0xda, 0x26,
    0xbe, 0xaa, 0x8b, 0xf1, 0x1b, 0x6f, 0x3f, 0xe6,
    0xe2, 0xb5, 0x65, 0x9c, 0x85, 0xdb, 0xc0, 0xad,
    0x3b, 0x1f, 0x2a, 0x4b, 0x6c, 0x09, 0x81, 0x31,
    0xc0, 0xa3, 0x6d, 0xac, 0xd1, 0xd7, 0x8b, 0xd3,
    0x81, 0xdc, 0xdf, 0xb0, 0x9c, 0x05, 0x2d, 0xb3,
    0x39, 0x91, 0xdb, 0x73, 0x38, 0xb4, 0xa8, 0x96,
};


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


    mbedtls_sha256_context ctx;
    uint8_t hash[32];
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts_ret (&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, image, image_size);
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    // no secret information in this hash, so memcmp is fine
    return memcmp(hash, expected_digest, sizeof(hash));

}

int suit_platform_verify_sha256(
    const uint8_t *expected_digest,
    const uint8_t *data,
    size_t data_len)
{
    mbedtls_sha256_context ctx;
    uint8_t hash[32];

    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts_ret (&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, data, data_len);
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);
    if (0==memcmp(hash, expected_digest, sizeof(hash))) {
        return CBOR_ERR_NONE;
    }
    else {
        return SUIT_ERROR_DIGEST_MISMATCH;
    }
}

int do_cose_auth(
    const uint8_t *auth_buffer,
    const uint8_t *data, size_t data_size)
{
    const uint8_t* p = auth_buffer;
    cbor_value_t auth_bstr;
    int rc = cbor_check_type_extract_ref(&p, p + 9, &auth_bstr, CBOR_TYPE_BSTR);
    if (rc) return rc;
    p = auth_bstr.ref.ptr;
    const uint8_t *auth_end = p + auth_bstr.ref.length;
    // The auth container is a list.
    // Only support single authorisation/signature
    // TODO: Multiple authorisations
    if (p[0] != 0x81) {
        RETURN_ERROR(1);
    }
    p += 1;
    // A COSE_Sign1_tagged must begin with 0xD2 0x84
    if (p[0] != 0xD2 || p[1] != 0x84) {
        RETURN_ERROR(1);
    }
    p += 2;
    // COSE_Sign1 = [
    //     protected : bstr .cbor header_map / bstr .size 0,
    //     unprotected : header_map,
    //     payload : bstr / nil,
    //     signature : bstr
    // ]
    cbor_value_t values[4];
    const uint8_t COSE_Sign1_types[] = {
        CBOR_TYPE_BSTR,
        CBOR_TYPE_MAP,
        CBOR_TYPE_BSTR,
        CBOR_TYPE_BSTR
    };
    for (size_t i = 0; i < 4; i++) {
        const uint8_t* cbor_start = p;
        rc = cbor_check_type_extract_ref(&p, auth_end, &values[i], COSE_Sign1_types[i]);
        if (rc) return rc;
        if (COSE_Sign1_types[i] == CBOR_TYPE_BSTR) {
            p = values[i].ref.ptr + values[i].ref.length;
        } else {
            p = cbor_start;
            rc = cbor_skip(&p, auth_end);
            if(rc) return rc;
        }
    }
    // Check that body_protected is recognised
    if (values[0].ref.length != 3) {
        RETURN_ERROR(2);
    }
    if (memcmp(values[0].ref.ptr, "\xA1\x01\x26", 3) != 0) {
        RETURN_ERROR(3);
    }
    // Digest the signed object:
    //    Sig_structure = [
    //        context : "Signature"                      ; Const
    //        body_protected : empty_or_serialized_map,  ; Included in auth buffer
    //        external_aad : bstr,                       ; NULL
    //        payload : bstr                             ; Included in manifest
    //    ]
    // body_protected is a digest between 224 and 512 bits
    // There should be an array wrapper (1B) and a type identifier (1B)

    size_t struct_len =
        sizeof(COSE_Sign1_context) - 1 +
        (values[0].ref.length + values[0].ref.ptr - values[0].cbor_start) +
        1 +
        (values[2].ref.length + values[2].ref.ptr - values[2].cbor_start);
    uint8_t bstr_start[1+sizeof(size_t)];

    size_t byte_size = sizeof(size_t) - __builtin_clz(struct_len)/8;
    size_t byte_size_log = sizeof(size_t)*8 - __builtin_clz(byte_size);
    bstr_start[0] = CBOR_TYPE_BSTR + byte_size_log + 23;
    for (size_t n = byte_size; n; n--) {
        bstr_start[byte_size - (n - 1)] = (struct_len >> ((n - 1)<<3));
    }
    mbedtls_sha256_context ctx;
    uint8_t hash[32];
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts_ret (&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, bstr_start, 1 + byte_size);
    mbedtls_sha256_update_ret(&ctx, COSE_Sign1_context, sizeof(COSE_Sign1_context) - 1);
    mbedtls_sha256_update_ret(&ctx, values[0].cbor_start, values[0].ref.length + values[0].ref.ptr - values[0].cbor_start);
    mbedtls_sha256_update_ret(&ctx, (uint8_t *)"\x40", 1);
    mbedtls_sha256_update_ret(&ctx, values[2].cbor_start, (values[2].ref.length + values[2].ref.ptr - values[2].cbor_start));
    mbedtls_sha256_finish_ret(&ctx, hash);
    mbedtls_sha256_free(&ctx);

    rc = uECC_verify(public_key, hash, values[3].ref.ptr);
    if (!rc) {
        return SUIT_ERR_SIG;
    }

    // Verify the manifest

    // Extract the signed digest of the manifest

    rc = verify_suit_digest(
        values[2].ref.ptr,
        values[2].ref.ptr + 1 + 8 + 2, //TODO: Fix length handling
        data,
        data_size);
    if (rc != CBOR_ERR_NONE) {
        rc = SUIT_ERR_SIG;
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
