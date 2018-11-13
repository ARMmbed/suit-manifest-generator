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

#include "min-parse.h"

#ifdef MFST_CBOR_ENCODING

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// A2                                      # Outer Wrapper
//    01                                   # authentication-wrapper-key
//    D2                                   # COSE_Sign1_Tagged(tag(18))
//       84                                # COSE_Sign1
//          46                             # Protected: map-serialized
//             A2012603182A                # Algorithm ID: ES256, Content Type: Octet-stream
//          A0                             # Unprotected: map(0)
//          F6                             # payload: primitive(22)/nil
//          58 40                          # signature: bytes(64)
static const uint8_t wrapper_to_signature[] = {
    0xa2, 0x01, 0xd2, 0x84, 0x46, 0xa2, 0x01, 0x26, 0x03, 0x18, 0x2a, 0xa0,
    0xf6, 0x58, 0x40
};
//             Signature
static const uint8_t cbor_null_buf[] = {0xF6};


static const size_t protected_offset = 4;
static const size_t signature_offset = sizeof(wrapper_to_signature);
static const size_t manifest_offset = sizeof(wrapper_to_signature) + SIGNATURE_SIZE + 1;
// 02                                      # manifest-key: unsigned(2)
// 5?                                      # serialized-manifest: bytes(??)

// Remainder of encoding is internal to serialized manifest
// A6                                      # manifest: map(6)
//    01                                   # manifest-version-key: unsigned(1)
//    01                                   # manifest-version: unsigned(1)
//    02                                   # manifest-sequence-number-key: unsigned(2)
static const uint8_t manifest_to_seq[] = {
    0xa6, 0x01, 0x01, 0x02, 0x03,

};

//    03                                   # preinstallation-info-key: unsigned(3)
//    A1                                   # preinstallation-info: map(1)
//       01                                # precondition-key: unsigned(1)
//       82                                # preconditions: array(2)
//          82                             # condition: array(2)
//             01                          # vendor ID: unsigned(1)
//             50                          # bytes(16)
static const uint8_t preinstall_prefix[] = { 0x03, 0xa1, 0x01, 0x82, 0x82, 0x01, 0x50 };
//                Vendor ID

//          82                             # array(2)
//             02                          # unsigned(2)
//             50                          # bytes(16)
static const uint8_t classid_prefix[] = { 0x82, 0x02, 0x50 };
//                Class ID

//    05                                   # install-key: unsigned(5)
//    A1                                   # install: map(1)
//       01                                # install-info-list-key: unsigned(1)
//       81                                # install-info-list: array(1)
//          A2                             # install-info: map(2)
//             01                          # component-id-key: unsigned(1)
//             80                          # component-id: array(0)
//             02                          # processors-key: unsigned(2)
//             81                          # processors: array(1)
//                A2                       # processor: map(2)
//                   01                    # processor-id-key: unsigned(1)
//                   82                    # processor-id: array(2)
//                      01                 # processor-id-resource: unsigned(1)
//                      01                 # processor-id-resource-remote: unsigned(1)
//                   03                    # processor-inputs-key: unsigned(3)
//                   81                    # processor-inputs-ranked-uris: array(1)
//                      82                 # processor-inputs-ranked-uri: array(2)
//                         00              # uri-rank: unsigned(0)
static const uint8_t install_prefix[] = {
    0x05, 0xA1, 0x01, 0x81, 0xA2, 0x01, 0x80, 0x02, 0x81, 0xA2, 0x01, 0x82,
    0x01, 0x01, 0x03, 0x81, 0x82, 0x00 };
//                         URI             # uri: str(??)

//    06                                   # payloads-key: unsigned(5)
//    81                                   # payloads: array(1)
//       A3                                # payload-info: map(3)
//          01                             # component-key: unsigned(1)
//          80                             # ComponentID: array(0)
//          02                             # payload-size-key
static const uint8_t payload_prefix[] = { 0x06, 0x81, 0xA3, 0x01, 0x80, 0x02 };
//          0?/1?                          # payload-size: unsigned(??)

//      03                             # unsigned(3)
//      84                             # array(4)
//         44                          # bytes(4)
//            A1011829                 # "\xA1\x01\x18)"
//         A0                          # map(0)
//         F6                          # primitive(22)
//         58 20                       # bytes(32)

static const uint8_t payload_digest_prefix[] = {
    0x03, 0x84, 0x44, 0xA1, 0x01, 0x18, 0x29, 0xA0, 0xF6, 0x58, 0x20
};
//            Payload Digest


static CBOR_UINT_TYPE cbor_get_as_uint(const uint8_t **p) {
    uint8_t iv = **p & 0x1F;
    CBOR_UINT_TYPE val = 0;
    if ( iv <= 23) {
        return iv;
    }
    (*p)++;
    for (iv = 1 << (iv - 24); iv > 0; iv --) {
        val = (val << 8) + **p;
        (*p)++;
    }
    return val;
}

int suit_minimal_cose_signature_init(
    const uint8_t** mfst,
    const uint8_t** signature,
    void* context,
    int (*update_sig_ctx)(void*, const uint8_t*, size_t))
{
    int rc = 0;
#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(*mfst, wrapper_to_signature, sizeof(wrapper_to_signature));
    if (rc) return rc;
#endif

    //    02                                   # manifest-key
#ifdef MFST_STRUCTURAL_VALIDATION
    rc = (0x02 != (*mfst)[manifest_offset - 1]);
    if (rc) return rc;
#endif

    // Store the signature pointer
    *signature = *mfst + signature_offset;

    const uint8_t* p = *mfst + manifest_offset;
    // Load manifest bytes:
    uint16_t mfstSize = cbor_get_as_uint(&p);

    // Add COSE Sig_structure array and context
    const uint8_t Sig_structure_begin[] = {0x84, 0x69, 'S', 'i', 'g', 'n', 'a', 't', 'u', 'r', 'e', '1'};
    rc = update_sig_ctx(context, Sig_structure_begin, sizeof(Sig_structure_begin));
    if(rc) return rc;
    // Add protected headers
    rc = update_sig_ctx(context, *mfst + protected_offset, 7);
    if(rc) return rc;
    // Add External AAD
    rc = update_sig_ctx(context, cbor_null_buf, 1);
    if(rc) return rc;
    // Add payload
    rc = update_sig_ctx(context, *mfst + manifest_offset, mfstSize + p - (*mfst + manifest_offset));
    if (rc) return rc;
    *mfst = p;
    return rc;
}

int suit_minimal_get_preinstallation_info(const uint8_t** mfst, CBOR_UINT_TYPE* sequence_number, const uint8_t** vid, const uint8_t** cid) {
    int rc = 0;
    const uint8_t* p = *mfst;
#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(manifest_to_seq, p, sizeof(manifest_to_seq));
    if (rc) return 1;
#endif

    p += sizeof(manifest_to_seq);

    // Get sequence number:
    *sequence_number = cbor_get_as_uint(&p);

#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(preinstall_prefix, p, sizeof(preinstall_prefix));
    if (rc) return 2;
#endif
    p += sizeof(preinstall_prefix);
    // Store Vendor ID
    *vid = p;
    p += UUID_SIZE;

#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(classid_prefix, p, sizeof(classid_prefix));
    if (rc) return 3;
#endif
    p += sizeof(classid_prefix);
    // Store Class ID
    *cid = p;
    p += UUID_SIZE;

    *mfst = p;
    return rc;
}

int suit_minimal_get_install_info(const uint8_t** mfst, const uint8_t** uri, size_t* uri_len) {
    int rc = 0;
    const uint8_t* p = *mfst;
#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(install_prefix, p, sizeof(install_prefix));
    if (rc) return 1;
#endif
    p += sizeof(install_prefix);
    // Get URI
    *uri_len = cbor_get_as_uint(&p);
    *uri = p;
    p += *uri_len;
    *mfst = p;
    return rc;
}

int suit_minimal_get_payload_info(const uint8_t** mfst, size_t* payload_size, const uint8_t** payload_digest) {
    int rc = 0;
    const uint8_t* p = *mfst;

#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(payload_prefix, p, sizeof(payload_prefix));
    if (rc) return 1;
#endif

    p += sizeof(payload_prefix);
    *payload_size = cbor_get_as_uint(&p);

#ifdef MFST_STRUCTURAL_VALIDATION
    rc = memcmp(payload_digest_prefix, p, sizeof(payload_digest_prefix));
    if (rc) return 2;
#endif
    p += sizeof(payload_digest_prefix);
    *payload_digest = p;
    p += DIGEST_SIZE;

    *mfst = p;
    return rc;
}

#endif // MFST_CBOR_ENCODING
