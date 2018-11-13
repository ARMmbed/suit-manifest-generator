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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int suit_minimal_cose_signature_init(
    const uint8_t** mfst,
    const uint8_t** signature,
    void* context,
    int (*update_sig_ctx)(void*, const uint8_t*, size_t))
{
    struct mfst_s *p_mfst = (struct mfst_s *)(*mfst);
    *signature = p_mfst->signature;
    int rc = update_sig_ctx(context, *mfst + SIGNATURE_SIZE, sizeof(struct mfst_s) - SIGNATURE_SIZE);
    if(rc) return rc;
    return 0;
}

int suit_minimal_get_preinstallation_info(const uint8_t** mfst, CBOR_UINT_TYPE* sequence_number, const uint8_t** vid, const uint8_t** cid) {
    struct mfst_s *p_mfst = (struct mfst_s *)(*mfst);
    // Assuming correct byte order, bit order.
    memcpy(sequence_number, &p_mfst->sequence_number, sizeof(CBOR_UINT_TYPE));
    *vid = p_mfst->vendor_id;
    *cid = p_mfst->class_id;
    return 0;
}

int suit_minimal_get_install_info(const uint8_t** mfst, const uint8_t** uri, size_t* uri_len) {
    struct mfst_s *p_mfst = (struct mfst_s *)(*mfst);
    *uri = p_mfst->uri;
    *uri_len = 0;
    return 0;
}

int suit_minimal_get_payload_info(const uint8_t** mfst, size_t* payload_size, const uint8_t** payload_digest) {
    struct mfst_s *p_mfst = (struct mfst_s *)(*mfst);
    // Assuming correct byte order, bit order.
    memcpy(payload_size, &p_mfst->payload_size, sizeof(CBOR_UINT_TYPE));
    *payload_digest = p_mfst->payload_digest;
    return 0;
}
