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

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

int key_to_var_index(int key) {
    int rc;
    if (key > 32 || key < 1 ) {
        SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED);
        return -rc;
    }
    key = key-1;
    key = 1 << key;
    if (!(key & SUIT_SUPPORTED_VARS)) {
        SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED);
        return -rc;
    }
    size_t supported = SUIT_SUPPORTED_VARS & ( key-1 );
    size_t idx = 0;
    for (idx = 0; supported; supported >>= 1) {
        idx += supported & 1;
    }
    return idx;
}


int key_to_reference(int key, suit_reference_t **ref, suit_parse_context_t* ctx) {
    //TODO: Check ACL
    if (key > 32 || key < 1 ) {
        RETURN_ERROR(CBOR_ERR_UNIMPLEMENTED);
    }
    key = key-1;
    key = 1 << key;
    if (!(key & SUIT_SUPPORTED_VARS)) {
        RETURN_ERROR(CBOR_ERR_UNIMPLEMENTED);
    }

    size_t supported = SUIT_SUPPORTED_VARS & ( key-1 );
    size_t idx = 0;
    for (idx = 0; supported; supported >>= 1) {
        idx += supported & 1;
    }
    *ref = &ctx->vars[0][idx];
    return CBOR_ERR_NONE;
}

int cbor_get_as_uint64(const uint8_t** p, const uint8_t* end, uint64_t* n){
    if (*p >= end) {
        RETURN_ERROR(CBOR_ERR_OVERRUN);
    }
    uint8_t iv = **p & ~CBOR_TYPE_MASK;
    if (iv >= 28){
        RETURN_ERROR(CBOR_ERR_INTEGER_ENCODING);
    }
    (*p)++;
    if (iv < 24) {
        *n = iv;
    } else {
        const uint8_t* uend = *p + (1 << (iv-24));
        if (uend > end) {
            RETURN_ERROR(CBOR_ERR_OVERRUN);
        }
        for (*n = 0; *p < uend; (*p)++) {
            *n = *n << 8 | **p;
        }
    }
    return CBOR_ERR_NONE;
}
int cbor_get_uint64(const uint8_t** p, const uint8_t* end, uint64_t* n){
    uint8_t type = **p & CBOR_TYPE_MASK;
    if (type != CBOR_TYPE_UINT) {
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
    }
    return cbor_get_as_uint64(p, end, n);
}

int cbor_get_int64(const uint8_t** p, const uint8_t* end, int64_t* n) {
    uint8_t type = **p & CBOR_TYPE_MASK;
    if (type != CBOR_TYPE_NINT && type != CBOR_TYPE_UINT) {
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
    }
    uint64_t uv;
    int rc = cbor_get_as_uint64(p, end, &uv);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    if (type == CBOR_TYPE_NINT) {
        *n = -1 - (int64_t)uv;
    } else {
        *n = uv;
    }
    return rc;
}

int cbor_extract_uint(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val)
{
    return cbor_get_uint64(p, end, &(val->u64));
}
int cbor_extract_int(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val)
{
    return cbor_get_int64(p, end, &(val->i64));
}

int cbor_extract_ref(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val
    )
{
    int rc = cbor_get_as_uint64(p, end, &(val->ref.uival));
    if (rc == CBOR_ERR_NONE) {
        val->ref.ptr = *p;
    }
    return rc;
}

int cbor_extract_primitive(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val)
{
    val->primitive = (**p & (~CBOR_TYPE_MASK));
    (*p)++;
    RETURN_ERROR(CBOR_ERR_NONE);
}

int cbor_check_type_extract_ref(
        const uint8_t **p,
        const uint8_t *end,
        cbor_value_t *o_val,
        const uint8_t cbor_type
) {
    if ((**p & CBOR_TYPE_MASK) != cbor_type) {
        PD_PRINTF("Expected: %u Actual %u\n", (unsigned) cbor_type>>5, (unsigned)(**p & CBOR_TYPE_MASK)>>5);

        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
    }
    o_val->cbor_start = *p;
    return cbor_extract_ref(p, end, o_val);
}

int (*cbor_extractors[])(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val) =
{
    cbor_extract_uint,
    cbor_extract_int,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_primitive
};

int cbor_skip(const uint8_t **p, const uint8_t *end)
{
    uint8_t ct = **p & CBOR_TYPE_MASK;
    size_t handler_index = ct >> 5;
    cbor_value_t val;
    int rc = cbor_extractors[handler_index](p, end, &val);
    if ((*p) > end) {
        SET_ERROR(rc, CBOR_ERR_OVERRUN);
    }
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    switch (ct) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NINT:
            break;
        case CBOR_TYPE_TSTR:
        case CBOR_TYPE_BSTR:
            if ((*p) + val.ref.uival <= end) {
                (*p) += val.ref.uival;
            } else {
                SET_ERROR(rc, CBOR_ERR_OVERRUN);
            }
            break;
        case CBOR_TYPE_MAP:
            val.ref.uival *= 2;
            // no break;
        case CBOR_TYPE_LIST:
            for (size_t count = val.ref.uival; count && rc == CBOR_ERR_NONE; count--) {
                rc = cbor_skip(p, end);
            }
            break;
        case CBOR_TYPE_SIMPLE:
            if (val.primitive == (CBOR_NULL & ~CBOR_TYPE_MASK)) {
                break;
            } else {
                // PD_PRINTF("primitive : %02x\n", val.primitive);
            }
        default:
            // PD_PRINTF("Skip Unimplemented for type %u\n", (unsigned) ct>>5);
            SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED);
    }
    return rc;
}

static int get_handler(
    const uint8_t cbor_b1,
    const uint8_t cbor_sub,
    const cbor_keyed_parse_element_t** h,
    const cbor_keyed_parse_elements_t* handlers,
    const int32_t key
) {
    size_t i;
    // Step 1: find the first key that matches
    int success = 0;
    for (i = 0; i < handlers->count; i++)
    {
        if (handlers->elements[i].key == key) {
            success = 1;
            break;
        }
    }

    if (!success ) {
        PD_PRINTF("Couldn't find a handler for key %d\n", (int) key);
        RETURN_ERROR(CBOR_ERR_KEY_MISMATCH);
    }
    // PD_PRINTF("Key Matched, Matching major %u, sub:%u\n", (unsigned) cbor_b1>>5, (unsigned)cbor_sub >> 5);
    // Step 2: Loop through handlers until a matching handler is found or a key mismatch is found
    // const cbor_keyed_parse_element_t* h;
    for (; i < handlers->count && handlers->elements[i].key == key; i++) {
    // do {
        uint8_t cbor_type = (cbor_b1 & CBOR_TYPE_MASK) >> 5;
        *h = &handlers->elements[i];
        if ((*h)->bstr_wrap) {
            if (cbor_type != CBOR_TYPE_BSTR >> 5) {
                continue;
            }
            cbor_type = cbor_sub & CBOR_TYPE_MASK;
        }
        if ((*h)->type == cbor_type) {
            return CBOR_ERR_NONE;
        }
        if (cbor_type == CBOR_TYPE_UINT >> 5 && (*h)->type == CBOR_TYPE_NINT >> 5)
        {
            return CBOR_ERR_NONE;
        }
        if ((*h)->null_opt && cbor_b1 == CBOR_NULL) {
            return CBOR_ERR_NONE;
        }
    } // while (++i < handlers->count && (*h)->key == key);
    PD_PRINTF("Type Mismatch\n");
    RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
}
static int handle_array(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
);
static int handle_list(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
);
static int handle_pairs(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
);
static int handle_tag(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers
);

/**
 * 
 * Step 1: get the handler.
 * Step 2: Unwrap if bstr-wrapped.
 * Step 3: Invoke the appropriate handler.
 */
static int handle_keyed_element(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    int32_t key
) {
    // TODO: Add pre-call-function?
    PD_PRINTF("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), key);

    cbor_value_t val;
    val.cbor_start =  *p;

    // Perform the extract in advance.
    uint8_t cbor_b1 = **p;
    int rc = cbor_extractors[(cbor_b1 & CBOR_TYPE_MASK)>>5](p, end, &val);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // PD_PRINTF("Extract done\r\n");
    uint8_t cbor_sub = **p;

    const cbor_keyed_parse_element_t *handler;
    rc = get_handler(cbor_b1, cbor_sub, &handler, handlers, key);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // PD_PRINTF("Selected handler %zu", handler_index);
    PD_PRINTF("%s\n", handler->desc);

    uint8_t cbor_type = cbor_b1 & CBOR_TYPE_MASK;
    if (handler->bstr_wrap) {
        // PD_PRINTF("parse offset: %zu. Unwrapping BSTR\n", (size_t)((*p)-ctx->envelope.ptr));
        val.cbor_start =  *p;

        end = val.ref.ptr + val.ref.uival;
        rc = cbor_extractors[(cbor_sub & CBOR_TYPE_MASK)>>5](p, end, &val);
        if (rc != CBOR_ERR_NONE) {
            return rc;
        }
        cbor_type = cbor_sub & CBOR_TYPE_MASK;
        // PD_PRINTF("Next type: %u\n", (unsigned)cbor_type >> 5);
    }

    // PD_PRINTF("[%s:%d] Invoking: %s\n", __FUNCTION__, __LINE__, handler->desc);
    if (handler->ptr == NULL) {
        // Nothing to do.
        PD_PRINTF("Skipping...\n");
        *p = val.cbor_start;
        rc = cbor_skip(p, end);
    }
    else if (handler->extract) {
        memcpy((void *)handler->ptr, &val, sizeof(cbor_value_t));
    }
    else if (handler->has_handler) {
        suit_handler_t handler_fn = (suit_handler_t) handler->ptr;
        // PD_PRINTF("Invoking explicit handler for CBOR Major %u\r\n", (unsigned)cbor_type >> 5);
        rc = handler_fn(p, end, ctx, &val, key, cbor_type);
    } else {
        // PD_PRINTF("Invoking default handler for CBOR Major %u\r\n", (unsigned)cbor_type >> 5);
        const cbor_keyed_parse_elements_t *children = (const cbor_keyed_parse_elements_t *) handler->ptr;
        switch(cbor_type) {
            case CBOR_TYPE_LIST:{
                int (*handler_fn) (const uint8_t** p, const uint8_t* end,
                    suit_parse_context_t *ctx,
                    const cbor_keyed_parse_elements_t *handlers,
                    size_t n_elements) ;
                if (handler->is_array) {
                    handler_fn = handle_array;
                }
                else if (handler->is_kv) {
                    handler_fn = handle_pairs;
                }
                else {
                    handler_fn = handle_list;
                }
                rc = handler_fn(p, end, ctx, children, val.ref.uival);
                break;
            }
            case CBOR_TYPE_MAP:
                rc = handle_pairs(p, end, ctx, children, val.ref.uival*2);
                break;
            case CBOR_TYPE_TAG:
                rc = handle_keyed_element(p, end, ctx, children, val.ref.uival);
                break;
        }
    }
    if (rc == CBOR_ERR_NONE) {
        if (handler->bstr_wrap) {
            *p = end;
        }
        else if ((cbor_b1 & CBOR_TYPE_MASK) == CBOR_TYPE_BSTR) {
            *p = val.ref.ptr+val.ref.uival;
        }
    }
    return rc;
}

static int handle_array(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
) {
    int rc = CBOR_ERR_NONE;
    for (; rc == CBOR_ERR_NONE && n_elements; n_elements--) {
        // PD_PRINTF("[%s:%d] ",__FUNCTION__, __LINE__);
        // PD_PRINTF("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), 0LL);
        rc = handle_keyed_element(p, end, ctx, handlers, 0);
    }
    return rc;
}

static int handle_list(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
) {
    int rc = CBOR_ERR_NONE;
    for (size_t i = 0; rc == CBOR_ERR_NONE && i < n_elements; i++) {
        // PD_PRINTF("[%s:%d] ",__FUNCTION__, __LINE__);
        // PD_PRINTF("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), (int64_t)i);
        rc = handle_keyed_element(p, end, ctx, handlers, i);
    }
    return rc;
}

static int handle_pairs(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_pairs
) {
    n_pairs = n_pairs/2;
    // PD_PRINTF("Handling %zu pairs\n", n_pairs);

    int rc = CBOR_ERR_NONE;
    for (; rc == CBOR_ERR_NONE && n_pairs; n_pairs--) {
        int64_t key64;
        // Get Key
        rc = cbor_get_int64(p, end, &key64);
        if (rc != CBOR_ERR_NONE) {
            break;
        }
        //TODO: range-check key64
        // Find handler
        // PD_PRINTF("[%s:%d] ",__FUNCTION__, __LINE__);
        // PD_PRINTF("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), (int64_t)key64);
        rc = handle_keyed_element(p, end, ctx, handlers, key64);
    }
    return rc;
}

static int handle_tag(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers
) {
    cbor_value_t tag;
    int rc = cbor_check_type_extract_ref(
        p, end, &tag, CBOR_TYPE_TAG
    );
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // PD_PRINTF("[%s:%d] ",__FUNCTION__, __LINE__);
    // PD_PRINTF("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), (int64_t)tag.ref.uival);
    // PD_PRINTF("Choosing betwen %zu tags\n", handlers->count);
    return handle_keyed_element(p, end, ctx, handlers, tag.ref.uival);
}

int suit_process_kv(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    const uint8_t type
) {
    // Ensure that the wrapper is a map.
    if ((**p & CBOR_TYPE_MASK) != type) {
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
    }
    cbor_value_t val;
    int rc = cbor_extract_ref(p, end, &val);
    if (rc == CBOR_ERR_NONE) {
        uint32_t n_keys = type == CBOR_TYPE_LIST ? val.ref.uival : val.ref.uival*2;
        rc = handle_pairs(p, end, ctx, handlers, n_keys);
    }
    return rc;
}

int Signature1_val_cat(suit_parse_context_t* ctx, cbor_value_t *val) {
    size_t clen = val->ref.uival + val->ref.ptr - val->cbor_start;
    if (ctx->Sign1.offset + clen > sizeof(ctx->Sign1.Signature1)) {
        RETURN_ERROR(SUIT_ERR_SIG);
    }
    memcpy(ctx->Sign1.Signature1 + ctx->Sign1.offset, val->cbor_start, clen);
    ctx->Sign1.offset += clen;
    return CBOR_ERR_NONE;
}
void suit_set_reference(suit_reference_t *ref, const uint8_t* end, cbor_value_t *val) {
    ref->ptr = val->cbor_start;
    ref->end = end;
}

PARSE_HANDLER(cose_sign1_alg_handler) {
    ctx->Sign1.alg = val->i64;
    return 0;
}
PARSE_HANDLER(cose_sign1_kid_handler) {
    suit_set_reference(&ctx->Sign1.kid, end, val);
    return 0;
}
PARSE_HANDLER(cose_sign1_payload_handler) {
    size_t clen = val->ref.uival + val->ref.ptr - val->cbor_start;
    if (clen > sizeof(ctx->manifest_suit_digest)) {
        return SUIT_ERR_SIG;
    }
    ctx->Sign1.Signature1[ctx->Sign1.offset++] = CBOR_TYPE_BSTR;
    memcpy(ctx->manifest_suit_digest, val->cbor_start, clen);
    return Signature1_val_cat(ctx, val);
}
PARSE_HANDLER(cose_sign1_signature_handler) {
    //TODO: Check for overflow.
    int rc = COSEAuthVerify(
        ctx->Sign1.Signature1, ctx->Sign1.offset,
        val->ref.ptr, val->ref.uival,
        ctx->Sign1.kid.ptr, ctx->Sign1.kid.end - ctx->Sign1.kid.ptr,
        ctx->Sign1.alg);

    return rc;
}

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_protected_elements,
    CBOR_KPARSE_ELEMENT_H(COSE_HDR_ALG, CBOR_TYPE_NINT, cose_sign1_alg_handler, "COSE Sign1 alg"),
);

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_unprotected_elements,
    CBOR_KPARSE_ELEMENT_H(COSE_HDR_KID, CBOR_TYPE_NINT, cose_sign1_kid_handler, "COSE Sign1 kid"),
);

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_protected,
    CBOR_KPARSE_ELEMENT_C(0, CBOR_TYPE_MAP, &cose_sign1_protected_elements, "COSE Sign1 protected"),
);

PARSE_HANDLER(cose_sign1_protected_handler) {
    int rc = Signature1_val_cat(ctx, val);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // ctx->Sign1.offset += val->ref.uival;
    end = val->ref.ptr + val->ref.uival;
    return handle_keyed_element(p, end, ctx, &cose_sign1_protected.elements, 0);
}

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_elements,
    CBOR_KPARSE_ELEMENT_H(0, CBOR_TYPE_BSTR, &cose_sign1_protected_handler, "COSE Sign1 Protected"),
    CBOR_KPARSE_ELEMENT_C(1, CBOR_TYPE_MAP, &cose_sign1_unprotected_elements, "COSE Sign1 Unprotected"),
    CBOR_KPARSE_ELEMENT_H(2, CBOR_TYPE_BSTR, &cose_sign1_payload_handler, "COSE Sign1 Payload"),
    CBOR_KPARSE_ELEMENT_H(3, CBOR_TYPE_BSTR, &cose_sign1_signature_handler, "COSE Sign1 Signature"),
);

PARSE_HANDLER(handle_cose_sign1) {
    // Actual length filled in later.
    memcpy(ctx->Sign1.Signature1, "\x84\x6ASignature1", SUIT_SIGNATURE1_CONTEXT_LEN+2);
    ctx->Sign1.offset = SUIT_SIGNATURE1_CONTEXT_LEN+2;
    return handle_list(p, end, ctx, &cose_sign1_elements.elements, val->ref.uival);
}

CBOR_KPARSE_ELEMENT_LIST(cose_auth_elements,
    CBOR_KPARSE_ELEMENT_H(COSE_SIGN1_TAG, CBOR_TYPE_LIST, handle_cose_sign1, "COSE Sign 1"),
);

CBOR_KPARSE_ELEMENT_LIST(auth_list_elements,
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_TAG, &cose_auth_elements, "Authorisation list"),
);


PARSE_HANDLER(version_handler)
{
    if (val->u64 != SUIT_SUPPORTED_VERSION) {
        RETURN_ERROR(SUIT_ERR_VERSION);
    }
    return CBOR_ERR_NONE;
}

PARSE_HANDLER(suit_common_handler) {
    suit_set_reference(&ctx->common, end, val);
    return 0;
}

int check_id(const int key, const uint8_t *id, suit_parse_context_t *ctx, int failcode) {
    suit_reference_t *ref;
    int rc = key_to_reference(key, &ref, ctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    const uint8_t *p = ref->ptr;
    cbor_value_t val;
    rc = cbor_check_type_extract_ref(&p, ref->end, &val, CBOR_TYPE_BSTR);
    if (rc != CBOR_ERR_NONE || val.ref.uival != UUID_SIZE) {
        RETURN_ERROR(failcode);
    }
    rc = memcmp(id, val.ref.ptr, UUID_SIZE);
    if (rc != 0) {
        SET_ERROR(rc, failcode);
    }
    return rc;
}

PARSE_HANDLER(vendor_match_handler)
{
    return check_id(key, vendor_id, ctx, SUIT_MFST_ERR_VENDOR_MISMATCH);
}
PARSE_HANDLER(class_match_handler)
{
    return check_id(key, class_id, ctx, SUIT_MFST_ERR_CLASS_MISMATCH);
}

static cbor_value_t exp_digest_alg;
static cbor_value_t exp_digest;
CBOR_KPARSE_ELEMENT_LIST(suit_digest_elements,
    CBOR_KPARSE_ELEMENT_EX(0, CBOR_TYPE_NINT, &exp_digest_alg, "SUIT Digest Algorithm"),
    CBOR_KPARSE_ELEMENT_EX(1, CBOR_TYPE_BSTR, &exp_digest, "SUIT Digest Bytes"),
);
CBOR_KPARSE_ELEMENT_LIST(suit_digest_container,
    CBOR_KPARSE_ELEMENT_C(0, CBOR_TYPE_LIST, &suit_digest_elements, "SUIT Digest"),
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_LIST, &suit_digest_elements, "SUIT Digest Wrapped"),
);


int suit_check_digest(suit_reference_t* expected_digest, const uint8_t *data, size_t data_len)
{
    const uint8_t *p = expected_digest->ptr;
    const uint8_t *end = expected_digest->end;
    int rc = handle_keyed_element(&p, end, NULL, &suit_digest_container.elements, 0);
    // int rc = suit_process_kv(&p, end, NULL, &suit_digest_elements.elements, CBOR_TYPE_LIST);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    return suit_platform_verify_digest(exp_digest_alg.i64, exp_digest.ref.ptr, exp_digest.ref.uival, data, data_len);
}


PARSE_HANDLER(image_match_handler)
{
    uint64_t image_size;
    //TODO: Component ID
    size_t component_index = 0;
    suit_reference_t *sz;
    int rc = key_to_reference(SUIT_PARAMETER_IMAGE_SIZE, &sz, ctx);
    const uint8_t *np = sz->ptr;
    rc = rc ? rc : cbor_get_uint64(&np, sz->end, &image_size);
    const uint8_t *image;
    rc = rc ? rc : suit_platform_get_image_ref(NULL, &image);
    suit_reference_t *exp;
    rc = rc ? rc : key_to_reference(SUIT_PARAMETER_IMAGE_DIGEST, &exp, ctx);
    rc = rc ? rc : suit_check_digest(exp, image, image_size);
    return rc;
}

//TODO: multiple components
PARSE_HANDLER(parameter_handler) {
    suit_reference_t *ref;
    int rc = key_to_reference(key, &ref, ctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    ref->ptr = val->cbor_start;
    ref->end = end;
    *p = val->cbor_start;
    return cbor_skip(p, end);
}
//TODO: This could be optimised: each parameter uses same handler, so this structure is too big
CBOR_KPARSE_ELEMENT_LIST(parameter_handlers,
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_VENDOR_ID, CBOR_TYPE_BSTR, parameter_handler, "vendor-id"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_CLASS_ID, CBOR_TYPE_BSTR, parameter_handler, "class-id"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_PARAMETER_IMAGE_DIGEST, CBOR_TYPE_LIST, parameter_handler, "img-digest"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_IMAGE_SIZE, CBOR_TYPE_UINT, parameter_handler, "img-size"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_URI, CBOR_TYPE_TSTR, parameter_handler, "uri"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_SOURCE_COMPONENT, CBOR_TYPE_UINT, parameter_handler, "source-comp"),
);

PARSE_HANDLER(invoke_handler)
{
    // TODO: add component ID
    return suit_platform_do_run();
}

CBOR_KPARSE_ELEMENT_LIST(sequence_elements,
    CBOR_KPARSE_ELEMENT_H(SUIT_CONDITION_VENDOR_ID, CBOR_TYPE_SIMPLE, vendor_match_handler, "vendor-match"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CONDITION_CLASS_ID, CBOR_TYPE_SIMPLE, class_match_handler, "class-match"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CONDITION_IMAGE_MATCH, CBOR_TYPE_SIMPLE, NULL, "image-match"),
    // CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_SET_COMP_IDX, CBOR_TYPE_UINT, set_component_handler),
    CBOR_KPARSE_ELEMENT_C(SUIT_DIRECTIVE_SET_PARAMETERS, CBOR_TYPE_MAP, &parameter_handlers, "set-parameters"),
    CBOR_KPARSE_ELEMENT_C(SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, CBOR_TYPE_MAP, &parameter_handlers, "override-parameters"),
    CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_FETCH, CBOR_TYPE_SIMPLE, NULL, "Fetch"),
    CBOR_KPARSE_ELEMENT_H(SUIT_DIRECTIVE_INVOKE, CBOR_TYPE_SIMPLE, invoke_handler, "invoke"),
);


CBOR_KPARSE_ELEMENT_LIST(common_elements,
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_DEPENDENCIES, CBOR_TYPE_BSTR, NULL, "Dependencies"),
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_COMPONENTS, CBOR_TYPE_BSTR, NULL, "Components"),
    CBOR_KPARSE_ELEMENT_C_BWRAP_KV(SUIT_COMMON_SEQUENCE, CBOR_TYPE_LIST, &sequence_elements, "common-sequence"),
);

CBOR_KPARSE_ELEMENT_LIST(common_entry_elements,
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_MAP, &common_elements, "Common Block")
);

PARSE_HANDLER(suit_sequence_handler) {
    // clear vars
    memset(ctx->vars, 0, sizeof(ctx->vars));
    const uint8_t *cp = ctx->common.ptr;
    const uint8_t *cend = ctx->common.end;
    int rc = handle_keyed_element(&cp, cend, ctx, &common_entry_elements.elements, 0);
    if (rc == CBOR_ERR_NONE) {
        rc = handle_pairs(p, end, ctx, &sequence_elements.elements, val->ref.uival);
    }
    return rc;
}

CBOR_KPARSE_ELEMENT_LIST(manifest_elements,
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_VERSION, CBOR_TYPE_UINT, version_handler, "SUIT Structure Version"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_SEQUCENCE_NUMBER, CBOR_TYPE_UINT, NULL, "SUIT Sequence Number"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_COMMON, CBOR_TYPE_BSTR, suit_common_handler, "SUIT Common"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_INSTALL, CBOR_TYPE_LIST, NULL, "Install sequence"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_VALIDATE, CBOR_TYPE_LIST, &suit_sequence_handler, "Validate sequence"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_RUN, CBOR_TYPE_LIST, &suit_sequence_handler, "Run sequence"),
);

//TODO: Add pre-handler/bwrap-handler option

PARSE_HANDLER(manifest_handler) {
    const uint8_t *data = val->cbor_start;
    size_t data_len = val->ref.ptr - val->cbor_start + val->ref.uival;
    suit_reference_t manifest_digest = {ctx->manifest_suit_digest, ctx->manifest_suit_digest + sizeof(ctx->manifest_suit_digest)};
    int rc = suit_check_digest(&manifest_digest, data, data_len);
    if (rc == CBOR_ERR_NONE) {
        rc = suit_process_kv(p, end, ctx, &manifest_elements.elements, CBOR_TYPE_MAP);
    }
    return rc;
}

CBOR_KPARSE_ELEMENT_LIST(envelope_handlers,
    CBOR_KPARSE_ELEMENT_A_BWRAP(SUIT_ENVELOPE_AUTH, CBOR_TYPE_LIST, &auth_list_elements, "Authorisation"),
    CBOR_KPARSE_ELEMENT_H(SUIT_ENVELOPE_MANIFEST, CBOR_TYPE_BSTR, &manifest_handler, "Manifest"),
);


int suit_do_process_manifest(const uint8_t *manifest, size_t manifest_size) {
    suit_parse_context_t ctx = {0};
    ctx.envelope.ptr = manifest;
    ctx.envelope.end = manifest + manifest_size;
    const uint8_t *p = manifest;
    const uint8_t *end = manifest + manifest_size;
    int rc = suit_process_kv(
        &p, end, &ctx, &envelope_handlers.elements, CBOR_TYPE_MAP
    );
    return rc;
}

PARSE_HANDLER(vs_seq_num_handler)
{
    ctx->search_result.ptr = val->cbor_start;
    ctx->search_result.end = end;
    return 0;
}


CBOR_KPARSE_ELEMENT_LIST(vs_manifest_handlers,
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_VERSION, CBOR_TYPE_UINT, version_handler, "Manifest version"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_SEQUCENCE_NUMBER, CBOR_TYPE_UINT, vs_seq_num_handler, "Sequence number"),
);

CBOR_KPARSE_ELEMENT_LIST(vs_wrapper_handlers,
    CBOR_KPARSE_ELEMENT_H(SUIT_ENVELOPE_AUTH, CBOR_TYPE_BSTR, NULL, "Authorisation"),
    CBOR_KPARSE_ELEMENT_C_BWRAP(SUIT_ENVELOPE_MANIFEST, CBOR_TYPE_MAP, &vs_manifest_handlers, "Manifest"),
);


int suit_get_seq(const uint8_t *manifest, size_t manifest_size, uint64_t *seqnum) {
    suit_parse_context_t ctx = {0};
    ctx.envelope.ptr = manifest;
    ctx.envelope.end = manifest + manifest_size;
    const uint8_t *p = manifest;
    const uint8_t *end = manifest + manifest_size;
    suit_process_kv(
        &p, end, &ctx, &vs_wrapper_handlers.elements, CBOR_TYPE_MAP
    );
    if (!ctx.search_result.ptr) {
        return CBOR_ERR_INTEGER_ENCODING;
    }
    p = ctx.search_result.ptr;
    return cbor_get_uint64(&p, ctx.search_result.end, seqnum);
}
