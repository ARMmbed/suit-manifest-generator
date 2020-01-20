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

int key_to_var_offset(int64_t key) {
    const int var_keys[] = {
        -1,   // RESVD
        -1,   // suit-parameter-strict-order
        -1,   // suit-parameter-coerce-condition-failure
        offsetof(suit_vars_t, vendor_id),   // suit-parameter-vendor-id
        offsetof(suit_vars_t, class_id),   // suit-parameter-class-id
        offsetof(suit_vars_t, device_id),   // suit-parameter-device-id
        offsetof(suit_vars_t, uri),   // suit-parameter-uri
        offsetof(suit_vars_t, encryption_info),   // suit-parameter-encryption-info
        offsetof(suit_vars_t, compression_info),   // suit-parameter-compression-info
        offsetof(suit_vars_t, unpack_info),   // suit-parameter-unpack-info
        offsetof(suit_vars_t, source_component),   // suit-parameter-source-component
        offsetof(suit_vars_t, image_digest),   // suit-parameter-image-digest
        offsetof(suit_vars_t, image_size),   // suit-parameter-image-size
    };
    if (key > ARRAY_SIZE(var_keys) || key < 0) {
        RETURN_ERROR(-SUIT_ERR_PARAMETER_KEY);
    }
    return var_keys[key];
}

int cbor_get_as_uint64(const uint8_t** p, const uint8_t* end, uint64_t* n){
    if (*p >= end) {
        RETURN_ERROR(CBOR_ERR_OVERRUN);
    }
    uint8_t iv = **p & ~CBOR_TYPE_MAX;
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
    uint8_t type = **p & CBOR_TYPE_MAX;
    if (type != CBOR_TYPE_UINT) {
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
    }
    return cbor_get_as_uint64(p, end, n);
}

int cbor_get_int64(const uint8_t** p, const uint8_t* end, int64_t* n) {
    uint8_t type = **p & CBOR_TYPE_MAX;
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

int cbor_extract_posint(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val)
{
    return cbor_get_as_uint64(p, end, &(val->u64));
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
    int rc = cbor_get_as_uint64(p, end, &(val->ref.length));
    if (rc == CBOR_ERR_NONE) {
        val->ref.ptr = *p;
    }
    return rc;
}

int cbor_extract_tag(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val)
{
    RETURN_ERROR(CBOR_ERR_UNIMPLEMENTED);
}
int cbor_extract_primitive(
    const uint8_t **p,
    const uint8_t *end,
    cbor_value_t *val)
{
    val->primitive = (**p & (~CBOR_TYPE_MAX));
    (*p)++;
    RETURN_ERROR(CBOR_ERR_NONE);
}



int cbor_check_type_extract_ref(
        const uint8_t **p,
        const uint8_t *end,
        cbor_value_t *o_val,
        const uint8_t cbor_type
) {
    if ((**p & CBOR_TYPE_MAX) != cbor_type) {
        PD_PRINTF("Expected: %u Actual %u\n", (unsigned) cbor_type>>5, (unsigned)(**p & CBOR_TYPE_MAX)>>5);

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
    cbor_extract_posint,
    cbor_extract_int,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_ref,
    cbor_extract_tag,
    cbor_extract_primitive
};

int cbor_skip(const uint8_t **p, const uint8_t *end)
{
    uint8_t ct = **p & CBOR_TYPE_MAX;
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
            if ((*p) + val.ref.length <= end) {
                (*p) += val.ref.length;
            } else {
                SET_ERROR(rc, CBOR_ERR_OVERRUN);
            }
            break;
        case CBOR_TYPE_MAP:
            val.ref.length *= 2;
            // no break;
        case CBOR_TYPE_LIST:
            for (size_t count = val.ref.length; count && rc == CBOR_ERR_NONE; count--) {
                rc = cbor_skip(p, end);
            }
            break;
        default:
            SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED);
    }
    return rc;
}
int get_handler(
    const uint8_t** p,
    const uint8_t* end,
    const int64_t key64,
    const cbor_keyed_parse_element_t* handlers,
    const size_t n_handlers
) {
    size_t i;
    // Find a matching key
    for (i = 0; i < n_handlers && handlers[i].key < key64; i++)
    {}
    if (i >= n_handlers || handlers[i].key != key64 ) {
        PD_PRINTF("Couldn't find a handler for key %d\n", (int) key64);
        RETURN_ERROR(-CBOR_ERR_KEY_MISMATCH);
    }
    uint8_t cbor_type = **p & CBOR_TYPE_MAX;
    for (; i < n_handlers && handlers[i].key == key64; i++) {
        if (handlers[i].type << 5 == CBOR_TYPE_NINT &&
            cbor_type == CBOR_TYPE_UINT)
        {
            return (int)i;
        }
        if (handlers[i].type << 5 == cbor_type) {
            return (int)i;
        }
        if (handlers[i].null_opt && **p == CBOR_NULL) {
            return (int)i;
        }
        if (!handlers[i].choice) {
            RETURN_ERROR(-CBOR_ERR_TYPE_MISMATCH);
        }
    }
    RETURN_ERROR(-CBOR_ERR_TYPE_MISMATCH);
}

int handle_pairs(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_element_t *handlers,
    const size_t n_handlers,
    size_t n_pairs
) {
    int rc = CBOR_ERR_NONE;
    for (; rc == CBOR_ERR_NONE && n_pairs; n_pairs--) {
        int64_t key64;
        // Get Key
        rc = cbor_get_int64(p, end, &key64);
        if (rc != CBOR_ERR_NONE) {
            break;
        // } else {
        //     cbor_value_t ptr;
        //     ptr.ref.ptr = *p;
        //     ptr.ref.length = 16;
        }
        //TODO: range-check key64
        // Find handler
        PD_PRINTF("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->outer), key64);
        rc = get_handler(p, end, key64, handlers, n_handlers);
        if (rc < 0) {
            rc = -rc;
            break;
        }
        size_t handler_index = rc;
        cbor_keyed_parse_element_t handler = handlers[handler_index];
        uint8_t cbor_type = **p & CBOR_TYPE_MAX;
        cbor_value_t val;
        PD_PRINTF("%s:%d\n    Invoking: %s\n", __FUNCTION__, __LINE__, handler.desc);
        val.cbor_start = *p;
        rc = cbor_extractors[handler.type](p, end, &val);
        if (rc == CBOR_ERR_NONE) {
            rc = handler.handler(p, end, ctx, &val, key64, cbor_type);
        }
    }
    return rc;
}

int suit_process_kv(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_element_t *handlers,
    const size_t n_handlers,
    const uint8_t type
) {
    // Ensure that the wrapper is a map.
    if ((**p & CBOR_TYPE_MAX) != type) {
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH);
    }
    cbor_value_t val;
    int rc = cbor_extract_ref(p, end, &val);
    if (rc == CBOR_ERR_NONE) {
        *p = val.ref.ptr;
        uint32_t n_keys = type == CBOR_TYPE_LIST ? val.ref.length/2 : val.ref.length;
        rc = handle_pairs(p, end, ctx, handlers, n_handlers, n_keys);
    }
    return rc;
}

int suit_process_bwrap_kv(
    const uint8_t** p,
    const uint8_t* end,
    suit_parse_context_t *ctx,
    const cbor_keyed_parse_element_t *handlers,
    const size_t n_handlers,
    const uint8_t type
) {
    PD_PRINTF("> %s (offset:%u)\n", __FUNCTION__, (unsigned)(*p - ctx->outer));
    cbor_value_t bstr;
    int rc = cbor_check_type_extract_ref(
        p, end, &bstr, CBOR_TYPE_BSTR
    );
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    PD_PRINTF("%s:%d %p %llu\n", __PRETTY_FUNCTION__, __LINE__, bstr.ref.ptr, bstr.ref.length);
    // Check bstr length
    if (end < bstr.ref.ptr + bstr.ref.length) {
        RETURN_ERROR(CBOR_ERR_OVERRUN);
    }
    // Extract from bstr
    const uint8_t* b_end = bstr.ref.ptr + bstr.ref.length;
    *p = bstr.ref.ptr;
    return suit_process_kv(p, b_end, ctx, handlers, n_handlers, type);
}

PARSE_HANDLER(vendor_match_handler)
{
    PD_PRINTF("> %s (offset:%u)\n", __FUNCTION__, (unsigned)(*p - ctx->outer));
    size_t len = MIN(val->ref.length, sizeof(vendor_id));
    int rc = memcmp(vendor_id, val->ref.ptr, len);
    if (rc != 0) {
        PD_PRINTF("< %s = %d\n", __FUNCTION__, rc);
        return SUIT_MFST_ERR_VENDOR_MISMATCH;
    }
    *p = val->ref.ptr + val->ref.length;
    PD_PRINTF("< %s\n", __FUNCTION__);
    return CBOR_ERR_NONE;
}
PARSE_HANDLER(class_match_handler)
{
    PD_PRINTF("> %s (offset:%u)\n", __FUNCTION__, (unsigned)(*p - ctx->outer));
    size_t len = MIN(val->ref.length, sizeof(class_id));
    int rc = memcmp(class_id, val->ref.ptr, len);
    if (rc != 0) {
        PD_PRINTF("< %s = %d\n", __FUNCTION__, rc);
        return SUIT_MFST_ERR_CLASS_MISMATCH;
    }
    *p = val->ref.ptr + val->ref.length;
    PD_PRINTF("< %s\n", __FUNCTION__);
    return CBOR_ERR_NONE;
}

int verify_suit_digest(
    const uint8_t *digest,
    const uint8_t *digest_end,
    const uint8_t *data,
    size_t data_len)
{
    cbor_value_t digest_array;
    cbor_value_t digest_type;
    cbor_value_t digest_bytes;
    int rc = CBOR_ERR_NONE;
    const uint8_t *p = digest;

    // Unwrap if wrapped
    if ((*p & CBOR_TYPE_MAX) == CBOR_TYPE_BSTR) {
        cbor_value_t digest_val;
        rc = cbor_extract_ref(&p, digest_end, &digest_val);
        if (rc == CBOR_ERR_NONE) {
            p = digest_val.ref.ptr;
            digest_end = digest_val.ref.ptr + digest_val.ref.length;
        }
    }

    // Get Array
    if (rc == CBOR_ERR_NONE)
    rc = cbor_check_type_extract_ref(&p, digest_end, &digest_array, CBOR_TYPE_LIST);
    // Get Type
    if (rc == CBOR_ERR_NONE) {
        rc = cbor_extract_int(&p, digest_end, &digest_type);
    }
    // Get Digest
    if (rc == CBOR_ERR_NONE) {
        rc = cbor_check_type_extract_ref(&p, digest_end, &digest_bytes, CBOR_TYPE_BSTR);
    }
    switch(digest_type.i64) {
        case SUIT_DIGEST_TYPE_SHA256:
            if (digest_bytes.ref.length != 256/8) {
                return CBOR_ERR_TYPE_MISMATCH;
            }
            return suit_platform_verify_sha256(digest_bytes.ref.ptr, data, data_len);
        case SUIT_DIGEST_TYPE_SHA224:
        case SUIT_DIGEST_TYPE_SHA384:
        default:
            return CBOR_ERR_UNIMPLEMENTED;
    }
}

PARSE_HANDLER(image_match_handler)
{
    cbor_value_t image_size;
    const uint8_t *np = ctx->vars[0].image_size;
    int rc = cbor_extract_posint(&np, np+10, &image_size);
    const uint8_t *image;
    if (rc == CBOR_ERR_NONE) {
        rc = suit_platform_get_image_ref(NULL, &image);
    }
    if (rc == CBOR_ERR_NONE) {
        verify_suit_digest(
            ctx->vars[0].image_digest,
            ctx->vars[0].image_digest + 1 + 8 + 2, //TODO: Fix length handling
            image,
            image_size.u64);
    }
    return rc;
}

//TODO: multiple components
PARSE_HANDLER(parameter_handler) {
    int rc = key_to_var_offset(key);
    if (rc < 0) {
        return -rc;
    }
    size_t var_offset = rc;
    if (var_offset >= sizeof(suit_vars_t)) {
        RETURN_ERROR(CBOR_ERR_OVERRUN);
    }
    //TODO: Check ACL
    const uint8_t **var_ptr = (void*)((uintptr_t) (&ctx->vars) + var_offset);
    if ((uintptr_t)var_ptr >= (uintptr_t)&ctx->vars + sizeof(suit_vars_t)) {
        RETURN_ERROR(CBOR_ERR_OVERRUN);
    }
    *var_ptr = val->cbor_start;
    (*p) = val->cbor_start;
    return cbor_skip(p, end);
}

const cbor_keyed_parse_element_t parameter_handlers[] = {
    CBOR_KPARSE_ELEMENT(SUIT_PARAMETER_VENDOR_ID, CBOR_TYPE_BSTR, parameter_handler, "vendor-id"),
    CBOR_KPARSE_ELEMENT(SUIT_PARAMETER_CLASS_ID, CBOR_TYPE_BSTR, parameter_handler, "class-id"),
    CBOR_KPARSE_ELEMENT(SUIT_PARAMETER_URI, CBOR_TYPE_TSTR, parameter_handler, "uri"),
    CBOR_KPARSE_ELEMENT(SUIT_PARAMETER_SOURCE_COMPONENT, CBOR_TYPE_UINT, parameter_handler, "source-comp"),
    CBOR_KPARSE_ELEMENT(SUIT_PARAMETER_IMAGE_DIGEST, CBOR_TYPE_LIST, parameter_handler, "img-digest"),
    CBOR_KPARSE_ELEMENT(SUIT_PARAMETER_IMAGE_SIZE, CBOR_TYPE_UINT, parameter_handler, "img-size"),
};

PARSE_HANDLER(override_parameters_handler)
{
    *p = val->ref.ptr;
    int rc = handle_pairs(p, end, ctx, parameter_handlers, ARRAY_SIZE(parameter_handlers), val->ref.length);
    return rc;

}
PARSE_HANDLER(set_parameters_handler)
{
    return override_parameters_handler(p, end, ctx, val, key, cbor_type);
}
PARSE_HANDLER(invoke_handler)
{
    // TODO: add component ID
    return suit_platform_do_run();
}

const cbor_keyed_parse_element_t sequence_handlers[] = {
    CBOR_KPARSE_ELEMENT(SUIT_CONDITION_VENDOR_ID, CBOR_TYPE_BSTR, vendor_match_handler, "vendor-match"),
    CBOR_KPARSE_ELEMENT(SUIT_CONDITION_CLASS_ID, CBOR_TYPE_BSTR, class_match_handler, "class-match"),
    CBOR_KPARSE_ELEMENT(SUIT_CONDITION_IMAGE_MATCH, CBOR_TYPE_SIMPLE, image_match_handler, "image-match"),
    // CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_SET_COMP_IDX, CBOR_TYPE_UINT, set_component_handler),
    CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_SET_PARAMETERS, CBOR_TYPE_MAP, set_parameters_handler, "set-parameters"),
    CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, CBOR_TYPE_MAP, override_parameters_handler, "override-parameters"),
    // // CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_FETCH, CBOR_TYPE_SIMPLE, fetch_handler),
    CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_INVOKE, CBOR_TYPE_SIMPLE, invoke_handler, "invoke"),
};
const size_t sequence_handlers_count = ARRAY_SIZE(sequence_handlers);

PARSE_HANDLER(version_handler)
{
    if (val->u64 != SUIT_SUPPORTED_VERSION) {
        RETURN_ERROR(SUIT_ERR_VERSION);
    }
    return CBOR_ERR_NONE;
}
PARSE_HANDLER(seq_num_handler)
{
    // Already checked.
    return CBOR_ERR_NONE;
}
PARSE_HANDLER(common_handler)
{
    ctx->common = val->ref.ptr;
    ctx->common_size = val->ref.length;
    *p = val->ref.ptr+val->ref.length;
    return CBOR_ERR_NONE;
}
PARSE_HANDLER(bstr_skip_handler)
{
    *p = val->ref.ptr + val->ref.length;
    return CBOR_ERR_NONE;
}
PARSE_HANDLER(common_sequence_handler)
{
    return suit_process_kv(p, end, ctx, sequence_handlers, sequence_handlers_count, CBOR_TYPE_LIST);
}
const cbor_keyed_parse_element_t common_handlers_seq[] = {
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_DEPENDENCIES, CBOR_TYPE_BSTR, bstr_skip_handler, "bstr-skip"),
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_COMPONENTS, CBOR_TYPE_BSTR, bstr_skip_handler, "bstr-skip"),
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_SEQUENCE, CBOR_TYPE_BSTR, common_sequence_handler, "common-sequence"),
};

int do_common(suit_parse_context_t *ctx) {
    const uint8_t *p = ctx->common;
    const uint8_t *end = ctx->common + ctx->common_size;
    return suit_process_kv(&p, end, ctx, common_handlers_seq, ARRAY_SIZE(common_handlers_seq), CBOR_TYPE_MAP);
}

PARSE_HANDLER(sequence_handler)
{
    int rc = do_common(ctx);
    if (rc == CBOR_ERR_NONE) {
        rc = suit_process_kv(p, end, ctx, sequence_handlers, sequence_handlers_count, CBOR_TYPE_LIST);
    }
    *p = val->ref.ptr + val->ref.length;
    return rc;
}

const cbor_keyed_parse_element_t manifest_handlers[] = {
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_VERSION, CBOR_TYPE_UINT, version_handler, "Manifest version"),
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_SEQUCENCE_NUMBER, CBOR_TYPE_UINT, seq_num_handler, "Sequence number"),
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_COMMON, CBOR_TYPE_BSTR, common_handler, "Common block"),
    // CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_INSTALL, CBOR_TYPE_BSTR, sequence_handler, "Install sequence"),
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_VALIDATE, CBOR_TYPE_BSTR, sequence_handler, "Validate sequence"),
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_RUN, CBOR_TYPE_BSTR, sequence_handler, "Run sequence"),

};
const size_t manifest_handlers_count = ARRAY_SIZE(manifest_handlers);

PARSE_HANDLER(manifest_extract_handler)
{
    size_t manifest_cbor_prefix_length = (uintptr_t) val->ref.ptr - (uintptr_t) val->cbor_start;
    int rc = do_cose_auth(ctx->auth, val->cbor_start, val->ref.length + manifest_cbor_prefix_length);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // p is already advanced into the bstr, so don't use bwrap_kv
    return suit_process_kv(
        p, end, ctx, manifest_handlers, manifest_handlers_count, CBOR_TYPE_MAP
    );
}

PARSE_HANDLER(auth_handler)
{
    ctx->auth = val->cbor_start;
    *p = val->ref.ptr + val->ref.length;
    return CBOR_ERR_NONE;
}

const cbor_keyed_parse_element_t wrapper_handlers[] = {
    CBOR_KPARSE_ELEMENT_NULL(SUIT_OUTER_AUTH, CBOR_TYPE_BSTR, auth_handler, "Authorisation"),
    CBOR_KPARSE_ELEMENT(SUIT_OUTER_MANIFEST, CBOR_TYPE_BSTR, manifest_extract_handler, "Manifest"),
};

const size_t wrapper_handlers_count = ARRAY_SIZE(wrapper_handlers);

int suit_do_process_manifest(const uint8_t *manifest, size_t manifest_size) {
    suit_parse_context_t ctx = {0};
    ctx.outer = manifest;
    ctx.outer_size = manifest_size;
    const uint8_t *p = manifest;
    const uint8_t *end = manifest + manifest_size;
    int rc = suit_process_kv(
        &p, end, &ctx, wrapper_handlers, wrapper_handlers_count, CBOR_TYPE_MAP
    );
    return rc;
}

PARSE_HANDLER(vs_seq_num_handler)
{
    ctx->search_result = val->cbor_start;
    return 0;
}

const cbor_keyed_parse_element_t vs_manifest_handlers[] = {
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_VERSION, CBOR_TYPE_UINT, version_handler, "Manifest version"),
    CBOR_KPARSE_ELEMENT(SUIT_MANIFEST_SEQUCENCE_NUMBER, CBOR_TYPE_UINT, vs_seq_num_handler, "Sequence number"),
};
const size_t vs_manifest_handlers_count = ARRAY_SIZE(vs_manifest_handlers);

PARSE_HANDLER(vs_manifest_handler)
{
    return suit_process_kv(
        p, end, ctx, vs_manifest_handlers, vs_manifest_handlers_count, CBOR_TYPE_MAP
    );
}

const cbor_keyed_parse_element_t vs_wrapper_handlers[] = {
    CBOR_KPARSE_ELEMENT_NULL(SUIT_OUTER_AUTH, CBOR_TYPE_BSTR, bstr_skip_handler, "Authorisation"),
    CBOR_KPARSE_ELEMENT(SUIT_OUTER_MANIFEST, CBOR_TYPE_BSTR, vs_manifest_handler, "Manifest"),
};
const size_t vs_wrapper_handlers_count = ARRAY_SIZE(vs_wrapper_handlers);

int suit_get_seq(const uint8_t *manifest, size_t manifest_size, uint64_t *seqnum) {
    suit_parse_context_t ctx = {0};
    ctx.outer = manifest;
    ctx.outer_size = manifest_size;
    const uint8_t *p = manifest;
    const uint8_t *end = manifest + manifest_size;
    suit_process_kv(
        &p, end, &ctx, vs_wrapper_handlers, vs_wrapper_handlers_count, CBOR_TYPE_MAP
    );
    if (!ctx.search_result) {
        return CBOR_ERR_INTEGER_ENCODING;
    }
    p = ctx.search_result;
    return cbor_get_uint64(&p, p+9, seqnum);
}
