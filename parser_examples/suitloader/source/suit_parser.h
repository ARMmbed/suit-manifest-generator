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
#ifndef _SUIT_PARSER_H_
#define _SUIT_PARSER_H_

#define MAX_COMPONENTS 2

#include <stdint.h>
#include <stddef.h>

#define CBOR_TYPE_UINT (0 << 5)
#define CBOR_TYPE_NINT (1 << 5)
#define CBOR_TYPE_BSTR (2 << 5)
#define CBOR_TYPE_TSTR (3 << 5)
#define CBOR_TYPE_LIST (4 << 5)
#define CBOR_TYPE_MAP (5 << 5)
#define CBOR_TYPE_TAG (6 << 5)
#define CBOR_TYPE_SIMPLE (7 << 5)
#define CBOR_TYPE_MAX (7 << 5)

#define CBOR_FALSE (CBOR_TYPE_SIMPLE | 20)
#define CBOR_TRUE (CBOR_TYPE_SIMPLE | 21)
#define CBOR_NULL (CBOR_TYPE_SIMPLE | 22)

#define SUIT_SUPPORTED_VERSION 1


#define PRINT_ON_ERROR 0

#define MIN(X,Y) ((X)<(Y)?(X):(Y))

#define SET_ERROR(RC, VAL)\
    do{\
        (RC)=(VAL);\
        if((VAL) && PRINT_ON_ERROR){printf("Error " #VAL " (%i) set on %s:%u\r\n",(VAL),__FILE__,__LINE__);\
    }}while(0)

#define RETURN_ERROR(VAL)\
    do{\
        if((VAL) && PRINT_ON_ERROR){printf("Error " #VAL " (%i) set on %s:%u\r\n",(VAL),__FILE__,__LINE__);}\
        return (VAL);}while(0)

#define ARRAY_SIZE(X) (sizeof(X)/sizeof((X)[0]))

#define SUIT_OUTER_AUTH 2
#define SUIT_OUTER_MANIFEST 3

#define SUIT_MANIFEST_VERSION 1
#define SUIT_MANIFEST_SEQUCENCE_NUMBER 2
#define SUIT_MANIFEST_COMMON 3
#define SUIT_MANIFEST_INSTALL 9
#define SUIT_MANIFEST_VALIDATE 10
#define SUIT_MANIFEST_LOAD 11
#define SUIT_MANIFEST_RUN 12

#define SUIT_COMMON_DEPENDENCIES 1
#define SUIT_COMMON_COMPONENTS 2
#define SUIT_COMMON_SEQUENCE 4

#define SUIT_CONDITION_VENDOR_ID 1
#define SUIT_CONDITION_CLASS_ID 2
#define SUIT_CONDITION_IMAGE_MATCH 3

#define SUIT_DIRECTIVE_SET_COMP_IDX 12
#define SUIT_DIRECTIVE_SET_PARAMETERS 19
#define SUIT_DIRECTIVE_OVERRIDE_PARAMETERS 20
#define SUIT_DIRECTIVE_FETCH 21
#define SUIT_DIRECTIVE_INVOKE 23

#define SUIT_PARAMETER_VENDOR_ID 3
#define SUIT_PARAMETER_CLASS_ID 4
#define SUIT_PARAMETER_URI 6
#define SUIT_PARAMETER_SOURCE_COMPONENT 10
#define SUIT_PARAMETER_IMAGE_DIGEST 11
#define SUIT_PARAMETER_IMAGE_SIZE 12

#define SUIT_DIGEST_TYPE_SHA224 1
#define SUIT_DIGEST_TYPE_SHA256 2
#define SUIT_DIGEST_TYPE_SHA384 3

#ifdef PARSER_DEBUG
#define CBOR_KPARSE_ELEMENT(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, .handler=(HANDLER), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_NULL(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, .null_opt = 1, .handler=(HANDLER), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_CHOICE(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .choice = 1, 0, .handler=(HANDLER), .desc=(DESC)}
#define PD_PRINTF(...)\
    printf(__VA_ARGS__)
#else
#define CBOR_KPARSE_ELEMENT(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, .handler=(HANDLER)}
#define CBOR_KPARSE_ELEMENT_NULL(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, .null_opt = 1, .handler=(HANDLER)}
#define CBOR_KPARSE_ELEMENT_CHOICE(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .choice = 1, 0, .handler=(HANDLER)}
#define PD_PRINTF(...)
#endif

#define PARSE_HANDLER(N)\
    int N( \
        const uint8_t **p, \
        const uint8_t *end, \
        suit_parse_context_t* ctx, \
        cbor_value_t *val, \
        const int key,\
        const uint8_t cbor_type \
    )

#ifdef __cplusplus
extern "C" {
#endif

extern const uint8_t vendor_id[16];
extern const uint8_t class_id[16];

enum {
    CBOR_ERR_NONE = 0,
    CBOR_ERR_TYPE_MISMATCH,
    CBOR_ERR_KEY_MISMATCH,
    CBOR_ERR_OVERRUN,
    CBOR_ERR_INTEGER_DECODE_OVERFLOW,
    CBOR_ERR_INTEGER_ENCODING,
    CBOR_ERR_UNIMPLEMENTED,
    SUIT_ERR_VERSION,
    SUIT_ERR_SIG,
    SUIT_ERROR_DIGEST_MISMATCH,
    SUIT_MFST_ERR_AUTH_MISSING,
    SUIT_MFST_ERR_MANIFEST_ENCODING,
    SUIT_MFST_UNSUPPORTED_ENTRY,
    SUIT_MFST_CONDITION_FAILED,
    SUIT_MFST_UNSUPPORTED_COMMAND,
    SUIT_MFST_UNSUPPORTED_ARGUMENT,
    SUIT_MFST_ERR_VENDOR_MISMATCH,
    SUIT_MFST_ERR_CLASS_MISMATCH,
    SUIT_ERR_PARAMETER_KEY,

};

typedef struct cbor_value_s {
    const uint8_t *cbor_start;
    union {
        uint64_t u64;
        int64_t i64;
        struct {
            const uint8_t *ptr;
            uint64_t length;
        } ref;
        uint8_t primitive;
    };
} cbor_value_t;

typedef struct suit_vars_s {
    const uint8_t *vendor_id;
    const uint8_t *class_id;
    const uint8_t *device_id;
    const uint8_t *uri;
    const uint8_t *encryption_info;
    const uint8_t *compression_info;
    const uint8_t *unpack_info;
    const uint8_t *source_component;
    const uint8_t *image_digest;
    const uint8_t *image_size;
    const uint8_t LAST[0];
} suit_vars_t;

typedef struct suit_parse_context_s {
    int64_t search_key;
    suit_vars_t vars[MAX_COMPONENTS];
    const uint8_t* outer;
    const uint8_t* auth;
    const uint8_t* inner;
    const uint8_t* common;
    const uint8_t* search_result;
    uint16_t outer_size;
    uint16_t common_size;
} suit_parse_context_t;

typedef PARSE_HANDLER((*suit_handler_t));

typedef struct cbor_keyed_parse_element_s {
    int  key:16;
    unsigned int resvd0:8;
    unsigned int type:3;
    unsigned int resvd1:2;
    unsigned int repeat:1;
    unsigned int choice:1;
    unsigned int null_opt:1;
    // Defined by cbor_type
    // int (*extractor)(void* ctx, const uint8_t **p, cbor_value_t *val, const uint8_t *end);
    suit_handler_t handler;
#ifdef PARSER_DEBUG
    const char* desc;
#endif
} cbor_keyed_parse_element_t;

int suit_do_process_manifest(const uint8_t *manifest, size_t manifest_size);
int suit_platform_do_run();
int suit_platform_verify_image(
    const uint8_t *component_id,
    int digest_type,
    const uint8_t* expected_digest,
    size_t image_size
);
int suit_platform_get_image_ref(
    const uint8_t *component_id,
    const uint8_t **image
);
int suit_platform_verify_sha256(
    const uint8_t *expected_digest,
    const uint8_t *data,
    size_t data_len);

int suit_get_seq(const uint8_t *manifest, size_t manifest_size, uint64_t *seqnum);
int do_cose_auth(
    const uint8_t *auth_buffer,
    const uint8_t *data, size_t data_size);
int cbor_check_type_extract_ref(
        const uint8_t **p,
        const uint8_t *end,
        cbor_value_t *o_val,
        const uint8_t cbor_type
);
int verify_suit_digest(
    const uint8_t *digest,
    const uint8_t *digest_end,
    const uint8_t *data,
    size_t data_len);

int cbor_skip(const uint8_t **p, const uint8_t *end);
#ifdef __cplusplus
}
#endif

#endif // _SUIT_PARSER_H_
