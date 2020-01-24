// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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

#ifndef BOOTLOADER_COMMON_H
#define BOOTLOADER_COMMON_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIZEOF_SHA256  (256/8)

#ifndef BUFFER_SIZE
#define BUFFER_SIZE (16 * 1024)
#endif

#define CLEAR_EVENT 0xFFFFFFFF

enum {
    RESULT_SUCCESS,
    RESULT_ERROR,
    RESULT_EMPTY
};

extern uint8_t buffer_array[BUFFER_SIZE];

extern uint32_t event_callback;
extern const char hexTable[16];

void arm_ucp_event_handler(uint32_t event);

void boot_debug(const char *s);

#define MBED_BOOTLOADER_ASSERT(condition, ...) { \
    if (!(condition)) {                          \
        boot_debug("[ERR ] ASSERT\r\n");                   \
        /* coverity[no_escape] */                \
        while (1) __WFI();                       \
    }                                            \
}

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_COMMON_H
