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
#ifndef _BOOTLOADER_H_
#define _BOOTLOADER_H_

#include <stddef.h>
#include <stdint.h>

#define MANIFEST_MAX_SIZE 1024

#ifdef __cplusplus
extern "C" {
#endif

typedef struct entrypoint_s {
    const uintptr_t app_offset;
    const uintptr_t manifest;
} entrypoint_t;

extern const uint8_t public_key[];
extern const uint8_t class_id[16];
extern const uint8_t vendor_id[16];
extern const entrypoint_t entrypoints [];
extern const size_t n_entrypoints;
int suit_bootloader();

#ifdef __cplusplus
} // extern "C"
#endif

#endif // _BOOTLOADER_H_
