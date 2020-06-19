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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>

#include "mbed.h"

#include "bootloader_platform.h"
#include "bootloader_common.h"
#include "mbed_application.h"
#include "suit_bootloader.h"

const uint8_t vendor_id[16] = {
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe
};
const uint8_t class_id[16] = {
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45
};

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

const entrypoint_t entrypoints[] = {
    {
        SUIT_BOOTLOADER_SLOT_A_OFFSET + SUIT_BOOTLOADER_HEADER_SIZE,
        SUIT_BOOTLOADER_SLOT_A_OFFSET
    },
    {
        SUIT_BOOTLOADER_SLOT_B_OFFSET + SUIT_BOOTLOADER_HEADER_SIZE,
        SUIT_BOOTLOADER_SLOT_B_OFFSET
    }
};
const size_t n_entrypoints = ARRAY_SIZE(entrypoints);


int main(void)
{

    /*************************************************************************/
    /* Print bootloader information                                          */
    /*************************************************************************/

    boot_debug("\r\n"
    "          __----'''----__\r\n"
    "         /  ``--._.--''  \\ \r\n"
    "  _..---`-._    / \\    _.-'---.._ \r\n"
    ".'      \\   `-./\\_/\\.-'   /      '.\r\n"
    "|        \\      / \\      /        |\r\n"
    "|         \\    |   |    /   .     |\r\n"
    "|          \\   |   |   /   /_\\    |\r\n"
    "|           \\  |   |  /           |\r\n"
    "|            \\ |   | /            |\r\n"
    "|     SUIT    \\|   |/    LOADER   |\r\n"
    "|              \\   /              |\r\n"
    "|               \\ /               |\r\n"
    "|                '                |\r\n"
    "\r\n");

#if MBED_CONF_MBED_TRACE_ENABLE
    mbed_trace_init();
    mbed_trace_print_function_set(boot_debug);
#endif // MBED_CONF_MBED_TRACE_ENABLE

#if MBED_CONF_MBED_BOOTLOADER_STARTUP_DELAY
    ThisThread::sleep_for(MBED_CONF_MBED_BOOTLOADER_STARTUP_DELAY);
#endif // MBED_CONF_MBED_BOOTLOADER_STARTUP_DELAY

    /*************************************************************************/
    /* Choose and execute a SUIT manifest                                    */
    /*************************************************************************/

    int rc = suit_bootloader();

    boot_debug("Failed to jump to application!\r\n");
    return -1;
}
