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
