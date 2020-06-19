#!/usr/bin/env sh
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2020 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------
set -e
set -x

SUIT_TOOL=`python3 -c "import os; print(os.path.realpath('../bin/suit-tool'))"`

pushd suitloader
mbed compile
popd

pushd suit-app
echo "slot_b/*" > .mbedignore
cp slot_a_app_info.h app_info.h
mbed compile --app-config slot-a-config.json --build slot_a

python3 $SUIT_TOOL create -i slot-a-manifest.json -o slot_a/manifest.cbor
python3 $SUIT_TOOL sign -m slot_a/manifest.cbor -k ./private_key.pem -o slot_a/signed-manifest.cbor

echo "slot_a/*" > .mbedignore
cp slot_b_app_info.h app_info.h
mbed compile --app-config slot-b-config.json --build slot_b
python3 $SUIT_TOOL create -i slot-b-manifest.json -o slot_b/manifest.cbor
python3 $SUIT_TOOL sign -m slot_b/manifest.cbor -k ./private_key.pem -o slot_b/signed-manifest.cbor
popd

srec_cat -Output suit_merged.hex -Intel -obs=16 \
    ./suitloader/BUILD/NRF52840_DK/GCC_ARM/suitloader.hex -Intel \
    ./suit-app/slot_a/suit-app.hex -Intel \
    ./suit-app/slot_a/signed-manifest.cbor -Binary -offset 0x8000 \
    ./suit-app/slot_b/suit-app.hex -Intel \
    ./suit-app/slot_b/signed-manifest.cbor -Binary -offset 0x84000
