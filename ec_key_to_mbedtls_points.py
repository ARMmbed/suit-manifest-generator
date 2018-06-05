#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2018 ARM Limited or its affiliates
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
'''
Converts a ECDSA PEM public key to the format needed by libcose + mbedtls

Invoke with: 'ec_key_to_mbedtls_points.py pubkey.pem'
'''
import sys
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

MBEDTLS_ECP_MAX_BYTES = 66
HEX_VALUES_PER_LINE = 12

keystr = None
with open(sys.argv[1], 'rb') as fd:
    keystr = fd.read()

key = load_pem_public_key(keystr, backend=default_backend())

xa = ['0x%02x'% x for x in binascii.a2b_hex(('%%0%dx'%(2*MBEDTLS_ECP_MAX_BYTES))%key.public_numbers().x)]
ya = ['0x%02x'% x for x in binascii.a2b_hex(('%%0%dx'%(2*MBEDTLS_ECP_MAX_BYTES))%key.public_numbers().y)]

print('const unsigned char mbedtls_ec_public_key_x [MBEDTLS_ECP_MAX_BYTES] = {')
while xa:
    print('    ' + ', '.join(xa[:HEX_VALUES_PER_LINE]) + ',')
    xa = xa[HEX_VALUES_PER_LINE:]
print('};')

print('const unsigned char mbedtls_ec_public_key_y [MBEDTLS_ECP_MAX_BYTES] = {')
while ya:
    print('    ' + ', '.join(ya[:HEX_VALUES_PER_LINE]) + ',')
    ya = ya[HEX_VALUES_PER_LINE:]
print('};')
