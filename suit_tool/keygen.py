# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2019-2020 ARM Limited or its affiliates
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_utils
from cryptography.hazmat.primitives import serialization as ks


import logging
import binascii
LOG = logging.getLogger(__name__)

def main(options):
    # Read the manifest wrapper
    private_key = {
        'secp256r1' : lambda : ec.generate_private_key(ec.SECP256R1(), default_backend()),
        'secp384r1' : lambda : ec.generate_private_key(ec.SECP384R1(), default_backend()),
        'secp521r1' : lambda : ec.generate_private_key(ec.SECP521R1(), default_backend()),
        'ed25519' : lambda : ed25519.Ed25519PrivateKey.generate(),
    }.get(options.type) ()


    options.output_file.write(private_key.private_bytes(ks.Encoding.DER,
        ks.PrivateFormat.PKCS8, ks.NoEncryption()))
    return 0
