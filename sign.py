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
"""
This is a demo script that is intended to act as a reference for SUIT manifest
signing.

NOTE: It is expected that C and C++ parser implementations will be written
against this script, so it does not adhere to PEP8 in order to maintain
similarity between the naming in this script and that of C/C++ implementations.
"""
import cbor
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Private key in arg 1
# Public key in arg 2
# Input file in arg 3
# Output file in arg 4

COSE_Sign_Tag = 98
APPLICATION_OCTET_STREAM_ID = 42
ES256 = -7

private_key = None
with open(sys.argv[1], 'rb') as fd:
    private_key = serialization.load_pem_private_key(fd.read(), password=None, backend=default_backend())

public_key = None
with open(sys.argv[2], 'rb') as fd:
    public_key = serialization.load_pem_public_key(fd.read(), backend=default_backend())

# Read the input file
doc = None
with open(sys.argv[3], 'rb') as fd:
    doc = fd.read()

# Check if the content is already a COSE_Sign_Tagged
isCOSE_Sign_Tagged = False
COSE_Sign = []
try:
    decodedDoc = cbor.loads(doc)
    if isinstance(decodedDoc, cbor.Tag) and decodedDoc.tag == COSE_Sign_Tag:
        isCOSE_Sign_Tagged = True
        COSE_Sign = decodedDoc.value
except:
    pass

if not isCOSE_Sign_Tagged:
    protected = cbor.dumps({
        3: APPLICATION_OCTET_STREAM_ID, # Content Type
    })
    unprotected = {
    }
    payload = doc
    signatures = []
    # Create a COSE_Sign_Tagged object
    COSE_Sign = [
        protected,
        unprotected,
        payload,
        signatures
    ]
# NOTE: Using RFC7093, Method 4
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(
    public_key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo))
kid = digest.finalize()
# Sign the payload
protected = cbor.dumps({
    1: ES256, # alg
    4: kid #kid
})

unprotected = {
}
Sig_structure = [
   "Signature", # Context
   COSE_Sign[0], # Body Protected
   protected, # signature protected
   b'', # External AAD
   COSE_Sign[2]
]

sig_str = cbor.dumps(Sig_structure)

signature = private_key.sign(
    sig_str,
    ec.ECDSA(hashes.SHA256())
)

COSE_Signature = [
    protected,
    unprotected,
    signature
]

COSE_Sign[3].append(COSE_Signature)

with open(sys.argv[4], 'wb') as fd:
    COSE_Sign_Tagged = cbor.Tag(98, COSE_Sign)
    fd.write(cbor.dumps(COSE_Sign_Tagged))
