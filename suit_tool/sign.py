#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2019 ARM Limited or its affiliates
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
import cbor
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils as asymmetric_utils
from cryptography.hazmat.primitives import serialization as ks


from suit_tool.manifest import COSE_Sign1, COSEList, SUITDigest,\
                               SUITWrapper, SUITBytes, SUITBWrapField
import logging
import binascii
LOG = logging.getLogger(__name__)

def main(options):
    # Read the manifest wrapper
    wrapper = cbor.loads(options.manifest.read())
    private_key = ks.load_pem_private_key(options.private_key.read(), password=None, backend=default_backend())

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(cbor.dumps(wrapper[SUITWrapper.fields['manifest'].suit_key]))

    cose_signature = COSE_Sign1().from_json({
        'protected' : {
            'alg' : 'ES256'
        },
        'unprotected' : {},
        'payload' : {
            'algorithm-id' : 'sha256',
            'digest-bytes' : binascii.b2a_hex(digest.finalize())
        }
    })

    Sig_structure = cbor.dumps([
        "Signature1",
        cose_signature.protected.to_suit(),
        b'',
        cose_signature.payload.to_suit(),
    ], sort_keys = True)
    sig_val = cbor.dumps(Sig_structure, sort_keys = True)
    LOG.debug('Signing: {}'.format(binascii.b2a_hex(sig_val).decode('utf-8')))


    ASN1_signature = private_key.sign(sig_val, ec.ECDSA(hashes.SHA256()))
    r,s = asymmetric_utils.decode_dss_signature(ASN1_signature)
    signature_bytes = r.to_bytes(256//8, byteorder='big') + s.to_bytes(256//8, byteorder='big')

    cose_signature.signature = SUITBytes().from_suit(signature_bytes)

    auth = SUITBWrapField(COSEList)().from_json([{
        'COSE_Sign1_Tagged' : cose_signature.to_json()
    }])

    wrapper[SUITWrapper.fields['auth'].suit_key] = auth.to_suit()

    options.output_file.write(cbor.dumps(wrapper, sort_keys=True))
    return 0
