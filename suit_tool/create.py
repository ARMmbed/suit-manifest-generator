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
from suit_tool.compile import compile_manifest
from suit_tool.manifest import SUITEnvelope, SUITDigest
import binascii
import json
import cbor2 as cbor
import itertools
import textwrap
from collections import OrderedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def suit_mfst(mfst, options):
    digest = {
        'sha256' : hashes.Hash(hashes.SHA256(), backend=default_backend()),
        'sha384' : hashes.Hash(hashes.SHA384(), backend=default_backend()),
        'sha512' : hashes.Hash(hashes.SHA512(), backend=default_backend()),
    }.get('sha256')

    mfst_tmp = mfst.to_suit()
    digest.update(cbor.dumps(mfst_tmp[SUITEnvelope.fields['manifest'].suit_key]))
    mfst_tmp[SUITEnvelope.fields['auth'].suit_key] = cbor.dumps([
        cbor.dumps(SUITDigest().from_json({
            'algorithm-id' : 'sha256',
            'digest-bytes' : binascii.b2a_hex(digest.finalize()).decode('utf-8')
        }).to_suit(), canonical = True)
    ])

    mfst_envelope = cbor.dumps(mfst_tmp, canonical=True)
    return mfst_envelope

def main(options):
    m = json.loads(options.input_file.read(), object_pairs_hook=OrderedDict)

    nm = compile_manifest(options, m)
    print('create done. Serializing')
    if m.get('severable') or (hasattr(options, 'severable') and options.severable):
        nm = nm.to_severable('sha256')
    output = {
        'suit' : lambda x: suit_mfst(x,options),
        'suit-debug' : lambda x: '\n'.join(itertools.chain.from_iterable(
            map(textwrap.wrap, x.to_debug('').split('\n'))
        )).encode('utf-8'),
        'json' : lambda x : json.dumps(x.to_json(), indent=2).encode('utf-8')
    }.get(options.format)(nm)
    options.output_file.write(output)

    return 0
