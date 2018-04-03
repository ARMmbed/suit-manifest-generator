#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2018 Freie Universitat Berlin
# Copyright 2018 Inria
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
from pyasn1.type import univ
from pyasn1.type.namedtype import NamedType, NamedTypes

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
import base64

ASN1_ED25519_TYPE = '1.3.101.112'

COSE_KEY_TYPE = 1
COSE_KEY_TYPE_OKP = 1
COSE_KEY_CRV = -1
COSE_KEY_CRV_ED25519 = 6
COSE_KEY_ID = 2
COSE_KEY_PARAM_X = -2
COSE_KEY_PARAM_D = -4


class Identifier(univ.Sequence):
    componentType = NamedTypes(
        NamedType('type', univ.ObjectIdentifier())
    )


class PrivKeyContainer(univ.OctetString):
    pass


class EddsaPrivateKey(univ.Sequence):
    componentType = NamedTypes(
        NamedType('Version', univ.Integer()),
        NamedType('Type', Identifier()),
        NamedType('PrivateKey', univ.OctetString()),
    )


class EddsaPublicKey(univ.Sequence):
    componentType = NamedTypes(
        NamedType('Type', Identifier()),
        NamedType('PublicKey', univ.BitString())
    )


def get_skey(skey_container):
    container = skey_container['PrivateKey']
    private_key, _ = der_decoder(container, asn1Spec=PrivKeyContainer)
    return bytes(private_key)


def get_pkey(pkey_container):
    return bytes(pkey_container['PublicKey'].asOctets())


def set_skey(skey_container, skey):
    container = PrivKeyContainer(value=skey)
    skey_container['PrivateKey'] = der_encoder(container)


"""
Build an ASN.1 representation from a secret key
"""


def build_asn1privkey(sk):
    skey = EddsaPrivateKey()
    skey['Version'] = 0
    skey_id = Identifier()
    skey_id['type'] = ASN1_ED25519_TYPE
    skey['Type'] = skey_id
    set_skey(skey, sk.to_seed())
    return skey


"""
Build an ASN.1 representation from a public key
"""


def build_asn1pubkey(pk):
    pkey = EddsaPublicKey()
    pkey_id = Identifier()
    pkey_id['type'] = ASN1_ED25519_TYPE
    pkey['Type'] = pkey_id
    pkey['PublicKey'] = univ.BitString.fromOctetString(pk.to_bytes())
    return pkey


"""
Build a CBOR/COSE representation of a key pair
"""


def build_cbor_privkey(skey, pkey=None, key_id=None):
    skey_cose = {COSE_KEY_TYPE: COSE_KEY_TYPE_OKP,
                 COSE_KEY_CRV: COSE_KEY_CRV_ED25519,
                 COSE_KEY_PARAM_D: skey.to_seed()
                 }
    if pkey:
        skey_cose[COSE_KEY_PARAM_X] = pkey.to_bytes()
    if key_id:
        skey_cose[COSE_KEY_ID] = key_id.encode('utf-8')
    return cbor.dumps(skey_cose)


def build_cbor_pubkey(pkey=None, key_id=None):
    pkey_cose = {COSE_KEY_TYPE: COSE_KEY_TYPE_OKP,
                 COSE_KEY_CRV: COSE_KEY_CRV_ED25519,
                 COSE_KEY_PARAM_X: pkey.to_bytes()
                 }
    if key_id:
        pkey_cose[COSE_KEY_ID] = key_id.encode('utf-8')
    return cbor.dumps(pkey_cose)


def parse_privkey(skey):
    if skey.startswith(b"-----BEGIN PRIVATE KEY-----"):
        pem_input = skey.decode('ascii')
        skey = base64.b64decode(''.join(pem_input.splitlines()[1:-1]))
    keys_input, _ = der_decoder(skey, asn1Spec=EddsaPrivateKey())
    return get_skey(keys_input)


def parse_pubkey(pkey):
    if pkey.startswith(b"-----BEGIN PUBLIC KEY-----"):
        pem_input = pkey.decode('ascii')
        pkey = base64.b64decode(''.join(pem_input.splitlines()[1:-1]))
    keys_input, _ = der_decoder(pkey, asn1Spec=EddsaPublicKey())
    return get_pkey(keys_input)
