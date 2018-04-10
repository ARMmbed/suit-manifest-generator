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


import argparse

import ed25519
import cbor
import pyasn1
import binascii
import base64

import eddsa

from pyasn1.type import univ
from pyasn1.type.namedtype import NamedType, NamedTypes

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
import base64

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--infile',
                        type=argparse.FileType('rb'),
                        help='Input private or combined key file to read from '
                        'instead of generating new keys')
    parser.add_argument('-I', '--inform',
                        choices=['cose', 'pem', 'der'],
                        default='der',
                        help='Input key file to read instead of generating'
                        ' new keys')
    parser.add_argument('-f', '--outform',
                        choices=['cose', 'pem', 'der'],
                        default='der',
                        help='Specify the output format, pem or der encoded '
                        'asn1 or COSE signer struct'
                        )
    parser.add_argument('-k', '--keyid',
                        default=None,
                        help="Key id to add to the COSE signer struct",
                        )
    parser.add_argument('skey',
                        type=argparse.FileType('wb'),
                        help="File to store the private key in")
    parser.add_argument('pkey',
                        nargs='?',
                        type=argparse.FileType('wb'),
                        help='File to store the public key in, if none, it is'
                        'combined in the private key')
    args = parser.parse_args()
    public_available = False
    private_available = False

    if args.infile:
        input_bytes = args.infile.read()
        if args.inform == 'cose':
            try:
                data = cbor.loads(input_bytes)
            except:
                print("Unable to load COSE key from file")
                exit(1)
            if eddsa.COSE_KEY_CRV not in data or data[eddsa.COSE_KEY_CRV] != eddsa.COSE_KEY_CRV_ED25519:
                print("No key curve found or wrong curve type in input")
                exit(1)
            try:
                sk = ed25519.SigningKey(data[eddsa.COSE_KEY_PARAM_D])
                private_available = True
            except ValueError:
                sk = None
            try:
                pk = ed25519.VerifyingKey(data[eddsa.COSE_KEY_PARAM_X])
                public_available = True
            except ValueError:
                pk = None
            try:
                keyid = data[eddsa.COSE_KEY_ID]
            except:
                keyid = None
        if args.inform == 'der' or args.inform == 'pem':
            if args.inform == 'pem':
                input_bytes = base64.b64decode(''.join(input_bytes.splitlines()[1:-1]))
            sk = parse_privkey(input_bytes)
            private_available = True
    else:
        # Generating new keys
        sk, pk = ed25519.create_keypair()
        public_available = True
        private_available = True

    # Reading input done, converting to output format
    if not public_available and not private_key:
        print("missing both public and private key, exiting")
        exit(1)
    if not public_available:
        print("No public key available, only writing private key")
    if not private_available:
        print("No private key available, only writing public key")

    if args.outform == 'der' or args.outform == 'pem':
        if public_available:
            pkey = eddsa.build_asn1pubkey(pk)
            pkey_asn1 = eddsa.der_encoder(pkey)
        if private_available:
            skey = eddsa.build_asn1privkey(sk)
            skey_asn1 = der_encoder(skey)

        if args.outform == 'der':
            if private_available:
                skey_output = skey_asn1
            if public_available:
                pkey_output = pkey_asn1
        elif args.outform == 'pem':
            if private_available:
                skey_output = '-----BEGIN PRIVATE KEY-----\n'.encode('ascii')
                skey_output += base64.b64encode(skey_asn1)
                skey_output += '\n-----END PRIVATE KEY-----\n'.encode('ascii')
            if public_available:
                pkey_output = '-----BEGIN PUBLIC KEY-----\n'.encode('ascii')
                pkey_output += base64.b64encode(pkey_asn1)
                pkey_output += '\n-----END PUBLIC KEY-----\n'.encode('ascii')
        if private_available:
            args.skey.write(skey_output)
        if public_available:
            args.pkey.write(pkey_output)
    elif args.outform == 'cose':
        if args.pkey:
            skey_output = eddsa.build_cbor_privkey(sk, key_id=args.keyid)
            pkey_output = eddsa.build_cbor_pubkey(pk, key_id=args.keyid)
            args.skey.write(skey_output)
            args.pkey.write(pkey_output)
        else:
            if not private_available:
                print("No private key available to write, aborting")
                exit(1)
            else:
                skey_output = eddsa.build_cbor_privkey(sk, pk, key_id=args.keyid)
                args.skey.write(skey_output)
