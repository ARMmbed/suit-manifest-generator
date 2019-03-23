#!/usr/bin/env python3
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
'''
Creates a manifest from the following JSON shorthand
JSON format:
{
    "digest-type" : "sha-256",
    "structure-version" : 1,
    "sequence-number" : 2,
    "components": [
        {
            "component-id":["hex/base64/text"],
            "bootable" : bool(),
            "images" : [
                {
                    "file"   : "path/to/image/file",
                    "digest" : "<hex digest>",
                    "size"   : <size of image>,
                    "uri"    : "http://path.to/file.bin",
                    "conditions" : [
                        {"component-offset": <offset of storage location>}
                    ]
                }
            ],
            "conditions" : []
        }
    ],
    "conditions" : [
        {"vendor-id" : "uuid"},
        {"class-id"  : "uuid"}
    ]
}
'''

import json
import cbor
import binascii
import copy
import sys
import os

from suit_manifest_encoder_04 import compile_to_suit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def read_file_chunked(options, fd):
    data = fd.read(options['chunk-size'])
    while data:
        yield data
        data = fd.read(options['chunk-size'])

def hash_file(options, fname):
    if not options.get('digest-type', None):
        options['digest-type']='sha-256'
    md = {
        'sha-256' : hashes.Hash(hashes.SHA256(), backend=default_backend())
    }.get(options['digest-type'], None)

    if not options.get('chunk-size', None):
        options['chunk-size']=4096
    with open(fname,'rb') as fd:
        for chunk in read_file_chunked(options, fd):
            md.update(chunk)
    return md.finalize()

def size_file(options, fname):
    return os.path.getsize(fname)

def component_id_to_indoc(jdoc):
    indoc = []
    for c in jdoc:
        try:
            c = binascii.a2b_hex(c)
        except:
            try:
                c = binascii.a2b_base64(c)
            except:
                pass
        indoc.append(c)
    return indoc

def json_image_to_indoc(jdoc):
    indoc = {}
    if 'file' in jdoc:
        indoc['digest'] = hash_file({}, jdoc['file'])
        indoc['size'] = size_file({}, jdoc['file'])
    else:
        indoc['digest'] = binascii.a2b_hex(jdoc['digest'])
        indoc['size'] = jdoc['size']
    if 'uri' in jdoc:
        indoc['uri'] = jdoc['uri']
    if 'conditions' in jdoc:
        conditions = []
        for cond in jdoc['conditions']:
            conditions.append(json_condition_to_indoc(cond))
        indoc['conditions'] = conditions
    return indoc

def json_component_to_indoc(jdoc):
    indoc = {
        'id': component_id_to_indoc(jdoc['component-id'])
    }
    if 'bootable' in jdoc:
        indoc['bootable'] = jdoc['bootable']
    indoc['images'] = []
    for image in jdoc['images']:
        indoc['images'].append(json_image_to_indoc(image))
    return indoc

def json_condition_to_indoc(jdoc):
    indoc = {}
    for k,v in jdoc.items():
        if k is 'condition-vendor-id' or k is 'condition-class-id':
            indoc[k] = uuid.UUID(v).bytes
        else:
            indoc[k] = v
    return indoc

def json_to_indoc(s):
    jdoc = json.loads(s)
    indoc = {
        'digest-type' : jdoc.get('digest-type', 'sha-256'),
        'structure-version': jdoc.get('structure-version', 1)
    }
    if 'sequence-number' not in jdoc:
        raise Exception('sequence-number is a required top-level element')
    indoc['sequence-number'] = jdoc['sequence-number']

    indoc['components'] = []
    for component in jdoc['components']:
        indoc['components'].append(json_component_to_indoc(component))
    indoc['conditions'] = []
    for condition in jdoc['conditions']:
        indoc['conditions'].append(json_condition_to_indoc(condition))
    return indoc



def main():
    s = None
    with open(sys.argv[1],'r') as fd:
        s = fd.read()
    indoc = json_to_indoc(s)
    o_cbor = compile_to_suit(indoc)

    with open(sys.argv[2], 'wb') as fd:
        fd.write(o_cbor)


if __name__ == '__main__':
    main()
