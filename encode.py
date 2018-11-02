#!/usr/bin/env python3
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
Creates a manifest from the following JSON shorthand
JSON format:
{
    sequence = x                 # Number
    conditions = []              # Vendor, class, device ID supported
    text = {}                    # Only 'updateDescription' supported
    payloads = [
        {
            component = [],      # ComponentIdentifier
            payloadFormat = x,   # raw or gzip
            payloadURI = x,      # text URI
            payloadFile = x      # path to payload
        }
    ]
}
'''

import json
import cbor
import binascii
import copy
import sys

from suit_manifest_encoder import OuterWrapper

def Processors_RawRemote(uri):
    return [{
        'id' : [1,1],
        'inputs' : [ 0, uri ]
    }]
def Processors_gzipRemote(uri):
    return [{
        'id' : [1,1],
        'inputs' : [ 0, uri ]
    },
    {
        'id' : [3,1],
        'inputs' : {0 : 0}
    }]

def json_payloads_to_indoc(j):
    installInfos = []
    payloads = []
    for p in j:
        install = {}
        payload = p.copy()
        payloads.append(payload)
        install['component'] = p['component']
        install['processors'] = {
            'raw' : Processors_RawRemote,
            'gzip' : Processors_gzipRemote
        }.get(p['payloadFormat'])(p['payloadURI'])
        installInfos.append(install)

    indoc = {
        'payloads' : payloads,
        'install' : {'payloadInstallInfos' : installInfos}
    }
    return indoc

def json_to_indoc(s):
    indoc = {
        'manifestVersion' : 1
    }
    jdoc = json.loads(s)
    indoc['sequence'] = jdoc['sequence']
    if 'conditions' in jdoc:
        if not 'preInstall' in indoc:
            indoc['preInstall'] = {}
        if not 'preConditions' in indoc['preInstall']:
            indoc['preInstall']['preConditions'] = []
        indoc['preInstall']['preConditions'] = copy.deepcopy(jdoc['conditions'])

    if 'payloads' in jdoc:
        indoc.update(json_payloads_to_indoc(jdoc['payloads']))

    if 'text' in jdoc:
        indoc['text'] = jdoc['text'].copy()

    return indoc



def main():
    s = None
    with open(sys.argv[1],'r') as fd:
        s = fd.read()
    indoc = json_to_indoc(s)

    o = OuterWrapper(indoc).to_pod()
    o_cbor = cbor.dumps(o, sort_keys=True)

    with open(sys.argv[2], 'wb') as fd:
        fd.write(o_cbor)


if __name__ == '__main__':
    main()
