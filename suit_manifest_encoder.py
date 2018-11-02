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
import json
import cbor
import binascii
import uuid
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

COSE_ALG = 1
COSE_Sign_Tag = 98
APPLICATION_OCTET_STREAM_ID = 42
ES256 = -7
EDDSA = -8

class Dependencies:
    def __init__(self, data):
        pass
    def to_pod(self):
        return None

class CDDLStruct:
    podList = []
    keyMap = {}
    structMap = {}

    def __init__(self, data):
        self.init_func(data)
    def init_func(self, data):
        self.data_dict = {}
        for k in self.podList:
            if k in data:
                self.data_dict[k] = data[k]
        for k, c in self.structMap.items():
            if k in data:
                self.data_dict[k] = c(data[k])
    def to_pod(self):
        data_pod = {}
        for k, v in self.keyMap.items():
            if k in self.data_dict:
                if isinstance(self.data_dict[k], (int, str, bytes, list, dict)):
                    data_pod[v] = self.data_dict[k]
                else:
                    data_pod[v] = self.data_dict[k].to_pod()
        return data_pod

class CDDLArray:
    def __init__(self, data):
        self._elements = [ self.ElementClass(e) for e in data]

    def to_pod(self):
        return [ e.to_pod() for e in self._elements]

class CDDLList:
    podList = []
    keyMap = {}
    structMap = {}
    def __init__(self, data):
        self.init_func(data)

    def init_func(self, data):
        self.data_dict = {}
        for k in self.podList:
            if self.keyMap[k] < len(data):
                self.data_dict[k] = data[self.keyMap[k]]
        for k, c in self.structMap.items():
            if self.keyMap[k] < len(data):
                self.data_dict[k] = c(data[self.keyMap[k]])

    def to_pod(self):
        data_pod = [ None for x in range(max(self.keyMap.values())+1)]
        for k, v in self.keyMap.items():
            if k in self.data_dict:
                if isinstance(self.data_dict[k], (int, str, bytes, list, dict)):
                    data_pod[v] = self.data_dict[k]
                else:
                    data_pod[v] = self.data_dict[k].to_pod()
        return data_pod

class ByteString:
    def __init__(self, data):
        # Is it bytes?
        if isinstance(data, bytes):
            self.pod = data
        else:
            # Is it hex?
            try:
                self.pod = binascii.a2b_hex(data)
            except:
                # Is it base64?
                try:
                    self.pod = binascii.a2b_base64(data)
                except:
                    # It must be text.
                    self.pod = data.encode('utf-8')
    def to_pod(self):
        return self.pod

class ComponentIdentifier(CDDLArray):
    ElementClass = ByteString

class COSE_Digest:
    algMap = {
        'sha-256': (41, lambda : hashes.Hash(hashes.SHA256(), backend=default_backend()))
    }
    def __init__(self, alg, payload):
        algNum, algFunc = self.algMap[alg]
        protected = cbor.dumps({COSE_ALG : algNum}, sort_keys=True)
        unprotected = {}

        Digest_structure = [
            "Digest",
            protected,
            unprotected,
            b'',
            bytes(payload)
        ]
        h = algFunc()
        h.update(cbor.dumps(Digest_structure, sort_keys=True))
        digest = h.finalize()
        self.pod = [
            protected,
            unprotected,
            None,
            digest
        ]

    def to_pod(self):
        return self.pod

class Processor(CDDLStruct):
    keyMap = {
        'id' : 1,
        'parameters' : 2,
        'inputs': 3
    }
    podList = ['id', 'parameters', 'inputs']

class Processors(CDDLArray):
    ElementClass = Processor

class Payload(CDDLStruct):
    keyMap = {
        'component' : 1,
        'payloadSize'      : 2,
        'payloadDigest'    : 3,
    }
    structMap = {
        'component' : ComponentIdentifier
    }
    podList = ['payloadSize']
    def __init__(self, data):
        self.init_func(data)

        if not 'payloadSize' in self.data_dict:
            if 'payload' in data:
                self.data_dict['payloadSize'] = len(data['payload'])
                payload = data['payload']
                self.data_dict['payloadDigest'] = COSE_Digest('sha-256', payload)
            if 'payloadFile' in data:
                self.data_dict['payloadSize'] = os.path.getsize(data['payloadFile'])
                with open(data['payloadFile'], 'rb') as fd:
                    self.data_dict['payloadDigest'] = COSE_Digest('sha-256', fd.read())

class Payloads:
    def __init__(self, data):
        self._payloads = [ Payload(p) for p in data]

    def to_pod(self):
        return [ p.to_pod() for p in self._payloads]


class UUIDParser:
    def __init__(self, data):
        self.uuid = uuid.UUID(data)
    def to_pod(self):
        return self.uuid.bytes

class IdCondition(CDDLList):
    keyMap = {
        'type': 0,
        'id' : 1
    }
    podList = ['type']
    structMap = {'id':UUIDParser}

class VendorIdCondition(IdCondition):
    pass
class ClassIdCondition(IdCondition):
    pass
class DeviceIdCondition(IdCondition):
    pass

class Condition:
    def __init__(self, data):
        self.subclass = None
        subclassType, subclassId = {
            'vendorId' : (VendorIdCondition, 1),
            'classId' : (ClassIdCondition, 2),
            'deviceId' : (DeviceIdCondition, 3),
        }.get(data[0])
        condData = [subclassId] + data[1:]
        self.subclass = subclassType(condData)

    def to_pod(self):
        return self.subclass.to_pod()

class PreCondition(Condition):
    pass


class PreConditions(CDDLArray):
    ElementClass = PreCondition

class PreInstallationInfo(CDDLStruct):
    keyMap = {
        'preConditions' : 1,
        # 'preDirectives' : 2,
    }
    structMap = {
        'preConditions' : PreConditions,
        # 'preDirectives' : PreDirectives,
     }


class PayloadInstallationInfo(CDDLStruct):
    keyMap = {
        'component' : 1,
        'processors' : 2,
        'allowOverride' : 3,
        'payloadInstaller' : 4,
        'payloadInstallerID' : 5,
        'payloadInstallerParameters' : 6,
    }
    structMap = {
        'component' : ComponentIdentifier,
        'processors' : Processors,
    }
    podList = ['allowOverride']

class PayloadInstallationInfos(CDDLArray):
    ElementClass = PayloadInstallationInfo

class InstallationInfo(CDDLStruct):
    keyMap = {
        'payloadInstallInfos' : 1
    }
    structMap = {
        'payloadInstallInfos' : PayloadInstallationInfos
    }

class TextInfo(CDDLStruct):
    keyMap = {
        'updateDescription' : 1
    }
    podList = ['updateDescription']

class Manifest(CDDLStruct):
    keyMap = {
        'manifestVersion' : 1,
        'sequence'        : 2,
        'preInstall'      : 3,
        'dependencies'    : 4,
        'payloads'        : 5,
        'install'         : 6,
        'postInstall'     : 7,
        'text'            : 8,
        'coswid'          : 9
    }
    structMap = {'dependencies':Dependencies,
                 'payloads':Payloads}
    podList = ['manifestVersion', 'sequence']
    refMap = {
        'preInstall' : PreInstallationInfo,
        'install' : InstallationInfo,
        'text': TextInfo,
    }
    refKeyMap = {
        'preInstall' : 3,
        'install' : 4,
        'postInstall' : 5,
        'text' : 6,
        'coswid' : 7,
    }
    def __init__(self, data):
        self.init_func(data)
        for k, c in self.refMap.items():
            if k in data:
                self.data_dict[k] = c(data[k])
                pod = self.data_dict[k].to_pod()
                cbor_payload = cbor.dumps(pod, sort_keys=True)
                cbor_payload_bstr = cbor.dumps(cbor_payload, sort_keys=True)
                self.data_dict[k+'Ref'] = COSE_Digest('sha-256', cbor_payload_bstr)
    def to_pod(self):
        data_pod = super(Manifest, self).to_pod()
        pod = {1 : None}
        for r in self.refKeyMap:
            if r in self.data_dict:
                cbor_element = cbor.dumps(self.data_dict[r].to_pod(), sort_keys=True)
                cbor_digest = cbor.dumps(self.data_dict[r + 'Ref'].to_pod(), sort_keys=True)
                if len(cbor_element) < len(cbor_digest):
                    data_pod[self.keyMap[r]] = self.data_dict[r].to_pod()
                else:
                    data_pod[self.keyMap[r]] = self.data_dict[r + 'Ref'].to_pod()
                    pod[self.refKeyMap[r]] = cbor_element
        pod[2] = cbor.dumps(data_pod, sort_keys=True)
        return pod


class OuterWrapper:
    def __init__(self, data):
        self.Manifest = Manifest(data)
        self.auth = None

    def sign(self, key):
        pod = self.to_pod()

    def to_pod(self):
        pod = self.Manifest.to_pod()

        return pod
