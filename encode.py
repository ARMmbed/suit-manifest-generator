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
import cbor
import os
import time
import binascii
import json
import uuid
import sys
from builtins import bytes

# armUUID = uuid.uuid5(uuid.NAMESPACE_DNS, 'arm.com')
# print(armUUID)
# armSuitDeviceUUID = uuid.uuid5(armUUID, 'suit')
# print(armSuitDeviceUUID)
jsonDoc = None
with open(sys.argv[1]) as fd:
    jsonDoc = json.load(fd)

def guessBinFormat(s):
    if isinstance(s,bytes):
        return s
    binval = None
    try:
        binval = binascii.a2b_hex(s)
    except:
        try:
            binval = binascii.a2b_base64(s)
        except:
            binval = s.encode('utf-8')
    return binval

# Convert/validate the binary elements that were loaded from JSON
if 'conditions' in jsonDoc:
    conditions = jsonDoc['conditions']
    if 'vendorId' in conditions:
        conditions['vendorId'] = uuid.UUID(conditions['vendorId']).bytes
    if 'classId' in conditions:
        conditions['classId'] = uuid.UUID(conditions['classId']).bytes

if 'payloadInfo' in jsonDoc:
    if 'digests' in jsonDoc['payloadInfo']:
        for k,v in jsonDoc['payloadInfo']['digests'].items():
            # Try to guess the encoding
            jsonDoc['payloadInfo']['digests'][k] = guessBinFormat(v)

indoc = jsonDoc

LatestManifestVersion = 2
COSE_Encrypt_Tag = 96

TextFields = {
    'manifestDescription' : 1,
    'payloadDescription' : 2,
    'vendor' : 3,
    'model' : 4
}

ConditionTypes = {
    'vendorId' : 1,
    'classId' : 2,
    'deviceId' : 3,
    'bestBefore' : 4
}

DirectiveTypes = {
    'applyImmediately' : 1,
    'applyAfter' : 2
}

PayloadFormatTypes = {
    'binary' : 1,
    'hex' : 2
}

PayloadDigestAlgorithmTypes = {
    'SHA-256' : 1,
    'SHA-384' : 2,
    'SHA-512' : 3,
}

PayloadDigestTypes = {
    'raw' : 1,
    'installed' : 2,
    'ciphertext' : 3,
    'pre-image' : 4
}

def getManifestVersion(doc) :
    return doc.get('manifestFormatVersion', LatestManifestVersion)

def getTextObj(doc):
    if not 'text' in doc:
        return None
    fields = {}
    for k,v in doc['text'].items():
        if not k in TextFields:
            raise ValueError('%r is not a valid text field', k)
        if TextFields[k] in fields:
            raise ValueError('%r must be unique in text fields', k)
        # Text fields are intentionally freeform. No validation needed.
        fields[TextFields[k]] = str(v)
    return fields

def getNonce(doc):
    return guessBinFormat(doc.get('nonce', os.urandom(16)))

def getTimestamp(doc):
    return doc.get('timestamp', int(time.time()))

def getConditions(doc):
    if not 'conditions' in doc:
        return []
    conditions = []
    for k,v in doc['conditions'].items():
        if not k in ConditionTypes:
            raise ValueError('Unrecognized condition type: %r'% k)
        # TODO: Condition validation
        conditions.append([ConditionTypes[k], guessBinFormat(v)])
    return conditions

def getDirectives(doc):
    if not 'directives' in doc:
        return None
    directives = []
    for k,v in doc['directives'].items():
        if not k in DirectiveTypes:
            raise ValueError('Unrecognized directive type: %r' % k)
        # TODO: Directive Validation
        directives.append([DirectiveTypes[k], guessBinFormat(v)])
    return directives

def getAliases(doc):
    pass
def getDependencies(doc):
    pass
def getExtensions(doc):
    pass
def getPayloadFormat(payloadInfo):
    if not 'format' in payloadInfo:
        raise ValueError('format is a required element of payloadInfo')
    payloadInfo_format = payloadInfo['format']
    formatType = None
    formatParams = None
    if isinstance(payloadInfo_format, str):
        if not payloadInfo_format in PayloadFormatTypes:
            raise ValueError('%r is not a recognized payload format'%payloadInfo_format)
        formatType = PayloadFormatTypes[payloadInfo_format]
    elif isinstance(payloadInfo_format, dict):
        if not 'type' in payloadInfo_format:
            raise ValueError('If payload format is a map, type is required.')
        if not payloadInfo_format['type'] in PayloadFormatTypes:
            raise ValueError('%r is not a recognized payload format'%payloadInfo_format['type'])
        formatType = PayloadFormatTypes[payloadInfo_format['type']]
        formatParams = payloadInfo_format.get('params', None)
    else:
        raise ValueError('No payload format found in payloadInfo')

    payloadFormat = [
        formatType
    ]
    if formatParams:
        payloadFormat.append(guessBinFormat(formatParams))
    return payloadFormat
def getPayloadSize(payloadInfo):
    if not 'size' in payloadInfo:
        raise ValueError('size is required in payloadInfo')
    return int(payloadInfo['size'])
def getPayloadStorageId(payloadInfo):
    if not 'storageId' in payloadInfo:
        raise ValueError('storageId is required in payloadInfo')
    return guessBinFormat(payloadInfo['storageId'])
def getPayloadURIs(payloadInfo):
    if not 'uris' in payloadInfo:
        return None
    docUris = payloadInfo['uris']
    if len(docUris) == 0:
        return None
    uris = []
    for uri in docUris:
        if not isinstance(uri,dict):
            raise ValueError('URI entries in the payloadInfo uris field must be maps')
        uris.append([str(uri['uri']),int(uri['rank'])])
    return uris
def getPayloadDigestAlgorithm(payloadInfo):
    if not 'digestAlgorithm' in payloadInfo:
        return None
    payloadInfo_dgstAlg = payloadInfo['digestAlgorithm']
    dgstType = None
    dgstParams = None
    if isinstance(payloadInfo_dgstAlg, str):
        if not payloadInfo_dgstAlg in PayloadDigestAlgorithmTypes:
            raise ValueError('%r is not a recognized digest algorithm'% payloadInfo_dgstAlg)
        dgstType = PayloadDigestAlgorithmTypes[payloadInfo_dgstAlg]
    elif isinstance(payloadInfo_dgstAlg, dict):
        if not 'type' in payloadInfo_dgstAlg:
            raise ValueError('If payload digest algorithm is a map, type is required.')
        if not payloadInfo_dgstAlg['type'] in PayloadDigestAlgorithmTypes:
            raise ValueError('%r is not a recognized digest algorithm'% payloadInfo_dgstAlg)
        dgstType = PayloadDigestAlgorithmTypes[payloadInfo_dgstAlg['type']]
        dgstParams = payloadInfo_dgstAlg.get('params', None)
    else:
        raise ValueError('digestAlgorithm must be either a map or a string.')

    digestAlgorithm = [
        dgstType
    ]
    if dgstParams:
        digestAlgorithm.append(guessBinFormat(dgstParams))
    return digestAlgorithm

def getPayloadDigests(payloadInfo):
    # TODO: digests may only be NULL if payload is not NULL.
    if not payloadInfo.get('digests', None) and not payloadInfo.get('payload', None):
        raise ValueError('digests MUST be present in payloadInfo if payload is omitted.')
    if not payloadInfo.get('digests', None):
        return None

    digests = []
    for k,v in payloadInfo['digests'].items():
        if not k in PayloadDigestTypes:
            raise ValueError('Unrecognized payload digest type: %r' % k)
        # TODO: Digest Parameter Validation
        digests.append([PayloadDigestTypes[k], guessBinFormat(v)])
    return digests

def getPayloadData(payloadInfo):
    if not 'payload' in payloadInfo:
        return None
    try:
        cb = cbor.loads(payloadInfo['payload'])
        if isinstance(cb, cbor.cbor.Tag) and cb.tag == COSE_Encrypt_Tag:
            return cb
    except:
        pass

    return guessBinFormat(payloadInfo['payload'])

def getPayloadInfo(doc):
    if not 'payloadInfo' in doc:
        return None
    docPayloadInfo = doc['payloadInfo']
    payloadInfo = [
        # Get the payload format
        getPayloadFormat(docPayloadInfo),
        # Get the payload size
        getPayloadSize(docPayloadInfo),
        # Get the storage identifier
        getPayloadStorageId(docPayloadInfo),
        # Get the URIs
        getPayloadURIs(docPayloadInfo),
        # Get the digestAlgorithm
        getPayloadDigestAlgorithm(docPayloadInfo),
        # Get a list of digests
        getPayloadDigests(docPayloadInfo),
        # Get the payload
        getPayloadData(docPayloadInfo)
    ]
    return payloadInfo
    #     payload = COSE_Encrypt / bstr / nil
    # ]
# print (indoc)
m = [
    getManifestVersion(indoc),
    getTextObj(indoc),
    getNonce(indoc),
    getTimestamp(indoc),
    getConditions(indoc),
    getDirectives(indoc),
    getAliases(indoc),
    getDependencies(indoc),
    getExtensions(indoc)
]
payloadInfo = getPayloadInfo(indoc)
if payloadInfo:
    m.append(payloadInfo)

# print (m)
cborstr = cbor.dumps(m)
# print(binascii.b2a_hex(cborstr))
with open(sys.argv[2], 'wb') as fd:
    fd.write(cborstr)
# pod = cbor.loads(cborstr)
# print (pod)
# Handle JSON's painful binary parsing...
# pod[2] = binascii.b2a_base64(pod[2]).strip()

# print(json.dumps(pod, indent=4))
