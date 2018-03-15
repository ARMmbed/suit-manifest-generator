import cbor
import os
import time
import binascii
import json
import uuid

armUUID = uuid.uuid5(uuid.NAMESPACE_DNS, 'arm.com')
armSuitDeviceUUID = uuid.uuid5(armUUID, 'suit')

indoc = {
    'text' : {
        'manifestDescription' : 'This is a test',
        'payloadDescription' : 'A test payload',
        'vendor' : 'A sample vendor',
        'model' : 'An experimental model'
    },
    'conditions' : {
        'vendorId' : armUUID.bytes,
        'classId' : armSuitDeviceUUID.bytes
    }

}

LatestManifestVersion = 2

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
    return doc.get('nonce', os.urandom(16))

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
        conditions.append([ConditionTypes[k], cbor.dumps(v)])
    return conditions

def getDirectives(doc):
    if not 'directives' in doc:
        return None
    directives = []
    for k,v in doc['directives'].items():
        if not k in DirectiveTypes:
            raise ValueError('Unrecognized directive type: %r' % k)
        # TODO: Directive Validation
        directives.append([DirectiveTypes[k], cbor.dumps(v)])
    return directives

def getAliases(doc):
    pass
def getDependencies(doc):
    pass
def getExtensions(doc):
    pass
def getPayloadInfo(doc):
    pass

print (indoc)
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

print (m)
cborstr = cbor.dumps(m)
print(binascii.b2a_hex(cborstr))
pod = cbor.loads(cborstr)

# Handle JSON's painful binary parsing...
pod[2] = binascii.b2a_base64(pod[2]).strip()

# print(json.dumps(pod, indent=4))
