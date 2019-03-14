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
import binascii
import cbor
import uuid
import json
examples = [
    {
        "structure-version" : 1,
        "sequence-number" : 1,
        "components": [
            {
                "id" : ["Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            }
        ],
        "run-image" : [
            {"directive-set-component":0},
            {"condition-image":None},
            {"directive-run":None}
        ]
    },
    {
        "structure-version" : 1,
        "sequence-number" : 2,
        "components": [
            {
                "id" : ["Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            }
        ],
        "apply-image" : [
            {"directive-set-component":0},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file.bin"]],
                }
            },
            {"directive-fetch":None}
        ]
    },
    {
        "structure-version" : 1,
        "sequence-number" : 3,
        "components": [
            {
                "id" : ["Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            }
        ],
        "common" : [
            {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
            {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
        ],
        "apply-image" : [
            {"directive-set-component":0},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file.bin"]],
                }
            },
            {"directive-fetch":None}
        ],
        "run-image" : [
            {"directive-set-component":0},
            {"condition-image":None},
            {"directive-run":None}
        ]
    },
    {
        "structure-version" : 1,
        "sequence-number" : 4,
        "components": [
            {
                "id" : ["Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            },
            {
                "id" : ["RAM", 0x400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            }
        ],
        "common" : [
            {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
            {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
        ],
        "apply-image" : [
            {"directive-set-component":0},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file.bin"]],
                }
            },
            {"directive-fetch":None}
        ],
        "run-image" : [
            {"directive-set-component":0},
            {"condition-image":None},
            {"directive-set-component":1},
            {
                "directive-set-var": {
                    "source-index" : 0,
                }
            },
            {"directive-fetch":None},
            {"condition-image":None},
            {"directive-run":None}
        ]
    },
    {
        "structure-version" : 1,
        "sequence-number" : 5,
        "components": [
            {
                "id" : ["Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            },
            {
                "id" : ["RAM", 0x400],
                "digest":"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                "size" : 34768
            }
        ],
        "common" : [
            {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
            {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
        ],
        "apply-image" : [
            {"directive-set-component":0},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file.bin"]],
                }
            },
            {"directive-fetch":None}
        ],
        "load-image" : [
            {"directive-set-component":0},
            {"condition-image":None},
            {"directive-set-component":1},
            {
                "directive-set-var": {
                    "source-index" : 0,
                    "compression-info" : {
                        "algorithm" : 'gzip'
                    }
                }
            },
            {"directive-copy":None},
        ],
        "run-image" : [
            {"condition-image":None},
            {"directive-run":None}
        ]
    },
    {
        "structure-version" : 1,
        "sequence-number" : 6,
        "components": [
            {
                "id" : ["ext-Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            },
            {
                "id" : ["Flash", 0x400],
                "digest":"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                "size" : 34768
            }
        ],
        "common" : [
            {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
            {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
        ],
        "apply-image" : [
            {"directive-set-component":0},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file.bin"]],
                }
            },
            {"directive-fetch":None}
        ],
        "load-image" : [
            {
                "directive-run-conditional": [
                    {"directive-set-component":1},
                    {"condition-not-image":None},
                    {"directive-set-component":0},
                    {"condition-image":None},
                    {"directive-set-component":1},
                    {
                        "directive-set-var": {
                            "source-index" : 0,
                        }
                    },
                    {"directive-fetch":None}
                ]
            },
        ],
        "run-image" : [
            {"directive-set-component":1},
            {"condition-image":None},
            {"directive-run":None}
        ]
    },
    {
        "structure-version" : 1,
        "sequence-number" : 7,
        "components": [
            {
                "id" : ["Flash", 0x13400],
                "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
                "size" : 34768
            },
            {
                "id" : ["Flash", 0x20400],
                "digest":"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
                "size" : 76834
            },
        ],
        "common" : [
            {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
            {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
        ],
        "apply-image" : [
            {"directive-set-component":0},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file1.bin"]],
                }
            },
            {"directive-set-component":1},
            {
                "directive-set-var": {
                    "uris" : [[0,"http://example.com/file2.bin"]],
                }
            },
            {"directive-set-component":True},
            {"directive-fetch":None}
        ],
        "run-image" : [
            {"directive-set-component":True},
            {"condition-image":None},
            {"directive-set-component":0},
            {"directive-run":None}
        ]
    }


]

SUIT_Authentication_Wrapper = 1
SUIT_Manifest = 2
SUIT_Dependency_Resolution = 7
SUIT_Payload_Fetch = 8
SUIT_Install = 9
SUIT_Text = 13
SUIT_Coswid = 14

SUIT_Manifest_Version = 1
SUIT_Manifest_Sequence_Number = 2
SUIT_Dependencies = 3
SUIT_Components = 4
SUIT_Dependency_Components = 5
SUIT_Common = 6
SUIT_Dependency_Resolution = 7
SUIT_Payload_Fetch = 8
SUIT_Install = 9
SUIT_Validate = 10
SUIT_Load = 11
SUIT_Run = 12
SUIT_Text = 13
SUIT_Coswid = 14

SUIT_Dependency_Digest = 1
SUIT_Dependency_Prefix = 2

SUIT_Component_Identifier = 1
SUIT_Component_Size = 2
SUIT_Component_Digest = 3

SUIT_Component_Dependency_Index = 2

SUIT_Condition_Vendor_Identifier = 1
SUIT_Condition_Class_Identifier = 2
SUIT_Condition_Device_Identifier = 3
SUIT_Condition_Image_Match = 4
SUIT_Condition_Image_Not_Match = 5
SUIT_Condition_Use_Before = 6
SUIT_Condition_Minimum_Battery = 7
SUIT_Condition_Update_Authorised = 8
SUIT_Condition_Version = 9
SUIT_Condition_Component_Offset = 10

SUIT_Directive_Set_Component_Index = 11
SUIT_Directive_Set_Manifest_Index = 12
SUIT_Directive_Run_Sequence = 13
SUIT_Directive_Run_Sequence_Conditional = 14
SUIT_Directive_Process_Dependency = 15
SUIT_Directive_Set_Parameters = 16
SUIT_Directive_Override_Parameters = 19
SUIT_Directive_Fetch = 20
SUIT_Directive_Copy = 21
SUIT_Directive_Run = 22
SUIT_Directive_Wait = 23

SUIT_Parameter_Strict_Order = 1
SUIT_Parameter_Coerce_Condition_Failure = 2
SUIT_Parameter_Vendor_ID = 3
SUIT_Parameter_Class_ID = 4
SUIT_Parameter_Device_ID = 5
SUIT_Parameter_URI_List = 6
SUIT_Parameter_Encryption_Info = 7
SUIT_Parameter_Compression_Info = 8
SUIT_Parameter_Unpack_Info = 9
SUIT_Parameter_Source_Component = 10
SUIT_Parameter_Image_Digest = 11
SUIT_Parameter_Image_Size = 12

SUIT_Compression_Algorithm = 1

# for example in examples:
    # Convert to Object
    # Print the content
    # Convert to CBOR
    # Print CBOR

def obj2bytes(o):
    if isinstance(o, int):
        l = []
        while o:
            l.append(o&0xff)
            o = o >> 8
        return bytes(l)
    if isinstance(o, str):
        return o.encode('utf-8')
    if isinstance(o, bytes):
        return o
    return b''

def make_SUIT_Components(unused, components):
    comps = []
    for component in components:
        c = {
            SUIT_Component_Identifier : [obj2bytes(x) for x in component["id"]]
        }
        if "digest" in component:
            c[SUIT_Component_Digest] = [1, binascii.a2b_hex(component["digest"])]
        if "size" in component:
            c[SUIT_Component_Size] = component["size"]
        comps.append(c)
    return (SUIT_Components, comps)
def make_SUIT_Compression_Info(info):
    algorithms = {
        'gzip' : 1,
        'bzip2' : 2,
        'deflate' : 3,
        'lz4' : 4,
        'lzma' : 7,
    }
    cinfo = {
        SUIT_Compression_Algorithm :algorithms[info['algorithm']]
    }

def make_SUIT_Set_Parameters(parameters):
    set_parameters = {}
    SUIT_Parameters_Keys = {
        # SUIT_Parameter_Strict_Order = 1
        # SUIT_Parameter_Coerce_Condition_Failure = 2
        # SUIT_Parameter_Vendor_ID = 3
        # SUIT_Parameter_Class_ID = 4
        # SUIT_Parameter_Device_ID = 5
        # SUIT_Parameter_URI_List = 6
        'uris' : lambda x: (SUIT_Parameter_URI_List, cbor.dumps(x)),
        # SUIT_Parameter_Encryption_Info = 7
        # SUIT_Parameter_Compression_Info = 8
        'compression-info': lambda x : (
            SUIT_Parameter_Compression_Info,
            cbor.dumps(make_SUIT_Compression_Info(x))
        ),
        # SUIT_Parameter_Unpack_Info = 9
        'source-index' : lambda x :(SUIT_Parameter_Source_Component, int(x)),
        # SUIT_Parameter_Image_Digest = 11
        # SUIT_Parameter_Image_Size = 12
    }
    for p in parameters:
        if p in SUIT_Parameters_Keys:
            k, v = SUIT_Parameters_Keys[p](parameters[p])
            set_parameters[k] = v
        else:
            raise Exception('ERROR: {} not found!'.format(p))

    return (SUIT_Directive_Set_Parameters, set_parameters)

def make_SUIT_Sequence(seq_name, sequence):
    seq = []
    SUIT_Sequence_Keys = {
        "condition-vendor-id"       : lambda x : (SUIT_Condition_Vendor_Identifier, uuid.UUID(x).bytes),
        "condition-class-id"        : lambda x : (SUIT_Condition_Class_Identifier, uuid.UUID(x).bytes),
        "condition-device-id"       : lambda x : (SUIT_Condition_Device_Identifier, uuid.UUID(x).bytes),
        "condition-image"           : lambda x : (SUIT_Condition_Image_Match, None),
        "condition-not-image"       : lambda x : (SUIT_Condition_Image_Not_Match, None),
        # SUIT_Condition_Use_Before = 6
        # SUIT_Condition_Minimum_Battery = 7
        # SUIT_Condition_Update_Authorised = 8
        # SUIT_Condition_Version = 9
        # SUIT_Condition_Component_Offset = 10
        #
        "directive-set-component"   : lambda x : (SUIT_Directive_Set_Component_Index, x),
        # SUIT_Directive_Set_Manifest_Index = 12
        # SUIT_Directive_Run_Sequence = 13
        # SUIT_Directive_Run_Sequence_Conditional = 14
        "directive-run-conditional" : lambda x : (
            SUIT_Directive_Run_Sequence_Conditional,
            cbor.dumps(make_SUIT_Sequence("conditional-sequence", x), sort_keys = True)
        ),
        # SUIT_Directive_Process_Dependency = 15
        # SUIT_Directive_Set_Parameters = 16
        "directive-set-var"         : make_SUIT_Set_Parameters,
        # SUIT_Directive_Override_Parameters = 19
        "directive-fetch"           : lambda x : (SUIT_Directive_Fetch, None),
        "directive-copy"            : lambda x : (SUIT_Directive_Copy, None),
        "directive-run"             : lambda x : (SUIT_Directive_Run, None),
        # SUIT_Directive_Wait = 23
    }
    for command in sequence:
        com_dict = {}
        for c in command:
            if c in SUIT_Sequence_Keys:
                k, v = SUIT_Sequence_Keys[c](command[c])
                com_dict[k] = v
            else:
                raise Exception('ERROR: {} not found!'.format(c))
        seq.append(com_dict)
    # print("Sequence {}: {}".format(seq_name, seq))
    return seq

def make_SUIT_Manifest(info):
    # print(info)
    SUIT_Manifest_Keys = {
        "structure-version" : lambda y, x: (SUIT_Manifest_Version, x),
        "sequence-number"   : lambda y, x: (SUIT_Manifest_Sequence_Number, x),
        # SUIT_Dependencies = 3
        "components"        : make_SUIT_Components,
        # SUIT_Dependency_Components = 5
        "common"            : lambda y, x: (SUIT_Common, cbor.dumps(make_SUIT_Sequence(y, x), sort_keys=True)),
        # SUIT_Dependency_Resolution = 7
        # SUIT_Payload_Fetch = 8
        "apply-image"       : lambda y, x: (SUIT_Install, cbor.dumps(make_SUIT_Sequence(y, x), sort_keys=True)),
        # SUIT_Validate = 10
        "load-image"        : lambda y, x: (SUIT_Load, cbor.dumps(make_SUIT_Sequence(y, x), sort_keys=True)),
        "run-image"         : lambda y, x: (SUIT_Run, cbor.dumps(make_SUIT_Sequence(y, x), sort_keys=True)),
        # SUIT_Text = 13
        # SUIT_Coswid = 14
    }
    manifest = {}
    for field in info:
        if field in SUIT_Manifest_Keys:
            k, v = SUIT_Manifest_Keys[field](field, info[field])
            manifest[k] = v
        else:
            raise Exception('ERROR: {} not found!'.format(field))

    # print ('suit-manifest: {}'.format(manifest))
    return manifest

def make_SUIT_Outer_Wrapper(info):
    Outer_Wrapper = {
        SUIT_Authentication_Wrapper : None,
        SUIT_Manifest               : cbor.dumps(make_SUIT_Manifest(info), sort_keys = True)
    }
    # print('Outer_Wrapper: {}'.format(Outer_Wrapper))
    return Outer_Wrapper

def pretty_print_components(indent, k, v):
    print('{}/ components / {} : ['.format(indent, k))
    indent += ' '*4
    for c in v:
        print('{}{{'.format(indent))
        indent += ' '*4
        digest_algorithms = {
            1: 'sha-256'
        }

        for k,v in c.items():
            {
                1 : lambda indent, k, v: print('{}/ component-identifier / 1 : [{}], '.format(
                    indent, ', '.join(['h\'{}\''.format(binascii.b2a_hex(x).decode('utf-8')) for x in v])
                )),
                3: lambda indent, k, v: print('{}/ component-digest / 2 : [ / {} / {}, h\'{}\'],'.format(
                    indent, digest_algorithms[v[0]], v[0], binascii.b2a_hex(v[1]).decode('utf-8')
                )),
                2: lambda indent, k, v: print('{}/ component-size / 3 : {}'.format(indent, v))
            }[k](indent, k, v)
        indent = indent[:-4]
        print('{}}}'.format(indent))
    indent = indent[:-4]
    print('{}],'.format(indent))

def pretty_print_uuid(indent, name, k, v):
    print('{indent}{{/ {name} / {key} : h\'{hex_val}\' \\ {uuid}}}'.format(
        indent=indent,
        name=name,
        key=k,
        hex_val=binascii.b2a_hex(v).decode('utf-8'),
        uuid=str(uuid.UUID(bytes=v))
    ))

def pretty_print_simple_command(indent, name, k, v):
    print('{indent}{{/ {name} / {key} : {value}}}'.format(
        indent=indent,
        name=name,
        key=k,
        value=v))
# def pretty_print_sub_sequence(indent, k, v):

def pretty_print_command_sequence(indent, name, k,v):
    lcs = cbor.loads(v)
    print('{}/ {} / {} : ['.format(indent, name, k))
    indent += ' '*4
    for c in lcs:
        for k,v in c.items():
            {
                1:  lambda indent, k, v: pretty_print_uuid(indent, 'vendor-id', k, v),
                2:  lambda indent, k, v: pretty_print_uuid(indent, 'class-id', k, v),
                3:  lambda indent, k, v: pretty_print_uuid(indent, 'device-id', k, v),
                4:  lambda indent, k, v: pretty_print_simple_command(indent, 'condition-image', k, v),
                5:  lambda indent, k, v: pretty_print_simple_command(indent, 'condition-not-image', k, v),
                11: lambda indent, k, v: pretty_print_simple_command(indent, 'set-component-index', k, v),
                14: lambda indent, k, v: pretty_print_command_sequence(indent, 'conditional-sequence', k, v),
                16: lambda indent, k, v: pretty_print_set_vars(indent, k, v),
                20: lambda indent, k, v: pretty_print_simple_command(indent, 'fetch', k, v),
                21: lambda indent, k, v: pretty_print_simple_command(indent, 'copy', k, v),
                22: lambda indent, k, v: pretty_print_simple_command(indent, 'run', k, v),
            }.get(
                k,
                lambda indent, k, v: print('{}{{{} : {}}}'.format(indent, k, v))
            )(indent, k, v)

    indent = indent[:-4]
    print('{}],'.format(indent))

def kv_pretty_print(indent, name, k, v):
    print('{indent}/ {name} / {key} : {value}'.format(
        indent=indent,
        name=name,
        key=k,
        value=v))

def kv_pretty_print_bin(indent, name, k, bv, v):
    print('{indent}/ {name} / {key} : h\'{bin_value}\' / {value} /'.format(
        indent=indent,
        name=name,
        key=k,
        bin_value=binascii.b2a_hex(bv).decode('utf-8'),
        value=v))

def pretty_print_set_vars(indent, k, vars):
    print('{}{{/ {} / {} : {{'.format(indent, 'set-vars', k))
    indent += ' '*4
    for k,v in vars.items():
        {
            6 : lambda indent, k, v: kv_pretty_print_bin(indent, 'uris', k, v, cbor.loads(v)),
            10 : lambda indent, x, y: kv_pretty_print(indent, 'source-component', x, y),
        }.get(k, lambda indent, x, y: kv_pretty_print(indent, 'unknown', x, y))(indent, k, v)
    indent = indent[:-4]
    print('{}}}}},'.format(indent))

def pretty_print_manifest(k, v):
    indent = ' '*4

    print('{}/ manifest / {} : {} \\'.format(indent, k, binascii.b2a_hex(v)))
    print('{}{{'.format(indent))
    indent +=' '*4
    dm = cbor.loads(v)
    for k,v in dm.items():
        {
            1: lambda indent, k, v: kv_pretty_print(indent, 'structure-version', k, v),
            2: lambda indent, k, v: kv_pretty_print(indent, 'sequence-number', k, v),
            4: pretty_print_components,
            6: lambda indent, k, v: pretty_print_command_sequence(indent, 'common', k, v),
            7: lambda indent, k, v: pretty_print_command_sequence(indent, 'dependency-resolution', k, v),
            8: lambda indent, k, v: pretty_print_command_sequence(indent, 'payload-fetch', k, v),
            9: lambda indent, k, v: pretty_print_command_sequence(indent, 'apply-image', k, v),
            10: lambda indent, k, v: pretty_print_command_sequence(indent, 'validate-image', k, v),
            11: lambda indent, k, v: pretty_print_command_sequence(indent, 'load-image', k, v),
            12: lambda indent, k, v: pretty_print_command_sequence(indent, 'run-image', k, v),
        }.get(k, lambda indent, k,v:print('{}{} : {}'.format(indent, k, v)))(indent, k,v)


    indent = indent[:-4]
    print('{}}}'.format(indent))

def pretty_print_outer_manifest(mfst):
    # print('manifest:')
    print('{')
    for k,v in cbor.loads(mfst).items():
        {
            1: lambda k,v: print('    / auth object / {} : {}'.format(k,v)),
            2: lambda k,v: pretty_print_manifest(k,v)
        }[k](k,v)
    print('}')

for i,example in enumerate(examples):
    print('## Example {}:\n'.format(i))
    outer = make_SUIT_Outer_Wrapper(example)
    cbor_outer = cbor.dumps(outer,sort_keys = True)
    print('''
The following JSON shows the intended behaviour of the manifest.

~~~ JSON
''')
    print(json.dumps(example, indent=4))
    print('~~~')
    print()
    print('Converted into the SUIT manifest, this produces:')
    print()
    print('~~~')
    pretty_print_outer_manifest(cbor_outer)
    print('~~~')
    print()
    print('\n\nTotal size of outer wrapper without COSE authentication object: {}\n'.format(len(cbor_outer)))
    print('Outer: \n\n~~~\n{}\n~~~\n'.format(binascii.b2a_hex(cbor_outer).decode('utf-8')))



#
# Ex 8:
#     2 image
#     Detached Apply
#     Download
#     Boot
#
# {
#     "structure-version" : 1,
#     "sequence-number" : 8,
#     "components": [
#         {
#             "id" : ["Flash", 0x13400],
#             "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
#             "size" : 34768
#         },
#         {
#             "id" : ["Flash", 0x20400],
#             "digest":"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
#             "size" : 76834
#         },
#     ],
#     "common" : [
#         {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
#         {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
#     ],
#     "apply-image" : [
#         "sha-256",
#         "8899aabbccddeeff0123456789abcdef0011223344556677fedcba9876543210"
#     ],
#     "load-run" : [
#         {"directive-set-component":0},
#         {"condition-image":None},
#         {"directive-run":None}
#     ]
# },
# [
#     {"directive-set-component":0},
#     {
#         "directive-set-var": {
#             "uris" : [[0,"http://example.com/file1.bin"]],
#         }
#     },
#     {"directive-set-component":1},
#     {
#         "directive-set-var": {
#             "uris" : [[0,"http://example.com/file2.bin"]],
#         }
#     },
#     {"directive-set-component":true},
#     {"directive-fetch":None}
# ]
# Ex 9:
#     2 image
#     Download 1
#     Download 2
#     Boot
#
# {
#     "structure-version" : 1,
#     "sequence-number" : 9,
#     "components": [
#         {
#             "id" : ["Flash", 0x13400],
#             "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
#             "size" : 34768
#         },
#         {
#             "id" : ["Flash", 0x20400],
#             "digest":"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
#             "size" : 76834
#         },
#     ],
#     "common" : [
#         {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
#         {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
#     ],
#     "apply-image" : [
#         "sha-256",
#         "8899aabbccddeeff0123456789abcdef0011223344556677fedcba9876543210"
#     ],
#     "load-run" : [
#         {"directive-set-component":0},
#         {"condition-image":None},
#         {"directive-run":None}
#     ]
# },
# [
#     {"directive-set-component":0},
#     {
#         "directive-set-var": {
#             "uris" : [[0,"http://example.com/file1.bin"]],
#         }
#     },
#     {"directive-fetch":None},
#     {"directive-set-component":1},
#     {
#         "directive-set-var": {
#             "uris" : [[0,"http://example.com/file2.bin"]],
#         }
#     },
#     {"directive-fetch":None}
# ]
# Ex 8:
#     2 image 2 mfst
#     Download
#     Boot
#
# {
#     "structure-version" : 1,
#     "sequence-number" : 10,
#     "components": [
#         {
#             "id" : ["Flash", 0x13400],
#             "digest":"00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210",
#             "size" : 34768
#         }
#     ],
#     "common" : [
#         {"condition-vendor-id" : "fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe"},
#         {"condition-class-id" : "1492af14-2569-5e48-bf42-9b2d51f2ab45"}
#     ],
#     "apply-image" : [
#         {"directive-set-component":0},
#         {
#             "directive-set-var": {
#                 "uris" : [[0,"http://example.com/file1.bin"]],
#             }
#         },
#         {"directive-fetch":None},
#     ],
#     "load-run" : [
#         {"directive-set-component":0},
#         {"condition-image":None},
#         {"directive-run":None}
#     ]
# },
# {
#     "structure-version" : 1,
#     "sequence-number" : 10,
#     "components": [
#         {
#             "id" : ["Flash", 0x20400],
#             "digest":"0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
#             "size" : 76834
#         }
#     ],
#     "dependent-components": [
#         ["Flash", 0x13400]
#     ],
#     "dependencies": [
#         {"digest" : "8899aabbccddeeff0123456789abcdef0011223344556677fedcba9876543210"}
#     ],
#     "dependency-fetch" : [
#         {"directive-set-manifest":0},
#         {
#             "directive-set-var": {
#                 "uris" : [[0,"http://example.com/mfst.bin"]],
#             }
#         },
#     ],
#     "apply-image" : [
#         {"directive-set-manifest":0},
#         {"condition-image":None},
#         {"directive-process":None},
#         {"directive-set-component":1},
#         {
#             "directive-set-var": {
#                 "uris" : [[0,"http://example.com/file2.bin"]],
#             }
#         },
#         {"directive-fetch":None},
#         {"condition-image":None}
#     ],
#     "validate": [
#         {"directive-set-manifest":0},
#         {"condition-image":None},
#         {"directive-process":None},
#         {"directive-set-component":1},
#         {"condition-image":None}
#     ],
#     "load-run" : [
#         {"directive-run":None}
#     ]
# },
#
#
# Ex 9:
#     2 image 2 mfst override
#     Override
#     Download
#     Boot
#
# Ex :
#     4 image
#     No-strict-order
#     Download
#     Boot
