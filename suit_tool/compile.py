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
import binascii
import copy
import collections
import json
import cbor
import sys
import textwrap
import itertools

import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


from suit_tool.manifest import SUITComponentId, SUITCommon, SUITSequence, \
                     suitCommonInfo, SUITCommand, SUITManifest, \
                     SUITWrapper

LOG = logging.getLogger(__name__)

def runable_id(c):
    id = c['install-id']
    if c.get('loadable'):
        id = c['load-id']
    return id

def hash_file(fname, alg):
    imgsize = 0
    digest = hashes.Hash(alg, backend=default_backend())
    with open(fname, 'rb') as fd:
        def read_in_chunks():
            while True:
                data = fd.read(1024)
                if not data:
                    break
                yield data
        for chunk in read_in_chunks():
            imgsize += len(chunk)
            digest.update(chunk)
    return digest, imgsize


def mkCommand(cid, name, arg):
    return SUITCommand().from_json({
        'component-id' : cid.to_json(),
        'command-id' :  name,
        'command-arg' : arg
    })

def check_eq(ids, choices):
    eq = {}
    neq = {}

    check = lambda x: x[:-1]==x[1:]
    get = lambda k, l: [d.get(k) for d in l]
    eq = { k: ids[k] for k in ids if any([k in c for c in choices]) and check(get(k, choices)) }
    check = lambda x: not x[:-1]==x[1:]
    neq = { k: ids[k] for k in ids if any([k in c for c in choices]) and check(get(k, choices)) }
    return eq, neq


def compile_manifest(options, m):
    m = copy.deepcopy(m)
    m['components'] += options.components
    # Compile list of All Component IDs
    ids = set([
        SUITComponentId().from_json(id) for comp_ids in [
            [c[f] for f in [
                'install-id', 'download-id', 'load-id'
            ] if f in c] for c in m['components']
        ] for id in comp_ids
    ])
    cid_data = {}
    for c in m['components']:
        if not 'install-id' in c:
            LOG.critical('install-id required for all components')
            raise Exception('No install-id')

        cid = SUITComponentId().from_json(c['install-id'])
        if not cid in cid_data:
            cid_data[cid] = [c]
        else:
            cid_data[cid].append(c)

    if not any(c.get('vendor-id', None) for c in m['components']):
        LOG.critical('A vendor-id is required for at least one component')
        raise Exception('No Vendor ID')

    if not any(c.get('class-id', None) for c in m['components'] if 'vendor-id' in c):
        LOG.critical('A class-id is required for at least one component that also has a vendor-id')
        raise Exception('No Class ID')

    # Construct common sequence
    CommonSeq = SUITSequence()
    for id, choices in cid_data.items():
        for c in choices:
            if 'file' in c:
                digest, imgsize = hash_file(c['file'], hashes.SHA256())
                c['install-digest'] = {
                    'algorithm-id' : 'sha256',
                    'digest-bytes' : binascii.b2a_hex(digest.finalize())
                }
                c['install-size'] = imgsize



        # if there is a choice, then we need a try-each for each item that is different.
        eqcmds, neqcmds = check_eq({
            'vendor-id': lambda cid, data: {
                'component-id' : cid.to_json(),
                'command-id' :  'condition-vendor-identifier',
                'command-arg' : data['vendor-id']
            },
            'class-id': lambda cid, data: {
                'component-id' : cid.to_json(),
                'command-id' :  'condition-class-identifier',
                'command-arg' : data['class-id']
            },
            'offset': lambda cid, data: {
                'component-id' : cid.to_json(),
                'command-id' :  'condition-component-offset',
                'command-arg' : data['offset']
            },
        }, choices)
        eqparams, neqparams = check_eq({
            'install-digest':'image-digest',
            'install-size':'image-size',
        }, choices)

        # First, set up equal parameters.
        params = {}
        for param, mkey in eqparams:
            params[mkey] = choices[0][param]
        if len(params):
            CommonSeq.append(SUITCommand().from_json({
                'component-id' : cid.to_json(),
                'command-id' :  "directive-override-parameters",
                'command-arg' : params
            }))

        # First add try-each components
        TryEachCmd = []
        for c in choices:
            TECseq = []
            for item, cmd in neqcmds.items():
                TECseq.append(cmd(cid, c))
            params = {}
            for param, mkey in neqparams.items():
                params[mkey] = c[param]
            if len(params):
                TECseq.append({
                    'component-id' : cid.to_json(),
                    'command-id' : 'directive-override-parameters',
                    'command-arg' : params
                })
            if len(TECseq):
                TryEachCmd.append(TECseq)
        if len(TryEachCmd):
            CommonSeq.append(SUITCommand().from_json({
                'component-id' : cid.to_json(),
                'command-id' : 'directive-try-each',
                'command-arg' : TryEachCmd
            }))
        # Finally, and equal commands
        for item, cmd in eqcmds.items():
            CommonSeq.append(SUITCommand().from_json(
                cmd(cid, choices[0])
            ))

    # TODO: Dependencies
    # If there are dependencies
        # Construct dependency resolution step
    InstSeq = SUITSequence()
    FetchSeq = SUITSequence()
    # Construct Installation step
    for c in m['components']:
        # If install-on-download is true
        if c.get('install-on-download', True) and 'uri' in c:
            cid = SUITComponentId().from_json(c['install-id'])
            params = {'uri' : c['uri']}
            if 'compression-info' in c and not c.get('decompress-on-load', False):
                params['compression-info'] = c['compression-info']
            InstSeq.append(SUITCommand().from_json({
                'component-id' : cid.to_json(),
                'command-id' : 'directive-set-parameters',
                'command-arg' : params
            }))
            # Download each component
            InstSeq.append(SUITCommand().from_json({
                'component-id' : cid.to_json(),
                'command-id' : 'directive-fetch',
                'command-arg' : None
            }))
            InstSeq.append(SUITCommand().from_json({
                'component-id' : cid.to_json(),
                'command-id' : 'condition-image-match',
                'command-arg' : None
            }))


        # Else
        else:
            if 'uri' in c:
                dldigest = c.get('download-digest', c['install-digest'])
                params = {
                    'uri' : c['uri'],
                    'image-digest' : dldigest
                }
                if 'compression-info' in c and not c.get('decompress-on-load', False):
                    params['compression-info'] = c['compression-info']

                cid = SUITComponentId().from_json(c['download-id'])
                # Set URI
                FetchSeq.append(SUITCommand().from_json({
                    'component-id' : cid.to_json(),
                    'command-id' : 'directive-set-parameters',
                    'command-arg' : params
                }))
                # Download component
                FetchSeq.append(SUITCommand().from_json({
                    'component-id' : cid.to_json(),
                    'command-id' : 'directive-fetch',
                    'command-arg' : None
                }))
                # Check digest
                FetchSeq.append(SUITCommand().from_json({
                    'component-id' : cid.to_json(),
                    'command-id' : 'condition-image-match',
                    'command-arg' : None
                }))
                instid = SUITComponentId().from_json(c['install-id'])
                dlid = SUITComponentId().from_json(c['download-id'])

                # Setup the source component
                InstSeq.append(SUITCommand().from_json({
                    'component-id' : instid.to_json(),
                    'command-id' : 'directive-set-parameters',
                    'command-arg' : {'source-component' : dlid.to_json()}
                }))

                # Move each component from download to install
                InstSeq.append(SUITCommand().from_json({
                    'component-id' : instid.to_json(),
                    'command-id' : 'directive-copy',
                    'command-arg' : None
                }))

                # Verify each component's install digest
                InstSeq.append(SUITCommand().from_json({
                    'component-id' : cid.to_json(),
                    'command-id' : 'condition-image-match',
                    'command-arg' : None
                }))


    ValidateSeq = SUITSequence()
    RunSeq = SUITSequence()
    LoadSeq = SUITSequence()
    # If any component is marked bootable
    if any(c.get('bootable', False) for c in m['components']):
        # Construct system validation
        for c in m['components']:
            cid = SUITComponentId().from_json(c['install-id'])
            # Verify component
            ValidateSeq.append(SUITCommand().from_json({
                'component-id' : cid.to_json(),
                'command-id' : 'condition-image-match',
                'command-arg' : None
            }))
            # If there are dependencies
                # Verify dependencies
                # Process dependencies
        # Generate image load section
        for c in m['components']:
            if c.get('loadable', False):
                # Move each loadable component
                loadparams = {
                    'source-component' : c['install-id'],
                    'image-digest' : c.get('load-digest', c['install-digest']),
                    'image-size' : c.get('load-size', c['install-size'])
                }
                if 'compression-info' in c and c.get('decompress-on-load', False):
                    loadparams['compression-info'] = c['compression-info']

                LoadSeq.append(SUITCommand().from_json({
                    'component-id' : c['load-id'],
                    'command-id' : 'directive-override-parameters',
                    'command-arg' : loadparams
                }))
                LoadSeq.append(SUITCommand().from_json({
                    'component-id' : c['load-id'],
                    'command-id' : 'directive-copy',
                    'command-arg' : None
                }))
                # Verify each modifiable comopnent
                LoadSeq.append(SUITCommand().from_json({
                    'component-id' : c['load-id'],
                    'command-id' : 'condition-image-match',
                    'command-arg' : None
                }))


        # Generate image invocation section
        bootable_components = [x for x in m['components'] if x.get('bootable')]
        if len(bootable_components) == 1:
            c = bootable_components[0]
            RunSeq.append(SUITCommand().from_json({
                'component-id' : runable_id(c),
                'command-id' : 'directive-run',
                'command-arg' : None
            }))
        else:
            te = []
            for c in bootable_components:
                pass
                # TODO: conditions
                # t.append(
                #
                # )
    #TODO: Text
    common = SUITCommon().from_json({
        'components': [id.to_json() for id in ids],
        'common-sequence': CommonSeq.to_json(),
    })

    jmanifest = {
        'manifest-version' : m['manifest-version'],
        'manifest-sequence-number' : m['manifest-sequence-number'],
        'common' : common.to_json()
    }

    jmanifest.update({k:v for k,v in {
            'payload-fetch' : FetchSeq.to_json(),
            'install' : InstSeq.to_json(),
            'validate' : ValidateSeq.to_json(),
            'run' : RunSeq.to_json(),
            'load' : LoadSeq.to_json()
    }.items() if v})

    wrapped_manifest = SUITWrapper().from_json({'manifest' : jmanifest})
    return wrapped_manifest
