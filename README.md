# suit-manifest-generator
This repo will contain a prototype manifest generator following the specification in the SUIT draft (https://tools.ietf.org/html/draft-moran-suit-manifest-01)


To encode:
```
python3 ./encode.py ./test-file.json ./test-out.cbor
```

NOTE: aliases, dependencies, and extensions are not supported in this version.

To sign:
```
openssl ecparam -name secp256r1 -out secp256r1.pem
openssl ecparam -in secp256r1.pem -genkey -noout -out secp256r1-key.pem
openssl ec -in secp256r1-key.pem -pubout -out ecpubkey.pem

python3 ./sign.py secp256r1-key.pem ecpubkey.pem ./test-out.cbor ./test-out-signed.cose
```

To see what was created:
```
>>> import cbor
>>> fd = open('test-out-signed.cose','rb')
>>> s = fd.read()
>>> pod = cbor.loads(s)
>>> print(pod)
Tag(98, [b'\xa1\x03\x18*', {}, b'\x8a\x02\xa4\x01nThis is a test\x02nA test payload\x03oA sample vendor\x04uAn experimental modelP\x0b\xcd\xda\xf9ap\x00\xdcxY\xb7\x91\x84\xaa\x82\xb8\x1aZ\xac"T\x82\x82\x01P\xfakJS\xd5\xad_\xdf\xbe\x9d\xe6c\xe4\xd4\x1f\xfe\x82\x02P\x14\x92\xaf\x14%i^H\xbfB\x9b-Q\xf2\xabE\xf6\xf6\xf6\xf6\x87\x81\x01\x10Cfoo\x81\x82nhttp://foo.com\x01\x81\x01\x81\x82\x01X \xc3\x12\x11\xd1\xff\x88\xf7zZ\xafe6w\x89[\xfc\xa7i\xf0m\xa1\x98\xa8\xfaq\x15j\xa6J\xcdi]\xf6', [[b'\xa2\x01&\x04X \x9e\x85v\x97\xb2\xd7Ph\xb0\xea\x13\x04\x7f\xba\x82\xfb\xe22H\x19\xbf0\xe0\xea\xec\xf5\xa6\xbbn\xb6\x8aZ', {}, b'0E\x02!\x00\x8c\xbf\xcc/hx\x9e\x92\x1e\x00 [t\x7f@\xa6\x0b\x1e\xd5<2q\xd6\xde\xd46G#\x04\xc8\xd7\x7f\x02 /&\xd3\xad7\x1ae\xe3\x1d0\xd45\x031\x15p\xc6\xf5d\x05{Bw\x12\xc6\xf2\xec!\x14\x0f\x0f\xcf']]])
```

This shows a COSE_Sign_Tagged structure:
```
Tag(98, [
    b'\xa1\x03\x18*', # The protected attributes (content type)
    {}, # The unprotected attributes
    # The payload (an encoded manifest)
    b'\x8a\x02\xa4\x01nThis is a test\x02nA test payload\x03oA sample vendor\x04uAn experimental modelP\x0b\xcd\xda\xf9ap\x00\xdcxY\xb7\x91\x84\xaa\x82\xb8\x1aZ\xac"T\x82\x82\x01P\xfakJS\xd5\xad_\xdf\xbe\x9d\xe6c\xe4\xd4\x1f\xfe\x82\x02P\x14\x92\xaf\x14%i^H\xbfB\x9b-Q\xf2\xabE\xf6\xf6\xf6\xf6\x87\x81\x01\x10Cfoo\x81\x82nhttp://foo.com\x01\x81\x01\x81\x82\x01X \xc3\x12\x11\xd1\xff\x88\xf7zZ\xafe6w\x89[\xfc\xa7i\xf0m\xa1\x98\xa8\xfaq\x15j\xa6J\xcdi]\xf6',
    # Signatures
    [
        [
            # Protected attributes (Key ID and Signature Algorithm)
            b'\xa2\x01&\x04X \x9e\x85v\x97\xb2\xd7Ph\xb0\xea\x13\x04\x7f\xba\x82\xfb\xe22H\x19\xbf0\xe0\xea\xec\xf5\xa6\xbbn\xb6\x8aZ',
            {}, # Unprotected attributes
            # Signature
            b'0E\x02!\x00\x8c\xbf\xcc/hx\x9e\x92\x1e\x00 [t\x7f@\xa6\x0b\x1e\xd5<2q\xd6\xde\xd46G#\x04\xc8\xd7\x7f\x02 /&\xd3\xad7\x1ae\xe3\x1d0\xd45\x031\x15p\xc6\xf5d\x05{Bw\x12\xc6\xf2\xec!\x14\x0f\x0f\xcf'
        ]
    ]
])
```
Examining the manifest inside shows:

```
>>> Manifest = cbor.loads(pod.value[2])
>>> print(Manifest)
[2, {1: 'This is a test', 2: 'A test payload', 3: 'A sample vendor', 4: 'An experimental model'}, b'\x0b\xcd\xda\xf9ap\x00\xdcxY\xb7\x91\x84\xaa\x82\xb8', 1521230420, [[1, b'\xfakJS\xd5\xad_\xdf\xbe\x9d\xe6c\xe4\xd4\x1f\xfe'], [2, b'\x14\x92\xaf\x14%i^H\xbfB\x9b-Q\xf2\xabE']], None, None, None, None, [[1], 16, b'foo', [['http://foo.com', 1]], [1], [[1, b'\xc3\x12\x11\xd1\xff\x88\xf7zZ\xafe6w\x89[\xfc\xa7i\xf0m\xa1\x98\xa8\xfaq\x15j\xa6J\xcdi]']], None]]
```

Here, the SUIT draft manifest structure is represented:
```
[
    2, # manifestVersion
    {  # text
        1: 'This is a test',       # Manifest description
        2: 'A test payload',       # Payload description
        3: 'A sample vendor',      # Vendor name
        4: 'An experimental model' # Model name
    },
    b'\x0b\xcd\xda\xf9ap\x00\xdcxY\xb7\x91\x84\xaa\x82\xb8', # nonce
    1521230420, # timestamp
    [ # conditions
        [1, b'\xfakJS\xd5\xad_\xdf\xbe\x9d\xe6c\xe4\xd4\x1f\xfe'], # vendorId
        [2, b'\x14\x92\xaf\x14%i^H\xbfB\x9b-Q\xf2\xabE'] # classId
    ],
    None, # directives
    None, # aliases
    None, # dependencies
    None, # extensions
    [ # payloadInfo
        [1],                     # format
        16,                      # size
        b'foo',                  # storageId
        [['http://foo.com', 1]], # uris
        [1],                     # digestAlgorithm
        { # digests
            # raw download digest
            1:                 b'\xc3\x12\x11\xd1\xff\x88\xf7zZ\xafe6w\x89[\xfc\xa7i\xf0m\xa1\x98\xa8\xfaq\x15j\xa6J\xcdi]'

        },
        None # payload (None means that it is referenced by URI)
    ]
]
```
