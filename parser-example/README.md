# Minimal draft-moran-suit-manifest-03 example parser

This parser example is intended to parse a very limited subset of the draft-moran-suit-manifest-03 manifest. The CDDL for the subset is shown below:

```CDDL

outer-wrapper = {
    authentication-wrapper => $auth-wrapper-types,
    manifest => suit-manifest,
}

authentication-wrapper = 1
manifest = 2

$auth-wrapper-types /= COSE_Sign1_Tagged

label = int / tstr
values = any

COSE_Sign1_Tagged = any ; TBD

COSE_Mac0 = [
      Headers,
      payload : bytes / nil,
      tag : bstr,
   ]

Headers = (
    protected : empty_or_serialized_map,
    unprotected : header_map
)

header_map = { Generic_Headers,
               * label => values
             }

empty_or_serialized_map = bstr .cbor header_map / bstr .size 0

Generic_Headers = (
   ? 1 => int / text,  ; algorithm identifier
)

COSE_Digest = COSE_Mac0

suit-manifest = {
    manifest-version => 1,
    sequence-number => uint,
    pre-install => pre-installation-info,
    install => installation-info,
    payloads => [ payload-info ],
    intent => COSE_Digest,
}

manifest-version = 1
sequence-number = 2
pre-install = 3
install = 5
payloads = 6
intent = 8

component-identifier = []

payload-info = {
    payload-component => component-identifier,
    payload-size => uint,
    payload-digest => COSE_Digest,
}
payload-component = 1
payload-size      = 2
payload-digest    = 3

pre-installation-info = {
    ? pre-conditions => [ + pre-condition ],
}

pre-conditions = 1

pre-condition = ( id-condition )

id-condition  = [
                  id-condition-vendor /
                  id-condition-class,
                  id : uuid,
                ]

id-condition-vendor = 1
id-condition-class = 2

uuid = bstr .size 16

installation-info = {
    payload-installation-infos => [ payload-installation-info ]
}
payload-installation-infos = 1
payload-installation-info = {
    install-component => component-identifier,
    payload-processors => [ processor ],
}
install-component = 1
payload-processors = 2

processor = {
    processor-id => [ 1, 1 ],
    processor-inputs => uri-list,
}

uri-list = [ [ 0,
                 link: uri,
               ]
           ]

processor-id = 1
processor-inputs = 3


firmware-intent = {
    * lang => tstr
}

lang = uint
```

Note that there is one change from draft-moran-suit-manifest-03: install comes before payload. This is due to the ordering of operations in an update process, in a minimal device: a payload must be installed (URI required from installation-info) before it can be verified (digest required from payload-info). All remaining changes are just specialisation of the draft, removing options that are not needed in the most minimal cases.

# Theory of Operation
This CBOR parser is heavily specialised for parsing draft-moran-suit-manifest-03 manifests. It does not parse CBOR objects per-se, instead, it does pattern matching on the binary structure of the manifest. It divides the manifests created by the above simple manifest into static and dynamic parts. Static parts are constant for any manifest that matches the above CDDL (with canonical map encoding). Dynamic portions contain the information that needs to be extracted from the manifest.

The dynamic components of the manifest are:

1. the signature
2. the size of the manifest (needed for signature validation)
3. the sequence number
4. the vendor id
5. the class id
6. the payload uri
7. the payload size
8. the payload digest

Of these fields, several are not fixed size:

1. the manifest size
2. the sequence number
3. the payload URI
4. the payload size

The parser can operate in two modes:

1. structural validation with information extraction
2. information extraction only

When performing structural validation, the parser compares the structure of the manifest to the expected structure, using memcmp.

When performing information extraction, the parser uses the sizes of the expected structure fragments to advance a pointer through the structure, reading the dynamic data, and ignoring the structural data.

Note that the parser halts after the payload hash and does not parse the digest of the associated text.

# Size
The linker prunes all the expected structure fragments when they are unused and their sizes become constants. This, along with fewer calls to memcmp reduces the footprint of the manifest parser, however it presents a risk: under some (very unlikely) conditions, it could allow unexpected behaviour.

If the same key were to sign both a minimal manifest, and a non-minimal manifest, it is possible that a device could read incorrect dynamic information and perform an unexpected sequence of operations. This would require a correctly signed non-minimal manifest to contain correct vendor ID and class ID where the minimal parser expects them, along with a correctly formed URI. This could cause the manifest to cause the download of an unexpected payload. If that same manifest were to contain a correct payload digest for that same unexpected payload, then the device would install it and try to boot it. This is very unlikely, but not impossible. The lesson here is to use different private keys for minimal and non-minimal manifests when using only information extraction.

Sizes are reported for Cortex-M4, built with -Os on:

```
arm-none-eabi-gcc (GNU Tools for ARM Embedded Processors 6-2017-q2-update) 6.3.1 20170620 (release) [ARM/embedded-6-branch revision 249437]
```

For full structural validation and information extraction, the manifest parser takes 560 bytes.
For information extraction only, the manifest parser takes 333 bytes.

For the sake of comparison, this repo also contains a minimal, fixed-format packed binary encoding (not the one described in draft-pagel-suit-manifest-00, one that is dramatically smaller than even that draft)

For information extraction from a minimal packed binary format that contains only the dynamic components, the compiled size is 102 bytes.
