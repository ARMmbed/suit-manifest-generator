# Parser Examples
This directory contains an example parser for SUIT Manifests. The example consists of two parts: a bootloader (suitloader) and an application (suit-app).

The app is a dummy application, which simply prints its version and blinks an LED.

suitloader is adapted from mbed-bootloader. It chooses between two applications based on the contents of the suit manifest. Suitloader targets the Nordic Semiconductor NRF52840_DK. The memory layout is shown below:

```
+--------------------------+ <-+ 0x100000
|                          |
|        Slot B App        | Size: 0x7BC00
|                          |
+--------------------------+ <-+ 0x84400
|      Slot B Manifest     |
+--------------------------+ <-+ 0x84000
|                          |
|        Slot A App        | Size: 0x7BC00
|                          |
+--------------------------+ <-+ 0x8400
|      Slot A Manifest     |
+--------------------------+ <-+ 0x8000
|                          |
|        Bootloader        |
|                          |
+--------------------------+ <-+ 0

```

A script is included that constructs a system image. The provided app is not capable of updating the system.

# Prerequisites

There are several components required to use the provided examples:

1. arm-none-eabi-gcc (version 9)
2. Python 3.7
3. python packages:

    1. cryptography
    2. colorama
    3. json
    4. cbor
    5. mbed-cli

4. srec_cat

# Getting Started

To use the examples, perform the following operations.

1. Prepare the bootloader

```
cd suitloader
mbed deploy
```

2. Prepare the application

```
cd suit-app
mbed deploy
```

3. Build a system image using the system image script

```
sh make_system_image.sh
```

# Next steps

To continue developing for suit manifests, here are some options to try:

1. Change the sequence numbers in suit-app/slot-a-manifest.json or suit-app/slot-a-manifest.json to see the bootloader select one slot or the other.
2. Change the version string or blink rate in slot_a_app_info.h or slot_b_app_info.h
3. Replace the default trust anchor in bootloader.c with your own public key and replace private_key.pem with your own private key. Use `suit-tool pubkey` to generate an ECC public key suitable for use in the suitloader from a PEM ECC private key.



# System Image Script

The provided script, `make_system_image.sh`, performs the following actions:

1. Build suitloader
2. Build suit-app for Slot A
3. Construct a manifest for suit-app in Slot A
4. Sign the manifest for suit-app in Slot A
5. Build suit-app for Slot B
6. Construct a manifest for suit-app in Slot B
7. Sign the manifest for suit-app in Slot B
8. Assemble the 5 component pieces into a single system image.

# Warnings

BEWARE: Do not use private_key.pem for any reason other than simple testing. It is public information and cannot be used as the basis for any security.

There are several known issues that affect the security of this implementation. Ensure that you have addressed these issues prior to using the supplied code for any practical purpose.

# Known Issues

These example parsers are not yet reference implementations. They have several known issues.

* Length-checking flaws: The parser does not fully validate lengths, particularly in stored variables. This could lead to security flaws from malformed CBOR.
* Single signature: Only one signature is supported.
* No COSE_Sign: Only COSE_Sign1 is supported.
* No MAC support: There is no support for COSE_Mac or COSE_Mac0.
* No dependency support: Support for dependencies is not implemented.
* No Try-Each support: The Try-Each block is not implemented.
