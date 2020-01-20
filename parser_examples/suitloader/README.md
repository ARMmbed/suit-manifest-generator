# suitloader

Demonstration bootloader to be used with SUIT manifests as described in [draft-ietf-suit-manifest](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/). This bootloader is derived from [mbed-bootloader](https://github.com/ARMmbed/mbed-bootloader).

## Build instructions

1. Install `mbed-cli` https://github.com/ARMmbed/mbed-cli
1. Run `mbed deploy` to pull in dependencies
1. Compile by running `mbed compile -t GCC_ARM -m NRF52840_DK --profile release`
