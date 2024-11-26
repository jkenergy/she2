# she2
SHE with extensions for GCM, KDF, counter

Based on the SHE software emulation library from Canis Labs:

https://github.com/kentindell/canis-she

Adds the following functions:

- GCM (SHE did not define AEAD cryptography, just AES and CMAC)
- KDF (using the NIST KDF based on CMAC)
- Non-volatile monotonic counter