# Key derivation examples

We must have a full subkey to derive the original key. This will be longer than
the individual round key for 192 and 256-bit keys.

Provide the complete subkey and the 32-bit offset. Note that the original key
is at offset 0.

For AES-256:
```
python3 -m aes_tools derive --skey de1369676ccc5a71fa2563959674ee155886ca5d2e2f31d77e0af1fa27cf73c3 --offset 40
Derived key: '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4'
```

For AES-128, round 9:
```
python3 -m aes_tools derive --skey ac7766f319fadc2128d12941575c006e --offset 36
Derived key: '2b7e151628aed2a6abf7158809cf4f3c'
```
