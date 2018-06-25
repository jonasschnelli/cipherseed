[![Build Status](https://travis-ci.org/jonasschnelli/cipherseed.svg?branch=master)](https://travis-ci.org/jonasschnelli/cipherseed) 

cipherseed
=====

Cipherseed is a scheme to encrypt 128 or 256bit entropy plus metadata with chacha20 and add two poly1305 MAC tags to allow a pratical form of plausible deniability


128bit/256bit entropy
----------------
* 1 byte header unencrypted
* 5 byte unencrypted pbkdf2-salt
* 3 byte header encrypted (1 byte type, 2 byte birthday)
* 16/32 byte encrypted entropy
* 4 byte primary MAC tag (tag covers salt || encrypted header || encrypted entropy)
* 4 byte secondary MAC tag (tag covers salt || encrypted header || encrypted entropy)
* = Total 33/49 bytes
* 33 bytes == 264 bits == 24 word mnemonic == 53 base32 chars (without checksum/hrp)
* 49 bytes == 392 bits == 36 word mnemonic == 79 base32 chars (without checksum/hrp)


Compile / Test
=====
```
gcc -O0 -g sha2.c chacha.c poly1305.c cipherseed.c tests.c -o test
./test
```
