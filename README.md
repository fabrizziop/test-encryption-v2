test-encryption-v2
==================

SHA-512-based cipher. Python 3.4

A key of the size you specify is created and stored in the header file in 512-bit slices. Each slice has its own salt, so you
must derive a key from each slice with each salt and your password.The header is tamper-proof with a HMAC based on your own password.
All key derivation functions use PBKDF2 SHA-512 with the iteration amount specified at file encryption.

The cipher works by concatenating all keys and getting a hash of that. Then, when you want to get the next 64-byte block, you move
the key one bit to the right, concatenate it to the previous hash, save that as the current state, hash all of that and you get the next feedback.
Then you transpose all the bits, hash it and you have the bytes to xor. 

In a variation, we start with an IV being the sha512 hash of the whole key, and we concatenate the key to that along with the feedback hash to start.
Then that IV becomes the sha512 of each plaintext block. Maybe it's safer. And if you flip a bit then all the 512-bit blocks after it become garbage.

This hasn't been tested. Probably secure. The CSPRNG passes dieharder tests. And, sensible total key sizes are 512 to 2048 bit, although
the header will allow you to use UP TO 33553920 bits of key material (n=65535 [FFFF]) and up to 65535000 (n=65535 [FFFF]) PBKDF2 SHA-512 iterations
