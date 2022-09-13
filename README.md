# aes ssl tools

Wrappers for AES encryption.

# third party licensing

This software requires of and wraps parts of openSSL, whose license can be found in the LICENSE_THIRD_PARTY file.

# what does this do?

It includes free floating functions for:

- encrypting and decrypting with the AES 128 CBC algorithm (backed by openSSL's libcrypto)
- encoding and decoding base64 strings (backed by openSSL's libcrypto)
- generate random bytes (backed, again, by OpenSSL's libcrypto)

There are a couple of classes in there too to:

- manage multithreading with libcrypto.
- represent byte sequences.

# why?

I needed these to interact with some software located on an outdated server.

# can I trust it?

I'm a not a crypto expert. All I know is that it worked for my purposes.
