#ifndef OPENSSL_TOOLS_AES_H
#define OPENSSL_TOOLS_AES_H

#include <memory>
#include <openssl/evp.h>

#include "bytes.h"

namespace openssl_tools {

//Thanks internet.
using EVP_CIPHER_CTX_ptr=std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

//!Encrypts a message with the given key, iv and data. The size of the resulting 
//!bytes might be different from what expected, as it might include right 
//!padding.
bytes aes_128_cbc_encrypt(const bytes&, const bytes&, const bytes&);
//!Decrypts a message with the given key, iv and data.
bytes aes_128_cbc_decrypt(const bytes&, const bytes&, const bytes&);

}

#endif