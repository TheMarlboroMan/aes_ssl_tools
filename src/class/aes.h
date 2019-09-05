#ifndef OPENSSL_TOOLS_AES_H
#define OPENSSL_TOOLS_AES_H

#include <memory>
#include <openssl/evp.h>

#include "bytes.h"

namespace openssl_tools {

using EVP_CIPHER_CTX_ptr=std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
bytes aes_128_cbc_encrypt(const bytes&, const bytes&, const bytes&);
bytes aes_128_cbc_decrypt(const bytes&, const bytes&, const bytes&);

}

#endif