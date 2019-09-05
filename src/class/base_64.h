#ifndef OPENSSL_TOOLS_BASE_64_H
#define OPENSSL_TOOLS_BASE_64_H

//TODO: Add namespace...
#include "bytes.h"

namespace openssl_tools {

bytes base64_encode(const bytes&);
bytes base64_decode(const bytes&);
size_t base64_calculate_length(const bytes&);

}

#endif