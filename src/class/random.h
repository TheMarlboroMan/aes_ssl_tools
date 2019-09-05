#ifndef OPENSSL_TOOLS_RANDOM_H
#define OPENSSL_TOOLS_RANDOM_H

//TODO: Add namespace...
#include "bytes.h"

namespace openssl_tools {

bytes random_bytes(size_t);

}

#endif