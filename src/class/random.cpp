#include "random.h"

#include <stdexcept>
#include <openssl/rand.h>

using namespace openssl_tools;

bytes openssl_tools::random_bytes(size_t _size) {

	bytes result(_size);
	if(1!=RAND_bytes(&result.get()[0], _size)) {
		throw std::runtime_error("unable to generate random bytes");
	}

	return result;
}