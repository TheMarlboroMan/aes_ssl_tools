#include "random.h"

#include <stdexcept>
#include <openssl/rand.h>

using namespace openssl_tools;

bytes openssl_tools::random_bytes(size_t _size) {

	bytes result(_size);
	int randb=RAND_bytes(result.offset(0), _size);
	if(1!=randb) {
		throw std::runtime_error("unable to generate random bytes");
	}

	return result;
}