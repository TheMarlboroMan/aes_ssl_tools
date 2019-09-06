#ifndef OPENSSL_TOOLS_EXCEPTION_H
#define OPENSSL_TOOLS_EXCEPTION_H

#include <stdexcept>
#include <string>
#include <sstream>

#include "bytes.h"

namespace openssl_tools {

class exception:
	public std::runtime_error {
	public:
		exception(const std::string& _e)
			:std::runtime_error(_e) {

			}
};

class base64_decode_exception
	:public exception {
	public:

	size_t			read,			//!Size read
					expected;		//!Expected size
	bytes			subject;		//!Copy of the bytes that caused the problem

					base64_decode_exception(size_t _read, size_t _expected, const bytes& _bytes):
			exception{"failure in base64_decode"},
			read{_read}, 
			expected{_expected}, 
			subject{_bytes} {
			
	}
};

class base64_encode_exception
	:public exception {
	public:

	bytes			subject;		//!Copy of the bytes that caused the problem

					base64_encode_exception(const std::string& _msg, const bytes& _bytes):
			exception{"failure in base64_encode : "+_msg},
			subject{_bytes} {}		
};

}

#endif