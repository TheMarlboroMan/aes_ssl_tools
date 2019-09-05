#ifndef OPENSSL_TOOLS_EXCEPTION_H
#define OPENSSL_TOOLS_EXCEPTION_H

#include <stdexcept>
#include <string>

namespace openssl_tools {

class exception:
	public std::runtime_error {
	public:
		exception(const std::string& _e)
			:std::runtime_error(_e) {

			}
};

}

#endif