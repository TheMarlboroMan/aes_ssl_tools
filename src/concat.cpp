#include <iostream>

#include "class/exception.h"
#include "class/bytes.h"
#include "class/base_64.h"

int main(int argc, char ** argv) {

	if(1==argc) {

		std::cerr<<"use "<<argv[0]<<" valuea [valueb ...]"<<std::endl;
		return 1;
	}

	try {

		std::vector<openssl_tools::bytes> values;
		for(int i=1; i<argc; i++) {
			std::string subject{std::string(argv[i])};
			values.push_back({subject});
		}

		openssl_tools::bytes result{0};
		for(const auto &b : values) {
			result+=openssl_tools::base64_decode(b);
		}
		
		std::cout<<base64_encode(result)<<std::endl;

		return 0;
	}
	catch(openssl_tools::base64_decode_exception& e) {

		std::cout<<"error "<<e.what()<<" read "<<e.read<<" expected "<<e.expected<<std::endl;
	}
	catch(std::exception& e) {

		std::cout<<"error "<<e.what()<<std::endl;
	}
}