#include <iostream>
#include <fstream>
#include <cassert>
#include <openssl/aes.h>

#include "class/bytes.h"
#include "class/base_64.h"
#include "class/aes.h"
#include "class/random.h"
#include "class/exception.h"

int main(int argc, char ** argv) {
	
	try {

		if(2!=argc) {

			std::cerr<<"use "<<argv[0]<<" message"<<std::endl
			<<"encrypts a message with AES-128-CBC."<<std::endl
			<<"the first 16 bits of the base64 encoded message will be IV."<<std::endl
			<<"output lines are as follows:"<<std::endl
			<<" - base64 of the key"<<std::endl
			<<" - base64 of the IV"<<std::endl
			<<" - base64 of the encrypted message"<<std::endl
			<<" - a single line with key and base64 of iv+encrypted message (what decrypt needs)"<<std::endl;
			return 1;
		}

		EVP_add_cipher(EVP_aes_128_cbc());

		std::string str_msg(argv[1]);
		
		openssl_tools::bytes key=openssl_tools::random_bytes(AES_BLOCK_SIZE),
			iv=openssl_tools::random_bytes(AES_BLOCK_SIZE),
			message{str_msg},
			encrypted=openssl_tools::aes_128_cbc_encrypt(key, iv, message);

		std::cout<<openssl_tools::base64_encode(key)<<std::endl
			<<openssl_tools::base64_encode(iv)<<std::endl
			<<openssl_tools::base64_encode(encrypted)<<std::endl
			<<openssl_tools::base64_encode(key)<<" "<<openssl_tools::base64_encode(iv+encrypted)<<std::endl;

		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}