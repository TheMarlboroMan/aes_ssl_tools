#include <iostream>
#include <fstream>
#include <cassert>
#include <openssl/aes.h>

#include "class/bytes.h"
#include "class/base_64.h"
#include "class/aes.h"
#include "class/exception.h"

int main(int argc, char ** argv) {
	
	try {

		if(3!=argc) {

			std::cerr<<"use "<<argv[0]<<" base64key base64message"<<std::endl
			<<"decrypts a message with the given key."<<std::endl
			<<"the base64 message should have the IV and AES-128-CBC encrypted message concatenated"<<std::endl;
			return 1;
		}

		EVP_add_cipher(EVP_aes_128_cbc());

		openssl_tools::bytes base64key{std::string{argv[1]}},
				base64data{std::string{argv[2]}},				
				key{openssl_tools::base64_decode(base64key)},
				data{openssl_tools::base64_decode(base64data)},
				iv=data.range(0, AES_BLOCK_SIZE),
				message=data.range(AES_BLOCK_SIZE),
				decoded=openssl_tools::aes_128_cbc_decrypt(key, iv, message);

		std::cout<<decoded.to_string()<<std::endl
			<<"string size: "<<decoded.to_string().size()<<std::endl
			<<"total blocks: "<<decoded.size()<<std::endl;
		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}