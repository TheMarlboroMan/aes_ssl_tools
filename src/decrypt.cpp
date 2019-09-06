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

		if(2!=argc) {

			std::cerr<<"use "<<argv[0]<<" filename"<<std::endl<<"decrypts a file whose contents are a key, the IV and a string that was encrypted with AES-128-CBC"<<std::endl;
			return 1;
		}

		EVP_add_cipher(EVP_aes_128_cbc());

		std::ifstream file(argv[1]);

		//Get length of file...
		file.seekg (0, file.end);
		size_t length=file.tellg();
		file.seekg (0, file.beg);

		openssl_tools::bytes filedump{length};
		file.read(reinterpret_cast<char *>(filedump.get().data()), length);

		openssl_tools::bytes key=filedump.range(0, AES_BLOCK_SIZE),
			iv=filedump.range(AES_BLOCK_SIZE, AES_BLOCK_SIZE),
			message=filedump.range(AES_BLOCK_SIZE*2),
			decoded=openssl_tools::aes_128_cbc_decrypt(key, iv, message);
		
		std::cout<<decoded.to_string()<<std::endl;

		openssl_tools::bytes encoded64=openssl_tools::base64_encode(key+iv+message);
		openssl_tools::bytes decoded64=openssl_tools::base64_decode(encoded64);

		assert(decoded64==key+iv+message);

		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}