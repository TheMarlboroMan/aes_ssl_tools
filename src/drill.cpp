#include <iostream>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <thread>
#include <mutex>

#include <openssl/aes.h>

#include "class/thread_manager.h"
#include "class/random.h"
#include "class/bytes.h"
#include "class/base_64.h"
#include "class/aes.h"
#include "class/exception.h"

struct crypt_pack {

	openssl_tools::bytes		key, iv, message;
};

struct full_pack {

	openssl_tools::bytes		key, iv, message;
	std::string					original,
								payload;
};

struct results_base_pack {

	std::mutex					mt;
	bool						fail=false;
	bool						is_fail() const {return fail;}
	void						set_fail() {fail=true;}
};

struct crypt_results_pack:
	public results_base_pack {

	std::vector<crypt_pack>			data;

									crypt_results_pack(size_t _size) {data.reserve(_size);}
	void							add(const crypt_pack& _data) {

		std::lock_guard<std::mutex> lock{mt};
		data.push_back(_data);
	}
};

struct full_results_pack:
	public results_base_pack {

	std::vector<full_pack>			data;
									full_results_pack(size_t _size) {data.reserve(_size);}
	void							add(const full_pack& _data) {

		std::lock_guard<std::mutex> lock{mt};
		data.push_back(_data);
	}
};

struct plain_results_pack:
	public results_base_pack {

	std::vector<std::string>		data;
									plain_results_pack(size_t _size) {data.reserve(_size);}
	void							add(const std::string& _data) {

		std::lock_guard<std::mutex> lock{mt};
		data.push_back(_data);
	}
};

void test_encrypt(const std::string, crypt_results_pack&);
void test_decrypt(const openssl_tools::bytes&, const openssl_tools::bytes&, const openssl_tools::bytes&, plain_results_pack&);
void test_encrypt_full(const std::string, full_results_pack&);
void test_decrypt_full(const openssl_tools::bytes&, const openssl_tools::bytes&, const openssl_tools::bytes&, const std::string&, const std::string&, plain_results_pack&);
void encrypt(const std::string&, plain_results_pack&);
void decrypt(const std::string&, plain_results_pack&);
void do_tests(const std::vector<std::string>&);
void do_tests_full(const std::vector<std::string>&);
void do_real(const std::vector<std::string>&);

std::mutex mtx_out;

int main(int argc, char ** argv) {
	
	openssl_tools::thread_manager threadman;

	try {

		if(3!=argc) {

			std::cerr<<"use "<<argv[0]<<" flags number_of_threads"<<std::endl<<"flags: 1 run tests, 2 run full tests, 4 run real"<<std::endl;
			return 1;
		}

		int total=std::atoi(argv[2]);
		if(total <=0 ) {
			std::cerr<<"use "<<argv[0]<<" flags number_of_threads"<<std::endl<<"flags: 1 run tests, 2 run full tests, 4 run real"<<std::endl;
			return 1;
		}

		EVP_add_cipher(EVP_aes_128_cbc());

		std::vector<std::string> input_strings;
		for(int i=0; i<total; i++) {
			std::string str("this is my string with the index ");
			str+=std::to_string(i);
			input_strings.push_back(str);
		}

		int flags=std::atoi(argv[1]);
		if(flags & 1) {
			do_tests(input_strings);
		}

		if(flags & 2) {
			do_tests_full(input_strings);
		}

		//TODO: Ok, something in "do real" fucks us up... go get it!!!
		if(flags & 4) {
			do_real(input_strings);
		}

		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}

void do_tests(const std::vector<std::string>& _input_strings) {

	size_t total=_input_strings.size();
	crypt_results_pack encrypted{total};

	std::vector<std::thread> tasks;
	for(const auto& _str : _input_strings) {
		tasks.push_back(std::thread(test_encrypt, _str, std::ref(encrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(encrypted.data.size()==total);
	if(encrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}

	plain_results_pack decrypted{total};
	tasks.clear();
	for(const auto& _cr : encrypted.data) {
		tasks.push_back(std::thread(
			test_decrypt, 
			std::ref(_cr.key), 
			std::ref(_cr.iv), 
			std::ref(_cr.message), 
			std::ref(decrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(decrypted.data.size()==total);
	if(decrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}

	std::cout<<"Here is the test data:"<<std::endl;
	for(const auto& _str : decrypted.data) {
		std::cout<<_str<<std::endl;
	}
}

void do_tests_full(const std::vector<std::string>& _input_strings) {

	size_t total=_input_strings.size();
	full_results_pack encrypted{total};

	std::vector<std::thread> tasks;
	for(const auto& _str : _input_strings) {
		tasks.push_back(std::thread(test_encrypt_full, _str, std::ref(encrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(encrypted.data.size()==total);
	if(encrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}

	plain_results_pack decrypted{total};
	tasks.clear();
	for(const auto& _cr : encrypted.data) {
		tasks.push_back(std::thread(
			test_decrypt_full, 
			std::ref(_cr.key), 
			std::ref(_cr.iv), 
			std::ref(_cr.message), 
			std::ref(_cr.original),
			std::ref(_cr.payload), 
			std::ref(decrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(decrypted.data.size()==total);
	if(decrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}

//	std::cout<<"Here is the test data:"<<std::endl;
//	for(const auto& _str : decrypted.data) {
//		std::cout<<_str<<std::endl;
//	}
}

void do_real(const std::vector<std::string>& _input_strings) {

	size_t total=_input_strings.size();
	plain_results_pack encrypted{total};

	std::vector<std::thread> tasks;
	for(const auto& _str : _input_strings) {
		tasks.push_back(std::thread(encrypt, _str, std::ref(encrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(encrypted.data.size()==total);
	if(encrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}

	plain_results_pack decrypted{total};
	tasks.clear();
	for(const auto& _cr : encrypted.data) {
		tasks.push_back(std::thread(decrypt, std::ref(_cr), std::ref(decrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(decrypted.data.size()==total);
	if(decrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}

//	std::cout<<"Here is the real data:"<<std::endl;
//	for(const auto& _str : decrypted.data) {
//		std::cout<<_str<<std::endl;
//	}
}

void test_encrypt(const std::string _str, crypt_results_pack& _pack) {

	try {
		openssl_tools::bytes 	key=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				iv=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				cyphered=openssl_tools::aes_128_cbc_encrypt(key, iv, _str);

		_pack.add({key, iv, cyphered});
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cout<<"CRYPT ERROR "<<e.what()<<std::endl;
	}
}

void test_decrypt(const openssl_tools::bytes& _key, const openssl_tools::bytes& _iv, const openssl_tools::bytes& _message, plain_results_pack& _pack) {

	try {
		auto decyphered=openssl_tools::aes_128_cbc_decrypt(_key, _iv, _message);
		_pack.add(decyphered.to_string());
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cout<<"DECRYPT ERROR "<<e.what()<<std::endl;
	}
}

void test_encrypt_full(const std::string _str, full_results_pack& _pack) {

	try {
		openssl_tools::bytes 	key=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				iv=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				cyphered=openssl_tools::aes_128_cbc_encrypt(key, iv, _str);

		//Keys should NEVER go along the message in the real world!
		openssl_tools::bytes all=key+iv+cyphered;
		openssl_tools::bytes encoded=openssl_tools::base64_encode(all);

//		{
//		std::lock_guard<std::mutex> lock{mtx_out};
//		std::cout<<"for "<<_str<<std::endl
//				<<"key "<<openssl_tools::base64_encode(key)<<std::endl
//				<<"iv  "<<openssl_tools::base64_encode(iv)<<std::endl
//				<<"cyphered "<<openssl_tools::base64_encode(cyphered)<<std::endl
//				<<"got "<<encoded<<std::endl
//				<<std::endl;
//		}

		_pack.add({key, iv, cyphered, _str, encoded.to_string()});
	}	
	catch(std::exception& e) {
		_pack.set_fail();
		std::cout<<"CRYPT ERROR "<<e.what()<<std::endl;
	}
}

void test_decrypt_full(
	const openssl_tools::bytes& _key, 
	const openssl_tools::bytes& _iv, 
	const openssl_tools::bytes& _message, 
	const std::string& _original, 
	const std::string& _payload, 
	plain_results_pack& _pack) {

	try {
		//A base 64 string enters...
		//TODO: Fuck, it is somewhere here....
//		openssl_tools::bytes decoded=openssl_tools::base64_decode({_payload});
	

		//We know the first AES_BLOCK_SIZE is the key, then IV and the rest is the
		//message so...

//		openssl_tools::bytes 	key=decoded.range(0, AES_BLOCK_SIZE),
//			iv=decoded.range(AES_BLOCK_SIZE, AES_BLOCK_SIZE),
//			cyphered=decoded.range(2*AES_BLOCK_SIZE),
		openssl_tools::bytes decyphered=openssl_tools::aes_128_cbc_decrypt(_key, _iv, _message);

		if(decyphered.to_string() != _original) {
			_pack.set_fail();
			std::cout<<"DECODED ENTITY DIFFERS..."<<std::endl;
		}

		_pack.add(decyphered.to_string());
	}
	catch(openssl_tools::base64_decode_exception& e) {
		
		_pack.set_fail();

		//Let us reconstruct the payload...
		openssl_tools::bytes all{""};
		all+=_key;
		all+=_iv;
		all+=_message;

		//TODO: Ok, ok, ok, ok... we know this failed... damn...

		std::cout<<"CRYPT ERROR, base64_decode read "
			<<e.read
			<<" instead of "<<e.expected
			<<" for '"<<e.subject<<"'"<<std::endl
			<<"payload was '"<<_payload<<"'"<<std::endl;
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cout<<"DECRYPT ERROR "<<e.what()<<std::endl;
	}
}

void encrypt(const std::string& _str, plain_results_pack& _pack) {
	
	try {
		openssl_tools::bytes 	key=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				iv=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				cyphered=openssl_tools::aes_128_cbc_encrypt(key, iv, _str);

		//Keys should NEVER go along the message in the real world!
		openssl_tools::bytes all=key+iv+cyphered;
		openssl_tools::bytes encoded=openssl_tools::base64_encode(all);

		_pack.add(encoded.to_string());
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cout<<"CRYPT ERROR "<<e.what()<<std::endl;
	}
}

void decrypt(const std::string& _str, plain_results_pack& _pack) {

	try {
		//A base 64 string enters...
		openssl_tools::bytes decoded=openssl_tools::base64_decode({_str});
		//We know the first AES_BLOCK_SIZE is the key, then IV and the rest is the
		//message so...

		openssl_tools::bytes 	key=decoded.range(0, AES_BLOCK_SIZE),
				iv=decoded.range(AES_BLOCK_SIZE, AES_BLOCK_SIZE),
				cyphered=decoded.range(2*AES_BLOCK_SIZE),
				decyphered=openssl_tools::aes_128_cbc_decrypt(key, iv, cyphered);

		//TODO: Almost good... there are extra padding chars.

		_pack.add(decyphered.to_string());
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cout<<"DECRYPT ERROR "<<e.what()<<std::endl;
	}
}