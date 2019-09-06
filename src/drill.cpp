#include <iostream>
#include <vector>
#include <memory>
#include <stdexcept>
#include <cassert>
#include <thread>
#include <mutex>
#include <fstream>

#include <openssl/aes.h>

#include "class/thread_manager.h"
#include "class/random.h"
#include "class/bytes.h"
#include "class/base_64.h"
#include "class/aes.h"
#include "class/exception.h"

struct full_pack {

	int							index;
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

void test_encrypt_full(int, const std::string, full_results_pack&);
void test_decrypt_full(const full_pack&, plain_results_pack&);
void encrypt(int, const std::string&, full_results_pack&);
void decrypt(const std::string&, plain_results_pack&);
void do_tests_full(const std::vector<std::string>&);
void do_real(const std::vector<std::string>&);
void file_marker(std::ofstream& _file, std::vector<int> _values);

std::mutex mtx_out;

int main(int argc, char ** argv) {
	
	openssl_tools::thread_manager threadman;

	try {

		if(3!=argc) {

			std::cerr<<"use "<<argv[0]<<" flags number_of_threads"<<std::endl<<"flags: 1 run tests, 2 run real"<<std::endl;
			return 1;
		}

		int total=std::atoi(argv[2]);
		if(total <=0 ) {
			std::cerr<<"use "<<argv[0]<<" flags number_of_threads"<<std::endl<<"flags: 1 run tests, 2 run real"<<std::endl;
			return 1;
		}

		EVP_add_cipher(EVP_aes_128_cbc());

		std::vector<std::string> input_strings;
		for(int i=0; i<total; i++) {
			std::string str("this is the test data with the index");
			str+=std::to_string(i);
			input_strings.push_back(str);
		}

		int flags=std::atoi(argv[1]);
		if(flags & 1) {
			do_tests_full(input_strings);
		}

		if(flags & 2) {
			do_real(input_strings);
		}

		return 0;
	}
	catch(std::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}

void do_tests_full(const std::vector<std::string>& _input_strings) {

	size_t total=_input_strings.size();
	full_results_pack encrypted{total};

	std::vector<std::thread> tasks;
	int index=0;
	for(const auto& _str : _input_strings) {
		tasks.push_back(std::thread(test_encrypt_full, index++, _str, std::ref(encrypted)));
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
			_cr,			
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

void test_encrypt_full(int _index, const std::string _str, full_results_pack& _pack) {

	try {
		openssl_tools::bytes	in{_str},
			 	key=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				iv=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				cyphered=openssl_tools::aes_128_cbc_encrypt(key, iv, in);

/*		try  {
			//Redundancy checks... remember to trim the output of these...
			openssl_tools::bytes decyphered=openssl_tools::aes_128_cbc_decrypt(key, iv, cyphered);
			if(in.trimmed() != decyphered.trimmed()) {
				throw std::runtime_error("redundancy decryption error");
			}
		}
		catch(std::exception& e) {
			std::cerr<<"CRYPT REDUNDANCY ERROR WILL RETHROW"<<std::endl;
			throw;
		}
*/
		//Keys should NEVER go along the message in the real world!
		openssl_tools::bytes all=key+iv+cyphered,
							encoded=openssl_tools::base64_encode(all);

		try {			
			//Redundancy check: we just encoded this, so we should be able
			//to decode it and should be the same, no trim at all.
			openssl_tools::bytes decoded=openssl_tools::base64_decode(encoded);
			assert(decoded==all);
		}
		catch(openssl_tools::base64_decode_exception& e) {
		
			std::cerr<<"CRYPT DECODING ERROR WILL WRITE RAW DATA TO FILE AND RETHROW"<<std::endl;
			std::cerr<<"read: "<<e.read<<" expected: "<<e.expected<<" subject: "<<e.subject<<std::endl;

			std::string filename{"dump-composite-plus-all"};
			std::ofstream file(filename+std::to_string(_index)+std::string(".dat").c_str(), std::ios::trunc);

			//A beginning marker, 32 66
			file_marker(file, std::vector<int>(32, 66));
			//Okay, keep it cool... 16 bits of a key, 16 of a iv, a shitload of a message.
			file<<key<<iv<<cyphered;
			//Now we can add a marker... Let's add 4 66...
			file_marker(file, std::vector<int>(32, 66));
			//And now we add "all", which should be the same as above.
			file<<all;

			//There are there so we can compare.
			std::ofstream alldump{"dump-all", std::ios::trunc};
			alldump<<all;

			std::ofstream compositeduimp{"dump-composite", std::ios::trunc};
			compositeduimp<<key<<iv<<cyphered;

			std::ofstream encodedump{"dump-encoded-str", std::ios::trunc};
			encodedump<<encoded;

			std::cout<<"THE ENCODED VALUE WAS "<<encoded.to_string()<<std::endl;

			throw;
		}

		_pack.add({_index, key, iv, cyphered, _str, encoded.to_string()});
	}	
	catch(std::exception& e) {
		_pack.set_fail();
		std::cerr<<"CRYPT ERROR "<<e.what()<<std::endl;
	}
}

void test_decrypt_full(
	const full_pack& _indata, 
	plain_results_pack& _pack) {

	try {
		//A base 64 string enters...We know that when decoded, the first 
		//!AES_BLOCK_SIZE is the key, then IV and the rest is the message so...
		openssl_tools::bytes decoded=openssl_tools::base64_decode({_indata.payload}),
			key=decoded.range(0, AES_BLOCK_SIZE),
			iv=decoded.range(AES_BLOCK_SIZE, AES_BLOCK_SIZE),
			cyphered=decoded.range(2*AES_BLOCK_SIZE),
			decyphered=openssl_tools::aes_128_cbc_decrypt(_indata.key, _indata.iv, _indata.message);

		if(decyphered.to_string() != _indata.original) {
			_pack.set_fail();
			std::cout<<"DECODED ENTITY DIFFERS..."<<std::endl;
		}

		_pack.add(decyphered.to_string());
	}
	catch(openssl_tools::base64_decode_exception& e) {
		
		_pack.set_fail();
		std::cerr<<"DECRYPT ERROR, base64_decode read in index "<<_indata.index<<", "
			<<e.read
			<<" instead of "<<e.expected
			<<" for '"<<e.subject<<"'"<<std::endl;

		//Drop stuff to a file...
		std::string filename{"dump-error"};
		filename+=std::to_string(_indata.index)+".dat";
		std::ofstream ofile{filename.c_str(), std::ios::trunc};
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cerr<<"DECRYPT ERROR "<<e.what()<<std::endl;
	}
}

void do_real(const std::vector<std::string>& _input_strings) {

	size_t total=_input_strings.size();
	full_results_pack encrypted{total};

	std::vector<std::thread> tasks;
	int i=0;
	for(const auto& _str : _input_strings) {
		tasks.push_back(std::thread(encrypt, i++, _str, std::ref(encrypted)));
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
		assert(false);
//		tasks.push_back(std::thread(decrypt, std::ref(_cr), std::ref(decrypted)));
	}
	for(auto& t : tasks) {
		t.join();
	}

	assert(decrypted.data.size()==total);
	if(decrypted.is_fail()) {
		throw std::runtime_error("Failure in encryption");
	}
}

void encrypt(int _index, const std::string& _str, full_results_pack& _pack) {
	
	try {
		openssl_tools::bytes 	key=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				iv=openssl_tools::random_bytes(AES_BLOCK_SIZE),
				cyphered=openssl_tools::aes_128_cbc_encrypt(key, iv, _str);

		//Keys should NEVER go along the message in the real world!
		openssl_tools::bytes all=key+iv+cyphered;
		openssl_tools::bytes encoded=openssl_tools::base64_encode(all);

		_pack.add({_index, key, iv, cyphered, _str, encoded.to_string()});
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cerr<<"CRYPT ERROR "<<e.what()<<std::endl;
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

		_pack.add(decyphered.to_string());
	}
	catch(std::exception& e) {
		_pack.set_fail();
		std::cerr<<"DECRYPT ERROR "<<e.what()<<std::endl;
	}
}

void file_marker(std::ofstream& _file, std::vector<int> _values) {		
		
	for(auto v : _values) {
		char c=static_cast<char>(v);
		_file.write(&c, sizeof(c));
	}
}