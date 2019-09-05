#include <iostream>
#include <string>

#include "class/bytes.h"
#include "class/random.h"
#include "class/exception.h"
#include "class/base_64.h"
#include "class/aes.h"

int main(int /*argc*/, char ** /*argv*/) {

	try {

		//Please, initialize your openssl stuff as needed!
		EVP_add_cipher(EVP_aes_128_cbc());

		//Bytes are the center of the library... They are just that, a sequence
		//of bytes.

		//For convenience sake, they can be created on a variety of ways...
		openssl_tools::bytes 	
				//5 bytes, with "hello"
				b_from_string(std::string("hello")), 
				//10 bytes, initialized with \0
				b_empty(10),		
				//This is a WONDERFUL way of shotting oneself in the foot. Even
				//if it is intentionally hard to write it could happen so let's
				//warn ourselves: copying 10 bytes from "world" will copy 
				//"world" and 5 more garbage bytes. Don't do this!!!!
				//10 bytes, the first 5 are hello, the rest are garbage
				b_padded_garbage(reinterpret_cast<const openssl_tools::bytes::byte *>("world"), 10), 
				//This is the way to do padded data with a source... intentionally
				//hard to write, of course: first the data, then the length to copy
				//and then the desired sequence size.
				//10 bytes, the first 5 are hello, the rest are \0
				b_padded(reinterpret_cast<const openssl_tools::bytes::byte *>("world"), 5, 10);


		//Bytes have the stream output overload, for convenience sake...
		std::cout<<"from string: "<<b_from_string<<std::endl
				<<"empty: "<<b_empty<<std::endl
				<<"padded (garbage expected, should be 'world'): "<<b_padded_garbage<<std::endl
				<<"padded: "<<b_padded<<std::endl;


		//Bytes can be concatenated...
		openssl_tools::bytes b_concatenation=b_from_string+b_padded; //15 bytes, helloworld and 5 garbage.

		std::cout<<"concatenation: "<<b_concatenation<<std::endl;

		//And this is a nice gotcha...
		openssl_tools::bytes b_exclamation("!");

		b_concatenation+=b_exclamation;	//..16 bytes: helloworld, plus 5 padding plus !.
		std::cout<<"gotcha, there are null characters: "<<b_concatenation<<" -> "<<b_concatenation.size()<<std::endl;

		//...so that's why we have ranges:
		b_concatenation=b_concatenation.range(0, 10); //From the begginning, grab 10 bytes.
		b_concatenation+=b_exclamation; //That's more like it.
		std::cout<<"fixed gotcha: "<<b_concatenation<<" -> "<<b_concatenation.size()<<std::endl;

		//Bytes can also be generated randomly... Reading this is kind of pointless..
		openssl_tools::bytes b_random=openssl_tools::random_bytes(16);
		std::cout<<"16 bytes of randomness "<<b_random<<std::endl;

		//better read as...
		for(unsigned int i=0; i<b_random.size(); i++) {
			//We can also do b_random[i]
			std::cout<<i<<" -> "<<(unsigned)b_random.at(i)<<std::endl;
		}

		//A good idea is to get these non printable bytes and base64 them.
		openssl_tools::bytes b64_random=openssl_tools::base64_encode(b_random);
		std::cout<<"random bytes in base 64: "<<b64_random<<std::endl;

		//Which leads to the final point: encryption... to encrypt, we need a 
		//key, an initialization vector and something to encrypt. These are all
		//just bytes... 

		//This is a generated key from the command line, with openssl rand -base64 16...
		//we used 16 bits, which is what the aging AES-128-CBC needs.
		openssl_tools::bytes	b64_key{"GmTVPcsJAoKJm+pATSyfGw=="};

		//...it is base64 encoded for readability, but encryption and decryption
		//want just bytes, so this makes our key ready to operate.
		openssl_tools::bytes	key{base64_decode(b64_key)};

		//We also need 16 bits for the IV (again, this is AES-128-CBC).
		openssl_tools::bytes	iv=openssl_tools::random_bytes(16);

		//!Finally, a message...
		std::string msg="this will be our message";
		openssl_tools::bytes	message{msg};

		//The AES encryption function returns bytes...
		openssl_tools::bytes encrypted=openssl_tools::aes_128_cbc_encrypt(key, iv, message);
		
		//Of course, these bytes are unprintable, unless we go byte to byte... 
		//We can always encode it in base64, safe to be printed. We'll do so 
		//here so we can ascertain that the message is never the same because
		//of different IVs.
		std::cout<<"encrypted base64: "<<openssl_tools::base64_encode(encrypted)<<std::endl;

		//Decryption needs the same key and IV... This means that keys can be 
		//shared (please, please, do not send your keys along) and that you must
		//find a way to ship the IV along with your message.

		//Anyway, the decryption function also takes and return bytes:
		openssl_tools::bytes decrypted=openssl_tools::aes_128_cbc_decrypt(key, iv, encrypted);

		//And that's all...
		std::cout<<"our message :'"<<decrypted<<"'"<<std::endl;

		//...well, almost.
		std::cout<<"size of original encrypted message "<<encrypted.size()<<std::endl;
		std::cout<<"size of decrypted message "<<decrypted.size()<<std::endl;

		//These two have different sizes in bytes!!!. Padding matters. You can 
		//always do "to_string" in string messages to rip the padding out...
		std::string str_decrypted=decrypted.to_string();

		std::cout<<"size of stringified message "<<msg.size()<<std::endl;
		std::cout<<"size of stringified decrypted message "<<str_decrypted.size()<<std::endl;
		
		//And that's it for now. Go have fun.

		return 0;
	}
	catch(openssl_tools::exception& e) {
		std::cerr<<"error: "<<e.what()<<std::endl;
		return 1;
	}
}