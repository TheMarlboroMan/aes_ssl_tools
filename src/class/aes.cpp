#include "aes.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#include "exception.h"

using namespace openssl_tools;

bytes openssl_tools::aes_128_cbc_encrypt(const bytes& _key, const bytes& _iv, const bytes& _in) {

	const int blocksize=AES_BLOCK_SIZE;

	EVP_CIPHER_CTX_ptr ctx{EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free};
	if(1!=EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, _key, _iv)) {
		throw std::runtime_error(ERR_error_string(ERR_get_error(), nullptr));
	}

	//First, we need the data to be a multiple of the block size...
    size_t pad_len=_in.size()+blocksize-(_in.size() % blocksize);

	//Great, now we can have these inputs and outputs...
	bytes 	input{_in, _in.size(), pad_len},
			output{pad_len+blocksize};	//Apparently we need some more blocksize :/.

	int 	cypher_length=0,
			bytes_written=0;

	if(1!=EVP_EncryptUpdate(ctx.get(), output, &bytes_written, input, input.size())) {
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	cypher_length+=bytes_written;

	if(1!=EVP_EncryptFinal_ex(ctx.get(), output.offset(bytes_written), &bytes_written)) {
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	cypher_length+=bytes_written;	
	return bytes{output, (size_t)cypher_length};
}

bytes openssl_tools::aes_128_cbc_decrypt(const bytes& _key, const bytes& _iv, const bytes& _in) {

	const int blocksize=AES_BLOCK_SIZE;

	EVP_CIPHER_CTX_ptr ctx{EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free};
	if(1!=EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr, _key, _iv)) {
		throw exception(
			std::string("EVP_DecryptInit_ex ")+
			ERR_error_string(ERR_get_error(), nullptr)		
		);
	}

	//First, we need the data to be a multiple of the block size... 	
    size_t pad_len=_in.size()+blocksize-(_in.size() % blocksize);
	bytes 	output{pad_len};

	int	 	bytes_written=0,
			decyphered_length=0;

	if(1!=EVP_DecryptUpdate(ctx.get(), output, &bytes_written, _in, _in.size())) {
		throw exception(
			std::string("EVP_DecryptUpdate ")+
			ERR_error_string(ERR_get_error(), nullptr)
			+" for "+_in.to_string()
		);
	}

	decyphered_length+=bytes_written;

	if(1!=EVP_DecryptFinal_ex(ctx.get(), output.offset(bytes_written), &bytes_written)) {
		//TODO: We need a better exception system...
		throw exception(
			std::string("EVP_DecryptFinal_ex ")+
			ERR_error_string(ERR_get_error(), nullptr)
			+" for "+_in.to_string()
		);
	}

	decyphered_length+=bytes_written;

	return bytes{output, (size_t)decyphered_length};
}