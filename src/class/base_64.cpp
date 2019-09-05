#include "base_64.h"

#include <string>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "bytes.h"
#include "exception.h"

using namespace openssl_tools;

bytes openssl_tools::base64_encode(const bytes& _bytes) {

	//TODO: I am pretty much sure this is leaking...
	BIO* b64=BIO_new(BIO_f_base64());
	BIO* bm=BIO_new(BIO_s_mem());

	b64=BIO_push(b64,bm);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	if(BIO_write(b64,_bytes, _bytes.size())<2) {
		throw std::runtime_error("openssl BIO_write() failed");
	}

	if(BIO_flush(b64)<1) {
		throw std::runtime_error("openssl BIO_flush() failed");
	}

	BUF_MEM * bptr=nullptr;
	BIO_get_mem_ptr(b64, &bptr);

	bytes result{bptr->data, bptr->length};
	
	//TODO: Use fucking RAII techniques and deleters for this.

	BIO_set_close(bm, BIO_NOCLOSE);
	BIO_free_all(b64);

	return result;
}

bytes openssl_tools::base64_decode(const bytes& _bytes) {

	auto calculate_length=[](const bytes& _input) {
		size_t	len=_input.size(),
				padding=0;

		if('='==_input.get()[len-2]) {
			padding=2;
		}
		else if('='==_input.get()[len-1]) {
			padding=1;
		}

		return (len*3)/4-padding;
	};
	
	size_t decoded_length=calculate_length(_bytes);
	bytes result{decoded_length};

	BIO *	bio=BIO_new_mem_buf(_bytes, -1),
		*	b64=BIO_new(BIO_f_base64());

	bio=BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer

	int read=BIO_read(bio, result, _bytes.size());

	if((int)decoded_length != read) {
		throw base64_decode_exception(read, decoded_length, _bytes);			
	}

	BIO_free_all(bio);
	return result;
}